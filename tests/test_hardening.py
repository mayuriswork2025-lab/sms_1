"""Handshake and relay hardening tests.

Run from the project root:

    python -m unittest discover tests -v

Covers: DH public values that would force a weak key, duplicate logins,
and frames whose sender doesn't match the connection that sent them.
"""

import contextlib
import io
import os
import tempfile
import unittest

from src.client import ChatClient
from src.dh import P, validate_public_key
from src.message_format import dh_public_signed_fields
from src.protocol import default_protocol
from src.server import ChatServer, ClientRegistry


class RecordingSocket:
    """Stands in for a TCP socket and keeps every payload sent through it."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(default_protocol.decode(data.rstrip(default_protocol.delimiter)))


class DHRangeTests(unittest.TestCase):
    def test_weak_values_are_rejected(self) -> None:
        for value in (0, 1, P - 1, P, P + 5):
            with self.assertRaises(ValueError):
                validate_public_key(value)

    def test_normal_values_are_accepted(self) -> None:
        for value in (2, 12345, P - 2):
            validate_public_key(value)

    def test_client_rejects_signed_weak_value(self) -> None:
        # Even a correctly signed DH value of 1 must not create a session,
        # because every shared secret computed from it would be 1.
        no_certs = os.path.join(tempfile.gettempdir(), "cn_sms_no_certs")
        with contextlib.redirect_stdout(io.StringIO()):
            alice = ChatClient("alice", "127.0.0.1", 0, certs_dir=no_certs, require_cert=False)
            bob = ChatClient("bob", "127.0.0.1", 0, certs_dir=no_certs, require_cert=False)
        bob.sock = RecordingSocket()

        signing_key = alice.identity.public_key_b64
        payload = {
            "type": "dh_public",
            "sender": "alice",
            "target": "bob",
            "public_key": "1",
            "signing_key": signing_key,
            "signature": alice.identity.sign(dh_public_signed_fields("alice", "bob", 1, signing_key)),
        }

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            bob.handle_dh_public(payload)
        self.assertIn("value out of range", output.getvalue())
        self.assertNotIn("alice", bob.state.session_keys)
        self.assertEqual(bob.sock.sent, [])


class DuplicateLoginTests(unittest.TestCase):
    def test_second_login_with_same_name_is_refused(self) -> None:
        registry = ClientRegistry()
        first, second = RecordingSocket(), RecordingSocket()
        self.assertEqual(registry.register(first, "alice"), "alice")
        self.assertIsNone(registry.register(second, "alice"))
        self.assertIs(registry.find("alice"), first)

    def test_name_is_free_again_after_disconnect(self) -> None:
        registry = ClientRegistry()
        first, second = RecordingSocket(), RecordingSocket()
        registry.register(first, "alice")
        registry.remove(first)
        self.assertEqual(registry.register(second, "alice"), "alice")

    def test_server_tells_the_duplicate_client_why(self) -> None:
        server = ChatServer()
        first, second = RecordingSocket(), RecordingSocket()
        with contextlib.redirect_stderr(io.StringIO()):
            server.handle_login(first, ("127.0.0.1", 1), {"type": "login", "username": "alice"})
            result = server.handle_login(second, ("127.0.0.1", 2), {"type": "login", "username": "alice"})
        self.assertIsNone(result)
        self.assertIn("already connected", second.sent[-1]["message"])


class SenderCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = ChatServer()
        self.alice_conn, self.bob_conn = RecordingSocket(), RecordingSocket()
        self.server.registry.register(self.alice_conn, "alice")
        self.server.registry.register(self.bob_conn, "bob")

    def relay(self, username: str | None, payload: dict) -> None:
        with contextlib.redirect_stderr(io.StringIO()):
            self.server.relay(username, payload, "Chat message")

    def test_matching_sender_is_relayed(self) -> None:
        payload = {"type": "chat", "sender": "alice", "target": "bob", "ciphertext": "abc"}
        self.relay("alice", payload)
        self.assertEqual(self.bob_conn.sent, [payload])

    def test_spoofed_sender_is_dropped(self) -> None:
        payload = {"type": "chat", "sender": "carol", "target": "bob", "ciphertext": "abc"}
        self.relay("alice", payload)
        self.assertEqual(self.bob_conn.sent, [])

    def test_frame_before_login_is_dropped(self) -> None:
        payload = {"type": "chat", "sender": "alice", "target": "bob", "ciphertext": "abc"}
        self.relay(None, payload)
        self.assertEqual(self.bob_conn.sent, [])


if __name__ == "__main__":
    unittest.main()
