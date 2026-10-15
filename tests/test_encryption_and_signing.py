"""AES-GCM session encryption and Ed25519 signature tests (phase 3).

Run from the project root:

    python -m unittest discover tests -v

The end-to-end tests wire two ChatClient objects together through an
in-memory socket, so no server needs to be running.
"""

import contextlib
import io
import json
import os
import unittest

from src.client import ChatClient, MessageRejected
from src.crypto import DecryptionError, SessionCipher, b64decode, b64encode, chat_associated_data
from src.protocol import default_protocol
from src.signing import SigningIdentity, verify


class RecordingSocket:
    """Stands in for a TCP socket and keeps every payload the client sends."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(default_protocol.decode(data.rstrip(default_protocol.delimiter)))


def flip_first_byte(b64_value: str) -> str:
    raw = bytearray(b64decode(b64_value))
    raw[0] ^= 0x01
    return b64encode(bytes(raw))


class SessionCipherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cipher = SessionCipher(os.urandom(32))
        self.aad = chat_associated_data("alice", "bob")

    def test_round_trip(self) -> None:
        nonce, ciphertext = self.cipher.encrypt("hello bob", self.aad)
        self.assertEqual(self.cipher.decrypt(nonce, ciphertext, self.aad), "hello bob")

    def test_ciphertext_does_not_contain_plaintext(self) -> None:
        _, ciphertext = self.cipher.encrypt("hello bob", self.aad)
        self.assertNotIn(b"hello bob", b64decode(ciphertext))

    def test_same_message_encrypts_differently_each_time(self) -> None:
        self.assertNotEqual(self.cipher.encrypt("hi", self.aad), self.cipher.encrypt("hi", self.aad))

    def test_tampered_ciphertext_is_rejected(self) -> None:
        nonce, ciphertext = self.cipher.encrypt("hello bob", self.aad)
        with self.assertRaises(DecryptionError):
            self.cipher.decrypt(nonce, flip_first_byte(ciphertext), self.aad)

    def test_retargeted_ciphertext_is_rejected(self) -> None:
        nonce, ciphertext = self.cipher.encrypt("hello bob", self.aad)
        with self.assertRaises(DecryptionError):
            self.cipher.decrypt(nonce, ciphertext, chat_associated_data("alice", "carol"))

    def test_wrong_key_is_rejected(self) -> None:
        nonce, ciphertext = self.cipher.encrypt("hello bob", self.aad)
        with self.assertRaises(DecryptionError):
            SessionCipher(os.urandom(32)).decrypt(nonce, ciphertext, self.aad)


class SigningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.alice = SigningIdentity.generate()
        self.fields = {"type": "chat", "sender": "alice", "target": "bob", "ciphertext": "abc"}

    def test_valid_signature_verifies(self) -> None:
        self.assertTrue(verify(self.alice.public_key_b64, self.fields, self.alice.sign(self.fields)))

    def test_tampered_fields_fail(self) -> None:
        signature = self.alice.sign(self.fields)
        self.assertFalse(verify(self.alice.public_key_b64, dict(self.fields, ciphertext="abd"), signature))

    def test_other_key_fails(self) -> None:
        mallory = SigningIdentity.generate()
        self.assertFalse(verify(self.alice.public_key_b64, self.fields, mallory.sign(self.fields)))

    def test_garbage_signature_fails(self) -> None:
        self.assertFalse(verify(self.alice.public_key_b64, self.fields, "not-base64!"))


class EndToEndTests(unittest.TestCase):
    """Alice and Bob complete a signed DH handshake, then exchange a chat message."""

    def setUp(self) -> None:
        self.alice = ChatClient("alice", "127.0.0.1", 0)
        self.bob = ChatClient("bob", "127.0.0.1", 0)
        self.alice.sock = RecordingSocket()
        self.bob.sock = RecordingSocket()

        with contextlib.redirect_stdout(io.StringIO()):
            self.alice.start_dh_handshake("bob")
            self.bob.handle_dh_public(self.alice.sock.sent[-1])
            self.alice.handle_dh_public(self.bob.sock.sent[-1])

    def alice_sends(self, text: str) -> dict:
        return default_protocol.decode(self.alice.seal_chat("bob", text).rstrip(default_protocol.delimiter))

    def test_both_sides_derive_the_same_session_key(self) -> None:
        self.assertEqual(self.alice.state.session_keys["bob"], self.bob.state.session_keys["alice"])

    def test_bob_decrypts_and_verifies_alices_message(self) -> None:
        self.assertEqual(self.bob.open_chat(self.alice_sends("hello bob")), "hello bob")

    def test_wire_payload_has_no_plaintext(self) -> None:
        payload = self.alice_sends("hello bob")
        self.assertNotIn("message", payload)
        self.assertNotIn("hello bob", json.dumps(payload))

    def test_tampered_ciphertext_fails_signature_check(self) -> None:
        payload = self.alice_sends("hello bob")
        payload["ciphertext"] = flip_first_byte(payload["ciphertext"])
        with self.assertRaisesRegex(MessageRejected, "invalid signature"):
            self.bob.open_chat(payload)

    def test_tampered_nonce_fails_signature_check(self) -> None:
        payload = self.alice_sends("hello bob")
        payload["nonce"] = flip_first_byte(payload["nonce"])
        with self.assertRaisesRegex(MessageRejected, "invalid signature"):
            self.bob.open_chat(payload)

    def test_forged_sender_is_rejected(self) -> None:
        # Mallory has her own valid key pair but claims to be Alice.
        mallory = SigningIdentity.generate()
        payload = self.alice_sends("hello bob")
        fields = {k: payload[k] for k in ("type", "sender", "target", "nonce", "ciphertext")}
        payload["signature"] = mallory.sign(fields)
        with self.assertRaisesRegex(MessageRejected, "invalid signature"):
            self.bob.open_chat(payload)

    def test_message_from_unknown_peer_is_rejected(self) -> None:
        payload = dict(self.alice_sends("hello bob"), sender="carol")
        with self.assertRaisesRegex(MessageRejected, "no session"):
            self.bob.open_chat(payload)

    def test_tampered_dh_public_value_is_rejected(self) -> None:
        carol = ChatClient("carol", "127.0.0.1", 0)
        carol.sock = RecordingSocket()
        with contextlib.redirect_stdout(io.StringIO()):
            self.alice.start_dh_handshake("carol")
        payload = dict(self.alice.sock.sent[-1])
        payload["public_key"] = str(int(payload["public_key"]) + 1)

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            carol.handle_dh_public(payload)
        self.assertIn("Rejected DH public value", output.getvalue())
        self.assertNotIn("alice", carol.state.session_keys)


if __name__ == "__main__":
    unittest.main()
