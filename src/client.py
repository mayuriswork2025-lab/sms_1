import argparse
import socket
import sys
import threading
import time
from typing import Dict

try:
    from src.ca import CertificateAuthority
    from src.crypto import DecryptionError, SessionCipher, chat_associated_data
    from src.dh import (
        compute_public_key,
        compute_shared_secret,
        derive_session_key,
        generate_private_key,
        validate_public_key,
    )
    from src.message_format import (
        build_chat_message,
        build_dh_public_message,
        build_login_message,
        chat_signed_fields,
        dh_public_signed_fields,
    )
    from src.protocol import MessageReader, ProtocolDecodeError, default_protocol
    from src.signing import SigningIdentity, verify
except ImportError:
    from ca import CertificateAuthority
    from crypto import DecryptionError, SessionCipher, chat_associated_data
    from dh import (
        compute_public_key,
        compute_shared_secret,
        derive_session_key,
        generate_private_key,
        validate_public_key,
    )
    from message_format import (
        build_chat_message,
        build_dh_public_message,
        build_login_message,
        chat_signed_fields,
        dh_public_signed_fields,
    )
    from protocol import MessageReader, ProtocolDecodeError, default_protocol
    from signing import SigningIdentity, verify

RECV_BUFFER_SIZE = 4096
DH_HANDSHAKE_TIMEOUT_SECONDS = 5.0


class DHSessionState:
    """Tracks in-progress and completed DH handshakes with other peers."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.pending_private_keys: Dict[str, int] = {}
        self.session_keys: Dict[str, bytes] = {}
        # Each peer's Ed25519 public key (base64), learned during the DH handshake.
        self.peer_signing_keys: Dict[str, str] = {}
        self.peer_certificates: Dict[str, str] = {}
        # Replay protection: last seq sent to / accepted from each peer this session.
        self.send_seq: Dict[str, int] = {}
        self.last_seen_seq: Dict[str, int] = {}


class MessageRejected(Exception):
    """Raised when an incoming chat message fails signature or decryption checks."""


class ChatClient:
    """Connects to the chat server, runs signed DH handshakes, and sends/receives encrypted messages."""

    def __init__(
        self,
        username: str,
        host: str,
        port: int,
        certs_dir: str = "certs",
        require_cert: bool = True,
    ) -> None:
        self.username = username
        self.host = host
        self.port = port
        self.certs_dir = certs_dir
        self.require_cert = require_cert
        self.state = DHSessionState()

        # Try to load trusted Root CA
        self.ca: CertificateAuthority | None = None
        try:
            self.ca = CertificateAuthority.load_from_dir(self.certs_dir)
        except Exception:
            self.ca = None

        # Load or generate signing identity. Certificates are issued only by the
        # CA administrator (python src/ca.py issue <username>); a client never
        # signs its own certificate, even if the CA private key is reachable.
        self.identity = SigningIdentity.load_or_generate(self.username, certs_dir=self.certs_dir)
        if self.identity.certificate_pem is None:
            print(f"[ca] No certificate for {self.username}. Ask the CA admin to run: python src/ca.py issue {self.username}")

        self.sock: socket.socket | None = None

    def run(self, message: str | None = None, target: str | None = None) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            self.sock = sock
            sock.connect((self.host, self.port))
            sock.sendall(build_login_message(self.username))

            receiver = threading.Thread(target=self.receive_messages, daemon=True)
            receiver.start()

            if message is not None:
                self.send_once(message, target)
            else:
                self.interactive_loop()

    def send_once(self, message: str, target: str | None) -> None:
        if not target:
            print("Error: --message requires --target <username> -- chat is peer-targeted.")
            return

        self.start_dh_handshake(target)
        if not self.wait_for_session_key(target, DH_HANDSHAKE_TIMEOUT_SECONDS):
            print(f"[dh] Timed out waiting for {target} to respond; message not sent.")
            return

        self.sock.sendall(self.seal_chat(target, message))
        print(f"[you -> {target}] {message}")

    def interactive_loop(self) -> None:
        print(f"Connected as {self.username}. Type messages and press Enter.")
        print("Type '/dh <username>' to start a Diffie-Hellman key exchange with a peer.")
        print("Type '/msg <username> <text>' to send an encrypted, signed message to a peer you've exchanged keys with.")
        print("Type 'quit' to exit.")

        while True:
            try:
                text = input("> ")
            except EOFError:
                break
            stripped = text.strip()

            if stripped.lower() == "quit":
                self.sock.sendall(default_protocol.encode({"type": "leave"}))
                break

            if stripped.startswith("/dh "):
                peer = stripped[len("/dh "):].strip()
                if not peer:
                    print("[dh] Usage: /dh <username>")
                    continue
                self.start_dh_handshake(peer)
                continue

            if stripped.startswith("/msg "):
                rest = stripped[len("/msg "):].strip()
                peer, _, body = rest.partition(" ")
                if not peer or not body:
                    print("[msg] Usage: /msg <username> <text>")
                    continue
                self.send_chat(peer, body)
                continue

            print("Unrecognized input. Use '/dh <username>' or '/msg <username> <text>'.")

    def send_chat(self, peer: str, body: str) -> None:
        with self.state.lock:
            has_session = peer in self.state.session_keys
        if not has_session:
            print(f"[msg] No session with {peer} yet. Run '/dh {peer}' first.")
            return
        self.sock.sendall(self.seal_chat(peer, body))
        print(f"[you -> {peer}] {body}")

    def seal_chat(self, peer: str, text: str) -> bytes:
        """Encrypt text for peer with the session key, then sign the ciphertext and sequence number."""
        with self.state.lock:
            session_key = self.state.session_keys[peer]
            seq = self.state.send_seq.get(peer, 0) + 1
            self.state.send_seq[peer] = seq
        cipher = SessionCipher(session_key)
        nonce, ciphertext = cipher.encrypt(text, chat_associated_data(self.username, peer))
        signature = self.identity.sign(chat_signed_fields(self.username, peer, nonce, ciphertext, seq))
        return build_chat_message(self.username, peer, nonce, ciphertext, signature, seq)

    def open_chat(self, payload: dict) -> str:
        """Verify an incoming chat message's signature and sequence number, then decrypt it.

        The signature is checked first so that nothing from an unauthenticated
        sender ever reaches the decryption step. A seq no higher than the last
        one accepted from this sender is a replay and is rejected. Raises
        MessageRejected if any check fails.
        """
        sender = payload.get("sender")
        target = payload.get("target")
        seq = payload.get("seq")
        nonce = payload.get("nonce")
        ciphertext = payload.get("ciphertext")
        signature = payload.get("signature")

        if target != self.username:
            raise MessageRejected(f"addressed to {target}, not us")
        if not (nonce and ciphertext and signature):
            raise MessageRejected("missing nonce, ciphertext, or signature")
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise MessageRejected("missing sequence number")

        with self.state.lock:
            session_key = self.state.session_keys.get(sender)
            signing_key = self.state.peer_signing_keys.get(sender)
        if session_key is None or signing_key is None:
            raise MessageRejected(f"no session with {sender}")

        if not verify(signing_key, chat_signed_fields(sender, target, nonce, ciphertext, seq), signature):
            raise MessageRejected("invalid signature")

        with self.state.lock:
            last_seen = self.state.last_seen_seq.get(sender, 0)
            if seq <= last_seen:
                raise MessageRejected(f"replayed message (seq {seq}, already accepted up to {last_seen})")

        try:
            plaintext = SessionCipher(session_key).decrypt(nonce, ciphertext, chat_associated_data(sender, target))
        except DecryptionError as exc:
            raise MessageRejected("decryption failed") from exc

        with self.state.lock:
            self.state.last_seen_seq[sender] = max(seq, self.state.last_seen_seq.get(sender, 0))
        return plaintext

    def receive_messages(self) -> None:
        # TCP is a byte stream, not a message stream: one recv() can return part
        # of a message, several messages, or both. MessageReader buffers raw
        # bytes and only hands back frames once a full delimiter-terminated
        # message has arrived.
        reader = MessageReader(default_protocol)
        while True:
            try:
                data = self.sock.recv(RECV_BUFFER_SIZE)
                if not data:
                    break

                for frame in reader.feed(data):
                    try:
                        payload = reader.decode(frame)
                    except ProtocolDecodeError:
                        print(f"[invalid packet] {frame!r}")
                        print("> ", end="", flush=True)
                        continue

                    message_type = payload.get("type")
                    if message_type == "system":
                        print(f"[server] {payload.get('message', '')}")
                        print("", end="", flush=True)
                    elif message_type == "chat":
                        sender = payload.get("sender", "unknown")
                        try:
                            message = self.open_chat(payload)
                            print(f"[{sender}] {message}  (signature verified)")
                        except MessageRejected as exc:
                            print(f"[security] Rejected message from {sender}: {exc}")
                        print("> ", end="", flush=True)
                    elif message_type == "dh_public":
                        self.handle_dh_public(payload)
                        print("> ", end="", flush=True)
            except OSError:
                break

    def start_dh_handshake(self, peer: str) -> None:
        private_key = generate_private_key()
        public_key = compute_public_key(private_key)
        with self.state.lock:
            self.state.pending_private_keys[peer] = private_key
        self.sock.sendall(self.signed_dh_public(peer, public_key))
        print(f"[dh] Sent signed public value to {peer}: {public_key}")
        print(f"[dh] Waiting for {peer}'s response...")

    def signed_dh_public(self, peer: str, public_key: int) -> bytes:
        signing_key = self.identity.public_key_b64
        certificate = self.identity.certificate_pem or ""
        signature = self.identity.sign(dh_public_signed_fields(self.username, peer, public_key, signing_key, certificate))
        return build_dh_public_message(self.username, peer, public_key, signing_key, signature, certificate)

    def handle_dh_public(self, payload: dict) -> None:
        sender = payload.get("sender", "unknown")
        target = payload.get("target")
        signing_key = payload.get("signing_key", "")
        certificate = payload.get("certificate", "")
        public_key_raw = payload.get("public_key", "")

        if target != self.username:
            print(f"[security] Rejected DH public value from {sender}: addressed to {target}, not us")
            return

        # Certificate and trust-chain validation (Phase 4)
        if self.require_cert:
            if not certificate:
                print(f"[security] Rejected DH public value from {sender}: missing certificate (trust chain required)")
                return
            if self.ca is None:
                print(f"[security] Rejected DH public value from {sender}: no trusted Root CA configured")
                return

            is_valid, cn, cert_pub_key, reason = self.ca.verify_certificate(certificate, expected_username=sender)
            if not is_valid:
                print(f"[security] Rejected DH public value from {sender}: certificate verification failed ({reason})")
                return

            # Binding check: certificate's public key must match signing key in payload
            if cert_pub_key != signing_key:
                print(f"[security] Rejected DH public value from {sender}: signing key does not match certificate public key")
                return

            print(f"[ca] Validated identity certificate for {sender} (bound to key {signing_key[:16]}...)")

        signed_fields = dh_public_signed_fields(sender, target, public_key_raw, signing_key, certificate)

        if not verify(signing_key, signed_fields, payload.get("signature", "")):
            print(f"[security] Rejected DH public value from {sender}: invalid signature")
            return
        try:
            peer_public_key = int(public_key_raw)
            validate_public_key(peer_public_key)
        except ValueError:
            print(f"[security] Rejected DH public value from {sender}: value out of range (would force a weak key)")
            return

        with self.state.lock:
            self.state.peer_signing_keys[sender] = signing_key
            if certificate:
                self.state.peer_certificates[sender] = certificate
            pending_private_key = self.state.pending_private_keys.pop(sender, None)
            # A new session starts counting from zero in both directions.
            self.state.send_seq[sender] = 0
            self.state.last_seen_seq[sender] = 0

            if pending_private_key is not None:
                # We initiated this handshake; this is the peer's reply.
                shared_secret = compute_shared_secret(pending_private_key, peer_public_key)
                self.state.session_keys[sender] = derive_session_key(shared_secret)
            else:
                # The peer initiated; generate our keys, derive the secret, and reply.
                our_private_key = generate_private_key()
                our_public_key = compute_public_key(our_private_key)
                shared_secret = compute_shared_secret(our_private_key, peer_public_key)
                self.state.session_keys[sender] = derive_session_key(shared_secret)
                self.sock.sendall(self.signed_dh_public(sender, our_public_key))

            session_key = self.state.session_keys[sender]
        print(f"[dh] Signed public value from {sender} verified: {peer_public_key}")
        print(f"[dh] {sender}'s signing key: {signing_key}")
        print(f"[dh] Shared secret established with {sender}")
        print(f"[dh] Session key (hex): {session_key.hex()}")

    def wait_for_session_key(self, peer: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.state.lock:
                if peer in self.state.session_keys:
                    return True
            time.sleep(0.05)
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure chat client")
    parser.add_argument("--username", required=True, help="Client username")
    parser.add_argument("--host", default="127.0.0.1", help="Server host")
    parser.add_argument("--port", type=int, default=9000, help="Server port")
    parser.add_argument("--message", help="Optional message to send once and exit")
    parser.add_argument("--target", help="Peer username to DH-handshake with and send --message to")
    parser.add_argument("--certs-dir", default="certs", help="Path to CA certificates directory")
    parser.add_argument("--no-cert", action="store_true", help="Disable certificate verification requirement")
    args = parser.parse_args()

    try:
        ChatClient(
            args.username,
            args.host,
            args.port,
            certs_dir=args.certs_dir,
            require_cert=not args.no_cert,
        ).run(args.message, args.target)
    except KeyboardInterrupt:
        print("\nConnection closed.")
        sys.exit(0)
