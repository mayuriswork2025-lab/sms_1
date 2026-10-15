"""AES-256-GCM session encryption.

Each chat message is encrypted with the 32-byte session key derived from
the Diffie-Hellman exchange (src/dh.py). GCM is an authenticated mode: it
produces ciphertext plus a 16-byte tag, and decryption fails if a single
bit of the ciphertext, nonce, or associated data was changed.

Associated data (AAD) is authenticated but not encrypted. We use it to
bind each ciphertext to its sender and target, so a relay can't take a
message Alice sent to Bob and re-deliver it as if it were for someone else.
"""

import base64
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE_BYTES = 12


class DecryptionError(ValueError):
    """Raised when a ciphertext fails GCM authentication or is malformed."""


class SessionCipher:
    """Encrypts and decrypts messages for one peer with a shared session key."""

    def __init__(self, session_key: bytes) -> None:
        if len(session_key) != 32:
            raise ValueError("AES-256 needs a 32-byte session key")
        self.aesgcm = AESGCM(session_key)

    def encrypt(self, plaintext: str, associated_data: bytes) -> tuple[str, str]:
        """Return (nonce, ciphertext), both base64-encoded for the JSON wire format.

        A fresh random nonce is used for every message. Reusing a nonce with
        the same key would break GCM's confidentiality and integrity, so it
        is never derived from anything predictable.
        """
        nonce = os.urandom(NONCE_SIZE_BYTES)
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
        return b64encode(nonce), b64encode(ciphertext)

    def decrypt(self, nonce_b64: str, ciphertext_b64: str, associated_data: bytes) -> str:
        try:
            nonce = b64decode(nonce_b64)
            ciphertext = b64decode(ciphertext_b64)
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, associated_data)
            return plaintext.decode("utf-8")
        except (InvalidTag, ValueError) as exc:
            raise DecryptionError("ciphertext failed authentication") from exc


def chat_associated_data(sender: str, target: str) -> bytes:
    return f"chat|{sender}|{target}".encode("utf-8")


def b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64decode(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


if __name__ == "__main__":
    key = os.urandom(32)
    cipher = SessionCipher(key)
    aad = chat_associated_data("alice", "bob")

    nonce, ciphertext = cipher.encrypt("hello bob", aad)
    print(f"Nonce:      {nonce}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted:  {cipher.decrypt(nonce, ciphertext, aad)}")

    try:
        cipher.decrypt(nonce, ciphertext, chat_associated_data("alice", "carol"))
    except DecryptionError:
        print("Re-targeted ciphertext rejected: OK")
