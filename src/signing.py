"""Ed25519 digital signatures.

Each client holds a long-lived identity key pair. It signs its DH public
value and every encrypted chat message with the private half; peers
verify with the public half. A valid signature proves the payload came
from the holder of that private key and was not modified afterwards.

Phase 3 limitation: the public signing key travels alongside the DH
public value, unauthenticated, so a man-in-the-middle could substitute
its own. Phase 4's certificate authority closes that gap by binding each
signing key to a username.
"""

import json
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

try:
    from src.crypto import b64decode, b64encode
except ImportError:
    from crypto import b64decode, b64encode


class SigningIdentity:
    """A client's Ed25519 key pair and optional CA-signed certificate."""

    def __init__(
        self,
        private_key: Ed25519PrivateKey,
        certificate_pem: Optional[str] = None,
    ) -> None:
        self.private_key = private_key
        public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_key_b64 = b64encode(public_bytes)
        self.certificate_pem = certificate_pem

    @classmethod
    def generate(cls) -> "SigningIdentity":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(
        cls,
        private_key_pem: str,
        certificate_pem: Optional[str] = None,
    ) -> "SigningIdentity":
        """Load identity from PEM-encoded private key and optional certificate."""
        from cryptography.hazmat.primitives.serialization import load_pem_private_key

        key = load_pem_private_key(private_key_pem.encode("ascii"), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise TypeError("Expected Ed25519 private key")
        return cls(key, certificate_pem=certificate_pem)

    @classmethod
    def load_or_generate(
        cls,
        username: str,
        certs_dir: str = "certs",
    ) -> "SigningIdentity":
        """Load credentials from certs_dir if available, otherwise generate new ones."""
        import os

        key_path = os.path.join(certs_dir, f"{username}_key.pem")
        cert_path = os.path.join(certs_dir, f"{username}.pem")

        if os.path.exists(key_path) and os.path.exists(cert_path):
            with open(key_path, "r", encoding="ascii") as f:
                key_pem = f.read()
            with open(cert_path, "r", encoding="ascii") as f:
                cert_pem = f.read()
            return cls.from_pem(key_pem, cert_pem)

        # Fallback to fresh generation without cert
        return cls.generate()

    def set_certificate(self, certificate_pem: str) -> None:
        self.certificate_pem = certificate_pem

    def sign(self, fields: Dict[str, Any]) -> str:
        return b64encode(self.private_key.sign(canonical_bytes(fields)))


def verify(public_key_b64: str, fields: Dict[str, Any], signature_b64: str) -> bool:
    """Return True only if signature_b64 is a valid signature of fields under the key."""
    try:
        public_key = Ed25519PublicKey.from_public_bytes(b64decode(public_key_b64))
        public_key.verify(b64decode(signature_b64), canonical_bytes(fields))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def canonical_bytes(fields: Dict[str, Any]) -> bytes:
    """Serialize fields deterministically so signer and verifier hash identical bytes.

    Plain json.dumps() may order keys or space values differently between
    calls; sorting keys and fixing separators gives one byte string per
    set of fields.
    """
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


if __name__ == "__main__":
    alice = SigningIdentity.generate()
    fields = {"type": "chat", "sender": "alice", "target": "bob", "ciphertext": "abc"}
    signature = alice.sign(fields)

    print(f"Alice's public key: {alice.public_key_b64}")
    print(f"Signature:          {signature}")
    print(f"Valid:              {verify(alice.public_key_b64, fields, signature)}")

    tampered = dict(fields, ciphertext="abd")
    print(f"Tampered valid:     {verify(alice.public_key_b64, tampered, signature)}")
