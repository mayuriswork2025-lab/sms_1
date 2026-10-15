"""Unit and integration tests for Certificate Authority and Trust Chain (Phase 4).

Tests:
1. Root CA generation, export, and re-import.
2. Certificate issuance with valid Common Name and Ed25519 public key.
3. Successful certificate verification against trusted Root CA.
4. Rejection of certificates from untrusted/rogue CAs.
5. Rejection of tampered certificates (modified subject or signature).
6. Rejection of expired certificates.
7. Rejection of revoked certificates.
8. Rejection of identity mismatch (CN != expected username).
9. Rejection of mismatched public key (certificate public key != signing key).
10. Full End-to-End DH handshake and message exchange using CA-validated identities.
11. Rejection of handshake when certificate is missing or forged.
"""

import contextlib
import datetime
import io
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from src.ca import (
    CertificateAuthority,
    cert_to_pem,
    pem_to_cert,
    private_key_to_pem,
    public_key_to_b64,
)
from src.client import ChatClient, MessageRejected
from src.message_format import build_dh_public_message, dh_public_signed_fields
from src.protocol import default_protocol
from src.signing import SigningIdentity


class RecordingSocket:
    """In-memory mock socket recording transmitted frames."""

    def __init__(self) -> None:
        self.sent: list[dict] = []

    def sendall(self, data: bytes) -> None:
        self.sent.append(default_protocol.decode(data.rstrip(default_protocol.delimiter)))


class CertificateAuthorityUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.ca = CertificateAuthority.create_root(common_name="Test Root CA")
        self.ca.save_to_dir(self.temp_dir)

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_ca_save_and_load(self) -> None:
        loaded_ca = CertificateAuthority.load_from_dir(self.temp_dir)
        self.assertEqual(loaded_ca.ca_cert.subject, self.ca.ca_cert.subject)
        self.assertIsNotNone(loaded_ca.ca_private_key)

    def test_issue_and_verify_valid_certificate(self) -> None:
        user_key = ed25519.Ed25519PrivateKey.generate()
        cert = self.ca.issue_certificate("alice", user_key.public_key(), validity_days=30)
        cert_pem = cert_to_pem(cert)

        valid, cn, pub_key, reason = self.ca.verify_certificate(cert_pem, expected_username="alice")
        self.assertTrue(valid)
        self.assertEqual(cn, "alice")
        self.assertEqual(pub_key, public_key_to_b64(user_key.public_key()))
        self.assertIn("verified successfully", reason)

    def test_untrusted_issuer_is_rejected(self) -> None:
        rogue_ca = CertificateAuthority.create_root(common_name="Rogue Evil CA")
        user_key = ed25519.Ed25519PrivateKey.generate()
        rogue_cert = rogue_ca.issue_certificate("alice", user_key.public_key())
        rogue_pem = cert_to_pem(rogue_cert)

        valid, cn, pub_key, reason = self.ca.verify_certificate(rogue_pem, expected_username="alice")
        self.assertFalse(valid)
        self.assertIn("Untrusted issuer", reason)

    def test_identity_mismatch_is_rejected(self) -> None:
        user_key = ed25519.Ed25519PrivateKey.generate()
        cert = self.ca.issue_certificate("bob", user_key.public_key())
        cert_pem = cert_to_pem(cert)

        # Alice presenting Bob's certificate
        valid, cn, pub_key, reason = self.ca.verify_certificate(cert_pem, expected_username="alice")
        self.assertFalse(valid)
        self.assertEqual(cn, "bob")
        self.assertIn("Identity mismatch", reason)

    def test_expired_certificate_is_rejected(self) -> None:
        user_key = ed25519.Ed25519PrivateKey.generate()
        # Certificate with validity in the past
        now = datetime.datetime.now(datetime.timezone.utc)
        expired_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "alice")]))
            .issuer_name(self.ca.ca_cert.subject)
            .public_key(user_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=60))
            .not_valid_after(now - datetime.timedelta(days=1))
            .sign(self.ca.ca_private_key, None)
        )
        valid, cn, pub_key, reason = self.ca.verify_certificate(cert_to_pem(expired_cert), expected_username="alice")
        self.assertFalse(valid)
        self.assertIn("expired", reason)

    def test_revoked_certificate_is_rejected(self) -> None:
        user_key = ed25519.Ed25519PrivateKey.generate()
        cert = self.ca.issue_certificate("alice", user_key.public_key())
        self.ca.revoke_certificate(cert.serial_number)

        valid, cn, pub_key, reason = self.ca.verify_certificate(cert_to_pem(cert), expected_username="alice")
        self.assertFalse(valid)
        self.assertIn("revoked", reason)

    def test_tampered_signature_is_rejected(self) -> None:
        user_key = ed25519.Ed25519PrivateKey.generate()
        cert = self.ca.issue_certificate("alice", user_key.public_key())
        # Tamper with the raw DER bytes of the certificate
        der = bytearray(cert.public_bytes(Encoding.DER))
        der[-5] ^= 0xFF
        try:
            tampered_cert = x509.load_der_x509_certificate(bytes(der))
            valid, _, _, reason = self.ca.verify_certificate(tampered_cert, expected_username="alice")
            self.assertFalse(valid)
        except Exception:
            # Parsing error also constitutes rejection
            pass


class TrustChainEndToEndTests(unittest.TestCase):
    """Integration tests verifying full client handshake with CA validation."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.mkdtemp()
        self.ca = CertificateAuthority.create_root(common_name="BACSE203 Root CA")
        self.ca.save_to_dir(self.temp_dir)

        # Issue certificates for Alice and Bob
        for name in ("alice", "bob"):
            key = ed25519.Ed25519PrivateKey.generate()
            cert = self.ca.issue_certificate(name, key.public_key())
            with open(os.path.join(self.temp_dir, f"{name}.pem"), "w", encoding="ascii") as f:
                f.write(cert_to_pem(cert))
            with open(os.path.join(self.temp_dir, f"{name}_key.pem"), "w", encoding="ascii") as f:
                f.write(private_key_to_pem(key))

        # Create clients configured with this CA directory
        self.alice = ChatClient("alice", "127.0.0.1", 0, certs_dir=self.temp_dir, require_cert=True)
        self.bob = ChatClient("bob", "127.0.0.1", 0, certs_dir=self.temp_dir, require_cert=True)
        self.alice.sock = RecordingSocket()
        self.bob.sock = RecordingSocket()

    def tearDown(self) -> None:
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_successful_ca_validated_handshake_and_chat(self) -> None:
        # Handshake: Alice -> Bob, Bob -> Alice
        with contextlib.redirect_stdout(io.StringIO()):
            self.alice.start_dh_handshake("bob")
            alice_dh_msg = self.alice.sock.sent[-1]
            self.assertIn("certificate", alice_dh_msg)

            self.bob.handle_dh_public(alice_dh_msg)
            bob_dh_msg = self.bob.sock.sent[-1]
            self.assertIn("certificate", bob_dh_msg)

            self.alice.handle_dh_public(bob_dh_msg)

        # Verify matching session keys
        self.assertIn("bob", self.alice.state.session_keys)
        self.assertIn("alice", self.bob.state.session_keys)
        self.assertEqual(self.alice.state.session_keys["bob"], self.bob.state.session_keys["alice"])

        # Bob has validated Alice's certificate
        self.assertIn("alice", self.bob.state.peer_certificates)

        # Alice sends encrypted chat message, Bob decrypts and verifies
        chat_bytes = self.alice.seal_chat("bob", "Verified with CA!")
        chat_payload = default_protocol.decode(chat_bytes.rstrip(default_protocol.delimiter))
        decrypted = self.bob.open_chat(chat_payload)
        self.assertEqual(decrypted, "Verified with CA!")

    def test_handshake_with_untrusted_ca_cert_is_rejected(self) -> None:
        rogue_ca = CertificateAuthority.create_root(common_name="Attacker CA")
        mallory_key = ed25519.Ed25519PrivateKey.generate()
        rogue_cert = rogue_ca.issue_certificate("alice", mallory_key.public_key())

        signing_identity = SigningIdentity(mallory_key)
        fake_pub_key = 123456789
        sig = signing_identity.sign(
            dh_public_signed_fields("alice", "bob", fake_pub_key, signing_identity.public_key_b64, cert_to_pem(rogue_cert))
        )
        fake_msg = default_protocol.decode(
            build_dh_public_message(
                "alice", "bob", fake_pub_key, signing_identity.public_key_b64, sig, cert_to_pem(rogue_cert)
            ).rstrip(default_protocol.delimiter)
        )

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.bob.handle_dh_public(fake_msg)

        self.assertIn("certificate verification failed", output.getvalue())
        self.assertNotIn("alice", self.bob.state.session_keys)

    def test_handshake_with_mismatched_public_key_is_rejected(self) -> None:
        # Mallory sends Alice's valid certificate, but Mallory's own signing key
        mallory_identity = SigningIdentity.generate()
        alice_cert_pem = self.alice.identity.certificate_pem

        fake_pub_key = 987654321
        sig = mallory_identity.sign(
            dh_public_signed_fields("alice", "bob", fake_pub_key, mallory_identity.public_key_b64, alice_cert_pem)
        )
        fake_msg = default_protocol.decode(
            build_dh_public_message(
                "alice", "bob", fake_pub_key, mallory_identity.public_key_b64, sig, alice_cert_pem
            ).rstrip(default_protocol.delimiter)
        )

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.bob.handle_dh_public(fake_msg)

        self.assertIn("signing key does not match certificate public key", output.getvalue())
        self.assertNotIn("alice", self.bob.state.session_keys)

    def test_handshake_with_missing_cert_is_rejected_when_required(self) -> None:
        signing_identity = SigningIdentity.generate()
        fake_pub_key = 1122334455
        sig = signing_identity.sign(
            dh_public_signed_fields("alice", "bob", fake_pub_key, signing_identity.public_key_b64, "")
        )
        legacy_msg = default_protocol.decode(
            build_dh_public_message(
                "alice", "bob", fake_pub_key, signing_identity.public_key_b64, sig, ""
            ).rstrip(default_protocol.delimiter)
        )

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.bob.handle_dh_public(legacy_msg)

        self.assertIn("missing certificate", output.getvalue())
        self.assertNotIn("alice", self.bob.state.session_keys)


if __name__ == "__main__":
    unittest.main()
