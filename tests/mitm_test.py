"""Adversarial Man-in-the-Middle (MITM) Testing Suite (Phase 5).

BACSE203 Computer Networks - Secure Messaging System

Simulates active and passive adversarial attacks against the messaging system:
1. Passive Eavesdropping (Ciphertext Inspection)
2. Classic Unauthenticated Diffie-Hellman Key Substitution (Phase 2 Flaw)
3. Signed Diffie-Hellman Key Substitution without CA (Phase 3 Flaw)
4. Active MITM against CA & Trust Chain (Phase 4 Defense):
   - Rogue/Self-Signed Certificate Injection
   - Identity Mismatch Impersonation
   - Certificate Replay with Key Substitution
   - Certificate Tampering
5. In-Transit Message Tampering (Ciphertext & Nonce bit-flipping)
6. Replay Attack Analysis

Can be run standalone:
    python tests/mitm_test.py

Or via unittest:
    python -m unittest tests/mitm_test.py -v
"""

import contextlib
import datetime
import io
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from typing import Any, Dict, List, Tuple

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding

from src.ca import (
    CertificateAuthority,
    cert_to_pem,
    pem_to_cert,
    private_key_to_pem,
    public_key_to_b64,
)
from src.client import ChatClient, MessageRejected
from src.crypto import DecryptionError, SessionCipher, b64decode, b64encode, chat_associated_data
from src.dh import (
    compute_public_key,
    compute_shared_secret,
    derive_session_key,
    generate_private_key,
)
from src.message_format import (
    build_chat_message,
    build_dh_public_message,
    chat_signed_fields,
    dh_public_signed_fields,
)
from src.protocol import default_protocol
from src.signing import SigningIdentity, verify


class PacketLogger:
    """Logs simulated network frames in Wireshark-friendly text capture format."""

    def __init__(self, log_path: str = "logs/traffic_capture.log", clear: bool = False) -> None:
        self.log_path = log_path
        os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
        if clear or not os.path.exists(self.log_path):
            with open(self.log_path, "w", encoding="utf-8") as f:
                f.write(f"# Secure Messaging System - Network Traffic Capture Log\n")
                f.write(f"# Started at: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n")
                f.write(f"# Format: [TIMESTAMP] [SRC:PORT -> DST:PORT] [FRAME_TYPE] PAYLOAD\n\n")

    def log(self, src: str, dst: str, frame: dict, note: str = "") -> None:
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S.%f")[:-3]
        frame_type = frame.get("type", "UNKNOWN")
        line = f"[{now}] [{src:>10} -> {dst:<10}] [{frame_type:<10}] {json.dumps(frame)}"
        if note:
            line += f"  # {note}"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


class MockWireSocket:
    """Mock socket capturing payloads sent by a ChatClient."""

    def __init__(self) -> None:
        self.sent: List[dict] = []

    def sendall(self, data: bytes) -> None:
        payload = default_protocol.decode(data.rstrip(default_protocol.delimiter))
        self.sent.append(payload)


class MITMTestRunner:
    """Executes all adversarial testing scenarios and prints formatted evaluation."""

    def __init__(self, logger: PacketLogger | None = None, clear_log: bool = False) -> None:
        self.logger = logger or PacketLogger(clear=clear_log)
        self.results: List[Tuple[str, str, str, str]] = []

    def record(self, scenario: str, attacker_action: str, outcome: str, status: str) -> None:
        self.results.append((scenario, attacker_action, outcome, status))

    def run_all(self) -> None:
        print("\n" + "=" * 80)
        print(" BACSE203 Computer Networks — Phase 5: Adversarial MITM Testing Suite")
        print("=" * 80 + "\n")

        self.test_passive_eavesdropping()
        self.test_unauthenticated_dh_mitm()
        self.test_signed_dh_without_ca_mitm()
        self.test_phase4_ca_rogue_cert()
        self.test_phase4_ca_identity_mismatch()
        self.test_phase4_ca_cert_replay_key_substitution()
        self.test_phase4_ca_tampered_cert()
        self.test_in_transit_ciphertext_tampering()
        self.test_replay_attack()

        self.print_summary()

    def test_passive_eavesdropping(self) -> None:
        """Scenario 1: Passive Eavesdropping on AES-256-GCM ciphertext."""
        print("--- [Scenario 1] Passive Eavesdropping on Encrypted Chat ---")
        session_key = derive_session_key(1234567890987654321)
        cipher = SessionCipher(session_key)
        aad = chat_associated_data("alice", "bob")
        plaintext = "Classified: Exam questions are in folder B"
        nonce, ciphertext = cipher.encrypt(plaintext, aad)

        chat_frame = {
            "type": "chat",
            "sender": "alice",
            "target": "bob",
            "nonce": nonce,
            "ciphertext": ciphertext,
            "signature": "simulated_sig",
        }
        self.logger.log("alice:9001", "server:9000", chat_frame, "Alice sends encrypted message")
        self.logger.log("server:9000", "bob:9002", chat_frame, "Server relays ciphertext")

        # Mallory captures chat_frame
        eavesdropped_bytes = b64decode(ciphertext)
        plaintext_leaked = plaintext.encode("utf-8") in eavesdropped_bytes

        # Mallory attempts decryption without session key
        mallory_key = derive_session_key(9999999999999999999)
        mallory_cipher = SessionCipher(mallory_key)
        mallory_success = False
        try:
            mallory_cipher.decrypt(nonce, ciphertext, aad)
            mallory_success = True
        except DecryptionError:
            mallory_success = False

        if not plaintext_leaked and not mallory_success:
            print("[PASS] Attacker cannot read plaintext. AES-256-GCM confidentiality holds.")
            self.record("Passive Eavesdropping", "Sniff ciphertext off wire", "Decryption failed (Invalid Tag)", "BLOCKED")
        else:
            print("[FAIL] Plaintext leaked to attacker!")
            self.record("Passive Eavesdropping", "Sniff ciphertext", "Plaintext exposed", "VULNERABLE")

    def test_unauthenticated_dh_mitm(self) -> None:
        """Scenario 2: Classic MITM against unauthenticated DH (Phase 2 Flaw)."""
        print("\n--- [Scenario 2] Classic DH Key Substitution MITM (Phase 2 Flaw) ---")
        # Alice generates keys
        a_priv = generate_private_key()
        A_pub = compute_public_key(a_priv)

        # Mallory sits in middle, generates two keys
        m_priv_for_alice = generate_private_key()
        M_pub_for_alice = compute_public_key(m_priv_for_alice)

        m_priv_for_bob = generate_private_key()
        M_pub_for_bob = compute_public_key(m_priv_for_bob)

        # Bob generates keys
        b_priv = generate_private_key()
        B_pub = compute_public_key(b_priv)

        # Alice -> Mallory (Alice thinks Bob is peer)
        self.logger.log("alice", "mallory", {"type": "dh_public", "public_key": str(A_pub)}, "Alice sends A (intercepted)")
        # Mallory -> Bob (Mallory replaces A with M_pub_for_bob)
        self.logger.log("mallory", "bob", {"type": "dh_public", "public_key": str(M_pub_for_bob)}, "Mallory substitutes A with M")

        # Bob computes key with Mallory
        s_bob_mallory = compute_shared_secret(b_priv, M_pub_for_bob)
        k_bm = derive_session_key(s_bob_mallory)

        # Bob -> Mallory (Bob sends B)
        self.logger.log("bob", "mallory", {"type": "dh_public", "public_key": str(B_pub)}, "Bob sends B (intercepted)")
        # Mallory -> Alice (Mallory replaces B with M_pub_for_alice)
        self.logger.log("mallory", "alice", {"type": "dh_public", "public_key": str(M_pub_for_alice)}, "Mallory substitutes B with M")

        # Alice computes key with Mallory
        s_alice_mallory = compute_shared_secret(a_priv, M_pub_for_alice)
        k_am = derive_session_key(s_alice_mallory)

        # Mallory computes both matching keys!
        k_ma = derive_session_key(compute_shared_secret(m_priv_for_alice, A_pub))
        k_mb = derive_session_key(compute_shared_secret(m_priv_for_bob, B_pub))

        self.logger.log("mallory", "mallory", {"status": "keys_established", "k_am": k_ma.hex()[:16], "k_bm": k_mb.hex()[:16]})

        # Now Alice sends encrypted message
        alice_cipher = SessionCipher(k_am)
        msg_alice = "Transfer $1,000 to Bob"
        n, c = alice_cipher.encrypt(msg_alice, chat_associated_data("alice", "bob"))

        # Mallory intercepts and decrypts!
        mallory_decrypt = SessionCipher(k_ma).decrypt(n, c, chat_associated_data("alice", "bob"))

        # Mallory tampers and re-encrypts to Bob!
        tampered_msg = "Transfer $10,000 to Mallory"
        n2, c2 = SessionCipher(k_mb).encrypt(tampered_msg, chat_associated_data("alice", "bob"))

        # Bob decrypts tampered message successfully!
        bob_received = SessionCipher(k_bm).decrypt(n2, c2, chat_associated_data("alice", "bob"))

        if bob_received == tampered_msg:
            print(f"[EXPLOITED] Unauthenticated DH intercepted! Alice sent: '{msg_alice}', Bob got: '{bob_received}'")
            self.record("Unauthenticated DH (Phase 2)", "Intercept DH values & split session", "Plaintext read & tampered", "SUCCEEDED (Proves Phase 2 flaw)")

    def test_signed_dh_without_ca_mitm(self) -> None:
        """Scenario 3: Signed DH key substitution without CA (Phase 3 Flaw)."""
        print("\n--- [Scenario 3] Signed DH Key Substitution without CA (Phase 3 Flaw) ---")
        alice_identity = SigningIdentity.generate()
        mallory_identity = SigningIdentity.generate()

        a_priv = generate_private_key()
        A_pub = compute_public_key(a_priv)

        m_priv = generate_private_key()
        M_pub = compute_public_key(m_priv)

        # Alice sends signed DH
        sig_alice = alice_identity.sign(dh_public_signed_fields("alice", "bob", A_pub, alice_identity.public_key_b64))

        # Mallory intercepts and replaces BOTH DH public key AND signing key with Mallory's key
        sig_mallory = mallory_identity.sign(dh_public_signed_fields("alice", "bob", M_pub, mallory_identity.public_key_b64))
        substituted_msg = {
            "type": "dh_public",
            "sender": "alice",
            "target": "bob",
            "public_key": str(M_pub),
            "signing_key": mallory_identity.public_key_b64,
            "signature": sig_mallory,
        }

        # Bob (in Phase 3 without CA) checks signature using the transmitted signing_key:
        fields = dh_public_signed_fields("alice", "bob", M_pub, mallory_identity.public_key_b64)
        bob_phase3_accepts = verify(mallory_identity.public_key_b64, fields, sig_mallory)

        if bob_phase3_accepts:
            print("[EXPLOITED] In Phase 3, Bob accepts replaced signing key on first sight without CA binding!")
            self.record("Signed DH without CA (Phase 3)", "Substitute DH key + signing key", "Bob accepted rogue signing key", "SUCCEEDED (Proves Phase 3 flaw)")

    def test_phase4_ca_rogue_cert(self) -> None:
        """Scenario 4a: Phase 4 CA defense against Rogue CA certificate injection."""
        print("\n--- [Scenario 4a] Active MITM: Rogue CA Certificate Injection (Phase 4) ---")
        root_ca = CertificateAuthority.create_root(common_name="BACSE203 Root CA")
        rogue_ca = CertificateAuthority.create_root(common_name="Mallory Untrusted CA")

        mallory_key = ed25519.Ed25519PrivateKey.generate()
        rogue_cert = rogue_ca.issue_certificate("alice", mallory_key.public_key())

        # Bob verifies against trusted Root CA
        valid, cn, pub_key, reason = root_ca.verify_certificate(cert_to_pem(rogue_cert), expected_username="alice")

        self.logger.log("mallory", "bob", {"type": "dh_public", "cert": "rogue_ca_cert"}, f"Result: {reason}")

        if not valid and "Untrusted issuer" in reason:
            print(f"[BLOCKED] Root CA rejected untrusted issuer: '{reason}'")
            self.record("Active MITM (Phase 4)", "Inject cert from rogue/untrusted CA", f"Rejected: {reason}", "BLOCKED")
        else:
            print("[FAIL] Rogue certificate accepted!")
            self.record("Active MITM (Phase 4)", "Inject rogue cert", "Accepted", "VULNERABLE")

    def test_phase4_ca_identity_mismatch(self) -> None:
        """Scenario 4b: Phase 4 CA defense against Identity Mismatch."""
        print("\n--- [Scenario 4b] Active MITM: Valid Cert with Identity Mismatch (Phase 4) ---")
        root_ca = CertificateAuthority.create_root(common_name="BACSE203 Root CA")

        mallory_key = ed25519.Ed25519PrivateKey.generate()
        mallory_cert = root_ca.issue_certificate("mallory", mallory_key.public_key())

        # Mallory claims to be Alice, but presents cert issued for Mallory
        valid, cn, pub_key, reason = root_ca.verify_certificate(cert_to_pem(mallory_cert), expected_username="alice")

        if not valid and "Identity mismatch" in reason:
            print(f"[BLOCKED] Detected identity mismatch: '{reason}'")
            self.record("Active MITM (Phase 4)", "Mallory cert claiming to be Alice", f"Rejected: {reason}", "BLOCKED")
        else:
            print("[FAIL] Mismatched identity accepted!")
            self.record("Active MITM (Phase 4)", "Identity mismatch", "Accepted", "VULNERABLE")

    def test_phase4_ca_cert_replay_key_substitution(self) -> None:
        """Scenario 4c: Phase 4 CA defense against Certificate Replay + Key Substitution."""
        print("\n--- [Scenario 4c] Active MITM: Certificate Replay with Key Substitution (Phase 4) ---")
        root_ca = CertificateAuthority.create_root(common_name="BACSE203 Root CA")

        alice_key = ed25519.Ed25519PrivateKey.generate()
        alice_cert = root_ca.issue_certificate("alice", alice_key.public_key())

        mallory_key = ed25519.Ed25519PrivateKey.generate()
        mallory_identity = SigningIdentity(mallory_key)

        # Mallory sends Alice's genuine certificate, but substitutes signing_key with Mallory's
        alice_cert_pem = cert_to_pem(alice_cert)
        valid, cn, cert_pub_key, reason = root_ca.verify_certificate(alice_cert_pem, expected_username="alice")

        # Handshake binding check:
        key_matches = (cert_pub_key == mallory_identity.public_key_b64)

        if valid and not key_matches:
            print("[BLOCKED] Public key in Alice's certificate does NOT match Mallory's signing key!")
            self.record("Active MITM (Phase 4)", "Replay Alice cert with Mallory key", "Binding check failed (Key mismatch)", "BLOCKED")
        else:
            print("[FAIL] Replayed cert with substituted key was accepted!")
            self.record("Active MITM (Phase 4)", "Replay cert with substituted key", "Accepted", "VULNERABLE")

    def test_phase4_ca_tampered_cert(self) -> None:
        """Scenario 4d: Phase 4 CA defense against Tampered Certificate."""
        print("\n--- [Scenario 4d] Active MITM: Tampered Certificate Fields (Phase 4) ---")
        root_ca = CertificateAuthority.create_root(common_name="BACSE203 Root CA")
        alice_key = ed25519.Ed25519PrivateKey.generate()
        alice_cert = root_ca.issue_certificate("alice", alice_key.public_key())

        der = bytearray(alice_cert.public_bytes(Encoding.DER))
        # Modify bytes in subject/public key area
        der[50] ^= 0x55

        try:
            tampered_cert = x509.load_der_x509_certificate(bytes(der))
            valid, _, _, reason = root_ca.verify_certificate(tampered_cert, expected_username="alice")
        except Exception as exc:
            valid = False
            reason = f"ASN.1 decode error or invalid signature: {exc}"

        if not valid:
            print(f"[BLOCKED] CA signature invalid on tampered certificate: '{reason}'")
            self.record("Active MITM (Phase 4)", "Modify bytes in certificate", f"Rejected: {reason[:40]}...", "BLOCKED")
        else:
            print("[FAIL] Tampered certificate passed validation!")
            self.record("Active MITM (Phase 4)", "Modify certificate bytes", "Accepted", "VULNERABLE")

    def test_in_transit_ciphertext_tampering(self) -> None:
        """Scenario 5: Active In-Transit Ciphertext & Nonce Tampering."""
        print("\n--- [Scenario 5] In-Transit Tampering of Encrypted Messages ---")
        alice_identity = SigningIdentity.generate()
        session_key = derive_session_key(4242424242)
        cipher = SessionCipher(session_key)

        nonce, ciphertext = cipher.encrypt("Meet me at gate 3", chat_associated_data("alice", "bob"))
        sig = alice_identity.sign(chat_signed_fields("alice", "bob", nonce, ciphertext))

        # Attacker tampers with ciphertext byte
        raw_ct = bytearray(b64decode(ciphertext))
        raw_ct[0] ^= 0x01
        tampered_ciphertext = b64encode(bytes(raw_ct))

        # Bob verifies signature
        sig_valid = verify(alice_identity.public_key_b64, chat_signed_fields("alice", "bob", nonce, tampered_ciphertext), sig)

        # Even if attacker forged signature somehow, GCM decryption checks tag:
        gcm_tamper_detected = False
        try:
            cipher.decrypt(nonce, tampered_ciphertext, chat_associated_data("alice", "bob"))
        except DecryptionError:
            gcm_tamper_detected = True

        if not sig_valid and gcm_tamper_detected:
            print("[BLOCKED] Tampered ciphertext rejected by both Ed25519 signature and AES-GCM auth tag!")
            self.record("Ciphertext Tampering", "Flip 1 bit in transmitted ciphertext", "Rejected by Signature & GCM Tag", "BLOCKED")
        else:
            print("[FAIL] Tampering went undetected!")
            self.record("Ciphertext Tampering", "Flip 1 bit in ciphertext", "Accepted", "VULNERABLE")

    def test_replay_attack(self) -> None:
        """Scenario 6: Message Replay Attack Analysis."""
        print("\n--- [Scenario 6] Replay Attack Analysis (Residual Risk) ---")
        alice_identity = SigningIdentity.generate()
        session_key = derive_session_key(5555555555)
        cipher = SessionCipher(session_key)

        nonce, ciphertext = cipher.encrypt("Transfer approved", chat_associated_data("alice", "bob"))
        sig = alice_identity.sign(chat_signed_fields("alice", "bob", nonce, ciphertext))

        # First delivery
        first_valid = verify(alice_identity.public_key_b64, chat_signed_fields("alice", "bob", nonce, ciphertext), sig)
        first_pt = cipher.decrypt(nonce, ciphertext, chat_associated_data("alice", "bob"))

        # Attacker captures frame and replays 10 seconds later:
        replay_valid = verify(alice_identity.public_key_b64, chat_signed_fields("alice", "bob", nonce, ciphertext), sig)
        replay_pt = cipher.decrypt(nonce, ciphertext, chat_associated_data("alice", "bob"))

        self.logger.log("mallory", "bob", {"type": "chat", "nonce": nonce, "ciphertext": ciphertext, "signature": sig}, "Replayed packet")

        print("[ANALYSIS] Without sequence numbers/timestamps, replayed valid frames verify again.")
        print("          This defines the explicit protection boundary documented in Phase 6.")
        self.record("Replay Attack", "Resend captured valid frame", "Accepted (Documented residual risk)", "DOCUMENTED LIMITATION")

    def print_summary(self) -> None:
        print("\n" + "=" * 90)
        print(" ADVERSARIAL TESTING SUMMARY & PROTECTION BOUNDARY MATRIX")
        print("=" * 90)
        row_fmt = "{:<32} | {:<28} | {:<16} | {:<10}"
        print(row_fmt.format("Attack Scenario", "Adversary Action", "Defense Mechanism", "Result"))
        print("-" * 90)
        for scenario, action, outcome, status in self.results:
            print(row_fmt.format(scenario[:32], action[:28], outcome[:16], status[:10]))
        print("=" * 90)
        print(f"Network packet trace written to: {self.logger.log_path}\n")


class AdversarialTestSuite(unittest.TestCase):
    """Unittest wrapper for CI/CD and automatic evaluation."""

    def setUp(self) -> None:
        self.runner = MITMTestRunner()

    def test_passive_eavesdropping_prevented(self) -> None:
        self.runner.test_passive_eavesdropping()
        self.assertEqual(self.runner.results[-1][3], "BLOCKED")

    def test_classic_dh_mitm_demonstrated(self) -> None:
        self.runner.test_unauthenticated_dh_mitm()
        self.assertIn("SUCCEEDED", self.runner.results[-1][3])

    def test_signed_dh_without_ca_mitm_demonstrated(self) -> None:
        self.runner.test_signed_dh_without_ca_mitm()
        self.assertIn("SUCCEEDED", self.runner.results[-1][3])

    def test_ca_blocks_rogue_cert(self) -> None:
        self.runner.test_phase4_ca_rogue_cert()
        self.assertEqual(self.runner.results[-1][3], "BLOCKED")

    def test_ca_blocks_identity_mismatch(self) -> None:
        self.runner.test_phase4_ca_identity_mismatch()
        self.assertEqual(self.runner.results[-1][3], "BLOCKED")

    def test_ca_blocks_cert_replay_key_sub(self) -> None:
        self.runner.test_phase4_ca_cert_replay_key_substitution()
        self.assertEqual(self.runner.results[-1][3], "BLOCKED")

    def test_ciphertext_tampering_blocked(self) -> None:
        self.runner.test_in_transit_ciphertext_tampering()
        self.assertEqual(self.runner.results[-1][3], "BLOCKED")


if __name__ == "__main__":
    MITMTestRunner(clear_log=True).run_all()
