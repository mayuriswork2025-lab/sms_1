"""Certificate Authority (CA), certificate issuance, validation, and trust chain.

BACSE203 Computer Networks - Secure Messaging System (Phase 4)

Binds client identities (usernames) to Ed25519 public signing keys using
X.509 v3 certificates signed by a trusted Root Certificate Authority.
Provides root key management, certificate issuance, expiration checking,
revocation tracking (CRL), and full trust chain verification.
"""

import argparse
import datetime
import os
import sys
from typing import Dict, Optional, Set, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
)
from cryptography.x509.oid import NameOID

try:
    from src.crypto import b64decode, b64encode
except ImportError:
    from crypto import b64decode, b64encode

DEFAULT_CERTS_DIR = "certs"
DEFAULT_CA_CN = "BACSE203 Root CA"
DEFAULT_VALIDITY_DAYS = 90
ROOT_CA_VALIDITY_DAYS = 3650


class CertificateVerificationError(ValueError):
    """Raised when an X.509 certificate fails trust chain or integrity checks."""


def cert_to_pem(cert: x509.Certificate) -> str:
    """Serialize an X.509 Certificate object to PEM-encoded string."""
    return cert.public_bytes(Encoding.PEM).decode("ascii")


def pem_to_cert(pem_data: str | bytes) -> x509.Certificate:
    """Parse a PEM-encoded certificate string or bytes into an X.509 Certificate."""
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("ascii")
    return x509.load_pem_x509_certificate(pem_data)


def private_key_to_pem(key: ed25519.Ed25519PrivateKey) -> str:
    """Serialize an Ed25519 private key to PKCS#8 PEM string (unencrypted for lab)."""
    return key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    ).decode("ascii")


def pem_to_private_key(pem_data: str | bytes) -> ed25519.Ed25519PrivateKey:
    """Load an Ed25519 private key from PEM bytes/string."""
    if isinstance(pem_data, str):
        pem_data = pem_data.encode("ascii")
    key = load_pem_private_key(pem_data, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError("Expected Ed25519 private key")
    return key


def public_key_to_b64(pub_key: ed25519.Ed25519PublicKey) -> str:
    """Convert an Ed25519 public key to standard raw base64."""
    raw = pub_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return b64encode(raw)


def b64_to_public_key(b64_str: str) -> ed25519.Ed25519PublicKey:
    """Parse a base64 string back into an Ed25519PublicKey."""
    raw = b64decode(b64_str)
    return ed25519.Ed25519PublicKey.from_public_bytes(raw)


class CertificateAuthority:
    """Issues, stores, revokes, and validates X.509 certificates.

    Acts as the Root of Trust for the messaging system. Both clients
    configure the CA's root certificate to verify peers during the DH
    handshake, preventing MITM public key substitution.
    """

    def __init__(
        self,
        ca_cert: x509.Certificate,
        ca_private_key: Optional[ed25519.Ed25519PrivateKey] = None,
        revoked_serials: Optional[Set[int]] = None,
    ) -> None:
        self.ca_cert = ca_cert
        self.ca_private_key = ca_private_key
        self.revoked_serials: Set[int] = set(revoked_serials or [])
        # Record of issued certificates: {username: x509.Certificate}
        self.issued_registry: Dict[str, x509.Certificate] = {}

    @classmethod
    def create_root(
        cls,
        common_name: str = DEFAULT_CA_CN,
        validity_days: int = ROOT_CA_VALIDITY_DAYS,
    ) -> "CertificateAuthority":
        """Generate a brand-new self-signed Root CA key pair and certificate."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        now = datetime.datetime.now(datetime.timezone.utc)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(private_key, None)
        )
        return cls(ca_cert=ca_cert, ca_private_key=private_key)

    @classmethod
    def load_from_dir(cls, certs_dir: str = DEFAULT_CERTS_DIR) -> "CertificateAuthority":
        """Load Root CA certificate and private key from the given directory."""
        ca_cert_path = os.path.join(certs_dir, "ca.pem")
        ca_key_path = os.path.join(certs_dir, "ca_key.pem")

        if not os.path.exists(ca_cert_path):
            raise FileNotFoundError(f"Root CA cert not found at {ca_cert_path}")

        with open(ca_cert_path, "r", encoding="ascii") as f:
            ca_cert = pem_to_cert(f.read())

        ca_key = None
        if os.path.exists(ca_key_path):
            with open(ca_key_path, "r", encoding="ascii") as f:
                ca_key = pem_to_private_key(f.read())

        ca = cls(ca_cert=ca_cert, ca_private_key=ca_key)

        # Load revocation file if present
        crl_path = os.path.join(certs_dir, "crl.txt")
        if os.path.exists(crl_path):
            with open(crl_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            ca.revoked_serials.add(int(line))
                        except ValueError:
                            pass

        return ca

    def save_to_dir(self, certs_dir: str = DEFAULT_CERTS_DIR) -> None:
        """Persist Root CA certificate and private key to disk."""
        os.makedirs(certs_dir, exist_ok=True)
        ca_cert_path = os.path.join(certs_dir, "ca.pem")
        with open(ca_cert_path, "w", encoding="ascii") as f:
            f.write(cert_to_pem(self.ca_cert))

        if self.ca_private_key is not None:
            ca_key_path = os.path.join(certs_dir, "ca_key.pem")
            with open(ca_key_path, "w", encoding="ascii") as f:
                f.write(private_key_to_pem(self.ca_private_key))

        crl_path = os.path.join(certs_dir, "crl.txt")
        with open(crl_path, "w", encoding="utf-8") as f:
            f.write("# Revoked Certificate Serial Numbers\n")
            for serial in sorted(self.revoked_serials):
                f.write(f"{serial}\n")

    def issue_certificate(
        self,
        username: str,
        public_key: ed25519.Ed25519PublicKey | str,
        validity_days: int = DEFAULT_VALIDITY_DAYS,
    ) -> x509.Certificate:
        """Issue an identity certificate binding `username` to `public_key`.

        Signed with the CA's Ed25519 private key.
        """
        if self.ca_private_key is None:
            raise PermissionError("Cannot issue certificates: CA private key not loaded.")

        if isinstance(public_key, str):
            public_key = b64_to_public_key(public_key)

        now = datetime.datetime.now(datetime.timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self.ca_private_key, None)
        )

        self.issued_registry[username] = cert
        return cert

    def revoke_certificate(self, serial_number: int) -> None:
        """Mark a certificate serial number as revoked."""
        self.revoked_serials.add(serial_number)

    def is_revoked(self, serial_number: int) -> bool:
        """Check if serial number is on revocation list."""
        return serial_number in self.revoked_serials

    def verify_certificate(
        self,
        cert_data: x509.Certificate | str | bytes,
        expected_username: Optional[str] = None,
        check_time: Optional[datetime.datetime] = None,
    ) -> Tuple[bool, str, str, str]:
        """Validate an X.509 certificate against this CA root.

        Checks performed:
        1. Parse certificate format.
        2. Issuer matches CA root subject name.
        3. Cryptographic signature check under CA public key.
        4. Expiration check (not_valid_before <= check_time <= not_valid_after).
        5. Revocation status check.
        6. Identity check: Subject Common Name matches expected_username.

        Returns:
            (is_valid, common_name, public_key_b64, reason_string)
        """
        try:
            if isinstance(cert_data, (str, bytes)):
                cert = pem_to_cert(cert_data)
            else:
                cert = cert_data
        except Exception as exc:
            return False, "", "", f"Malformed certificate: {exc}"

        # 1. Issuer check
        if cert.issuer != self.ca_cert.subject:
            return (
                False,
                "",
                "",
                f"Untrusted issuer: '{cert.issuer}' does not match root CA '{self.ca_cert.subject}'",
            )

        # 2. Cryptographic signature check
        try:
            ca_pub_key = self.ca_cert.public_key()
            ca_pub_key.verify(cert.signature, cert.tbs_certificate_bytes)
        except InvalidSignature:
            return False, "", "", "Invalid CA signature: certificate was forged or tampered with"
        except Exception as exc:
            return False, "", "", f"Signature verification error: {exc}"

        # 3. Validity period check
        at_time = check_time or datetime.datetime.now(datetime.timezone.utc)
        if at_time < cert.not_valid_before_utc:
            return (
                False,
                "",
                "",
                f"Certificate not yet valid (valid from {cert.not_valid_before_utc.isoformat()})",
            )
        if at_time > cert.not_valid_after_utc:
            return (
                False,
                "",
                "",
                f"Certificate has expired (expired at {cert.not_valid_after_utc.isoformat()})",
            )

        # 4. Revocation check
        if self.is_revoked(cert.serial_number):
            return False, "", "", f"Certificate serial {cert.serial_number} has been revoked"

        # 5. Extract Subject Common Name
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not cns:
            return False, "", "", "Certificate has no Common Name attribute"
        subject_cn = str(cns[0].value)

        # 6. Extract raw public key in base64
        pub_key_b64 = public_key_to_b64(cert.public_key())

        # 7. Match identity if expected
        if expected_username is not None and subject_cn != expected_username:
            return (
                False,
                subject_cn,
                pub_key_b64,
                f"Identity mismatch: certificate is for '{subject_cn}', but expected '{expected_username}'",
            )

        return True, subject_cn, pub_key_b64, "Certificate verified successfully"


def initialize_default_environment(certs_dir: str = DEFAULT_CERTS_DIR) -> CertificateAuthority:
    """Create a Root CA and default certificates for 'alice' and 'bob'.

    Safe to run repeatedly: preserves existing root and keys if already present.
    """
    os.makedirs(certs_dir, exist_ok=True)
    ca_cert_path = os.path.join(certs_dir, "ca.pem")

    if os.path.exists(ca_cert_path):
        ca = CertificateAuthority.load_from_dir(certs_dir)
    else:
        ca = CertificateAuthority.create_root()
        ca.save_to_dir(certs_dir)
        print(f"[CA] Generated new Root CA certificate in {certs_dir}/ca.pem")

    # Ensure alice and bob exist
    for user in ("alice", "bob"):
        user_cert_path = os.path.join(certs_dir, f"{user}.pem")
        user_key_path = os.path.join(certs_dir, f"{user}_key.pem")

        if not (os.path.exists(user_cert_path) and os.path.exists(user_key_path)):
            user_key = ed25519.Ed25519PrivateKey.generate()
            user_cert = ca.issue_certificate(user, user_key.public_key())

            with open(user_cert_path, "w", encoding="ascii") as f:
                f.write(cert_to_pem(user_cert))
            with open(user_key_path, "w", encoding="ascii") as f:
                f.write(private_key_to_pem(user_key))
            print(f"[CA] Issued certificate and key for '{user}' in {certs_dir}/")

    return ca


def main() -> None:
    parser = argparse.ArgumentParser(description="Certificate Authority management tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = subparsers.add_parser("init", help="Initialize Root CA and default certs")
    p_init.add_argument("--dir", default=DEFAULT_CERTS_DIR, help="Certs directory")

    # issue
    p_issue = subparsers.add_parser("issue", help="Issue certificate for a username")
    p_issue.add_argument("username", help="Username / Common Name")
    p_issue.add_argument("--dir", default=DEFAULT_CERTS_DIR, help="Certs directory")
    p_issue.add_argument("--days", type=int, default=DEFAULT_VALIDITY_DAYS, help="Validity period")

    # verify
    p_verify = subparsers.add_parser("verify", help="Verify certificate against Root CA")
    p_verify.add_argument("cert_path", help="Path to certificate PEM file")
    p_verify.add_argument("--username", help="Expected username")
    p_verify.add_argument("--dir", default=DEFAULT_CERTS_DIR, help="Certs directory")

    # revoke
    p_revoke = subparsers.add_parser("revoke", help="Revoke certificate by serial number")
    p_revoke.add_argument("serial", type=int, help="Certificate serial number")
    p_revoke.add_argument("--dir", default=DEFAULT_CERTS_DIR, help="Certs directory")

    args = parser.parse_args()

    if args.command == "init":
        initialize_default_environment(args.dir)
        print("Initialization complete.")
    elif args.command == "issue":
        ca = CertificateAuthority.load_from_dir(args.dir)
        user_key = ed25519.Ed25519PrivateKey.generate()
        cert = ca.issue_certificate(args.username, user_key.public_key(), validity_days=args.days)
        cert_path = os.path.join(args.dir, f"{args.username}.pem")
        key_path = os.path.join(args.dir, f"{args.username}_key.pem")
        with open(cert_path, "w", encoding="ascii") as f:
            f.write(cert_to_pem(cert))
        with open(key_path, "w", encoding="ascii") as f:
            f.write(private_key_to_pem(user_key))
        print(f"Issued certificate for {args.username}: {cert_path}")
    elif args.command == "verify":
        ca = CertificateAuthority.load_from_dir(args.dir)
        with open(args.cert_path, "r", encoding="ascii") as f:
            cert_pem = f.read()
        valid, cn, pub_key, reason = ca.verify_certificate(cert_pem, expected_username=args.username)
        print(f"Verification result: {'PASS' if valid else 'FAIL'}")
        print(f"Subject CN: {cn}")
        print(f"Public Key (b64): {pub_key}")
        print(f"Details: {reason}")
        sys.exit(0 if valid else 1)
    elif args.command == "revoke":
        ca = CertificateAuthority.load_from_dir(args.dir)
        ca.revoke_certificate(args.serial)
        ca.save_to_dir(args.dir)
        print(f"Revoked serial: {args.serial}")


if __name__ == "__main__":
    main()
