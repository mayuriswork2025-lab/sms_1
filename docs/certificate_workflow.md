# Certificate Authority & Trust Chain Workflow

**BACSE203 Computer Networks — Project 12**  
*Milestone 47: Months 3–4 — CA Workflow, Certificate Validation, and Trust Chain*

---

## 1. Motivation and Problem Statement

In **Phase 2**, Alice and Bob exchanged Diffie-Hellman public values ($A = g^a \pmod p$, $B = g^b \pmod p$) to derive a shared symmetric session key. However, Diffie-Hellman alone has no identity verification: an active attacker in the middle can intercept $A$ and $B$, substitute their own values, and establish two independent sessions.

In **Phase 3**, digital signatures were introduced using Ed25519. Senders signed their DH public values and chat messages. However, during the handshake, the sender's public signing key was transmitted directly on the wire without prior trust (*Trust On First Use* / TOFU). An attacker in the middle could substitute both the DH public value *and* the public signing key, re-sign the payload, and completely bypass signature authentication.

**Phase 4 solves this vulnerability by introducing a Public Key Infrastructure (PKI) with a Certificate Authority (CA).** The CA functions as a trusted third party that cryptographically binds a client's identity (username) to their long-lived Ed25519 public signing key using an X.509 certificate.

---

## 2. Architecture and Trust Model

```
                    +------------------------------------+
                    |      BACSE203 Root CA              |
                    |  - Root Private Key (Offline/Safe) |
                    |  - Root Certificate (ca.pem)       |
                    +-----------------+------------------+
                                      |
                        Issues & signs identity certs
                                      |
            +-------------------------+-------------------------+
            |                                                   |
            v                                                   v
  +--------------------+                             +--------------------+
  |   Alice's Cert     |                             |    Bob's Cert      |
  | CN = alice         |                             | CN = bob           |
  | PubKey = K_alice   |                             | PubKey = K_bob     |
  | Signed by Root CA  |                             | Signed by Root CA  |
  +---------+----------+                             +----------+---------+
            |                                                   |
            |            Signed DH Handshake + Cert             |
            +---------------------------------------------------+
                       (Relayed through untrusted Server)
```

### Trust Boundary
1. **Root of Trust:** The Root CA's public key (in `certs/ca.pem`) is pre-installed or distributed out-of-band to all clients.
2. **Untrusted Server:** The relay server routes traffic between clients but is never trusted with private keys or session keys.
3. **Clients:** Each client trusts the Root CA. A peer's public signing key is trusted **only if** presented within a valid certificate signed by the Root CA matching the peer's claimed identity.

---

## 3. Certificate Structure

Certificates are standard RFC 5280 **X.509 v3** certificates encoded in PEM format:

| Field | Attribute / Value | Description |
|---|---|---|
| **Version** | v3 | Standard X.509 format |
| **Serial Number** | Random 128-bit integer | Uniquely identifies the certificate |
| **Issuer** | `CN=BACSE203 Root CA` | The entity that signed this certificate |
| **Subject** | `CN=<username>` (e.g. `alice`, `bob`) | The identity bound to this key |
| **Public Key Algorithm** | Ed25519 (OID `1.3.101.112`) | Modern Edwards-curve 256-bit signing key |
| **Subject Public Key** | 32 raw bytes (Base64 encoded) | Client's public signing key |
| **Validity Period** | `Not Before` / `Not After` | Active validity window (default: 90 days) |
| **Basic Constraints** | `CA=False` (for clients) / `CA=True` (for root) | Distinguishes end-entity certs from CAs |
| **Signature** | Ed25519 signature by Root CA | Cryptographic proof of binding |

---

## 4. Complete Certificate Lifecycle

### 4.1 Root CA Initialization
The Root CA generates its own Ed25519 key pair and self-signed certificate:
```bash
python src/ca.py init --dir certs
```
Output files:
- `certs/ca.pem`: Public Root CA certificate distributed to all clients.
- `certs/ca_key.pem`: Secret CA private key used exclusively for signing client certificates.

### 4.2 Certificate Issuance
When a client registers, the CA generates (or receives via CSR) the client's public key, signs an X.509 certificate, and saves credentials:
```bash
python src/ca.py issue alice --dir certs --days 90
python src/ca.py issue bob --dir certs --days 90
```
Output files:
- `certs/alice.pem`: Alice's X.509 identity certificate.
- `certs/alice_key.pem`: Alice's private key (kept secret by Alice).

### 4.3 Revocation (CRL)
If a private key is compromised, the certificate can be revoked:
```bash
python src/ca.py revoke <serial_number> --dir certs
```
Revoked serial numbers are logged in `certs/crl.txt` and rejected during verification.

---

## 5. Certificate Verification Algorithm

When a client receives a `dh_public` message from peer `sender`:

```
                       Incoming dh_public Message
                                   |
                +------------------v------------------+
                | 1. Is 'certificate' present in      |── NO ──▶ REJECT: Missing certificate
                |    message payload?                 |
                +------------------+------------------+
                                  YES
                                   |
                +------------------v------------------+
                | 2. Does Root CA signature verify    |── NO ──▶ REJECT: Untrusted issuer /
                |    over certificate fields?         |                  forged signature
                +------------------+------------------+
                                  YES
                                   |
                +------------------v------------------+
                | 3. Is current UTC time within       |── NO ──▶ REJECT: Certificate expired
                |    not_valid_before .. after?       |                  or not yet valid
                +------------------+------------------+
                                  YES
                                   |
                +------------------v------------------+
                | 4. Is certificate serial number     |── YES ─▶ REJECT: Certificate revoked
                |    on Certificate Revocation List?  |
                +------------------+------------------+
                                   NO
                                   |
                +------------------v------------------+
                | 5. Does Subject Common Name match   |── NO ──▶ REJECT: Identity mismatch
                |    the claimed sender username?     |
                +------------------+------------------+
                                  YES
                                   |
                +------------------v------------------+
                | 6. Does Subject Public Key match    |── NO ──▶ REJECT: Signing key
                |    the payload's 'signing_key'?     |                  substitution
                +------------------+------------------+
                                  YES
                                   |
                +------------------v------------------+
                | 7. Does payload Ed25519 signature   |── NO ──▶ REJECT: Tampered DH key /
                |    verify under that public key?    |                  invalid signature
                +------------------+------------------+
                                  YES
                                   |
                     ACCEPT: Derive Shared Secret
```

---

## 6. Wire Protocol Integration

In `src/message_format.py`, the `dh_public` frame carries the certificate:

```json
{
  "type": "dh_public",
  "sender": "alice",
  "target": "bob",
  "public_key": "1756060446855...",
  "signing_key": "2CXFMv3RXqKmMd9KBiXw4DVXkh6Vr98nD9QcsZHulSA=",
  "certificate": "-----BEGIN CERTIFICATE-----\nMIH4MIGroAMCAQICFBS5cM...\n-----END CERTIFICATE-----\n",
  "signature": "Vv8F1LzM4s47UoV..."
}
```

The payload signature covers all fields including `"certificate"`:
$$\text{Signature} = \text{Sign}_{K_{\text{alice\_priv}}}(\text{canonical}(\text{type, sender, target, public\_key, signing\_key, certificate}))$$

This binds the ephemeral Diffie-Hellman public key directly to the verified certificate.

---

## 7. Security Guarantees & Attack Resistance

| Attack Vector | Vulnerable in Phase 3? | Defended in Phase 4? | Mechanism |
|---|---|---|---|
| **Eavesdropping on traffic** | Defended | Defended | AES-256-GCM session key derived from DH |
| **Ciphertext tampering** | Defended | Defended | AES-GCM Auth Tag + Ed25519 message signatures |
| **DH key substitution (pure DH)** | Vulnerable | Defended | Sender signs DH value with identity key |
| **Rogue signing key substitution** | **Vulnerable** | **Defended** | CA checks reject keys not signed by Root CA |
| **Impersonation with rogue cert** | **Vulnerable** | **Defended** | Signature verification against Root CA fails |
| **Identity spoofing with valid cert** | **Vulnerable** | **Defended** | Subject Common Name checked against claimed sender |
| **Cert replay with swapped DH key** | **Vulnerable** | **Defended** | Public key in cert checked against message signing key |
| **Expired / revoked cert usage** | **Vulnerable** | **Defended** | Validity timestamps & CRL checks |

---

## 8. Verification and Testing

Run the CA and trust chain test suite:
```bash
python -m unittest tests/test_ca_and_trust.py -v
```

All 11 tests assert that valid certificates succeed, while expired, revoked, mismatched, untrusted, or tampered certificates fail with immediate connection drop.
