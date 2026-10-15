# Project 12 Executive Summary: Secure Messaging System (CN_SMS)

**BACSE203 Computer Networks | Course Outcome CO5 | Module 5**

---

## 1. Project Overview

The **Secure Messaging System with Full Key Management (CN_SMS)** is an end-to-end encrypted and authenticated communication platform designed to protect message confidentiality, integrity, and authenticity across untrusted network relays.

Built entirely using Python and standard cryptographic primitives, the system successfully addresses all 4 milestones across 6 development phases:

```
+-----------------------------------------------------------------------------------------+
|                                    MILESTONES SUMMARY                                   |
+-----------------------------------------------------------------------------------------+
| Milestone 45 (Months 1–2): Plaintext framing protocol & TCP client-server relay.       |
| Milestone 46 (Months 2–3): RFC 3526 DH key exchange, AES-256-GCM & Ed25519 signatures. |
| Milestone 47 (Months 3–4): X.509 Certificate Authority, trust chain & revocation.      |
| Milestone 48 (Months 5–6): Adversarial MITM testing, STRIDE threat model, final report. |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Key Components & Implementation

| Component | Module | Standard / Algorithm | Role in System |
|---|---|---|---|
| **Key Exchange** | `src/dh.py` | RFC 3526 MODP Group 14 (2048-bit prime, $g=2$) | Derives 256-bit ephemeral shared secret without direct transmission. |
| **Symmetric Cipher** | `src/crypto.py` | AES-256-GCM + 12-byte random nonce | Encrypts chat payloads with authenticated associated data (AAD). |
| **Digital Signatures** | `src/signing.py` | Ed25519 (Edwards-curve RFC 8032) | Signs DH public values and chat messages to guarantee origin authenticity. |
| **Certificate Authority** | `src/ca.py` | X.509 v3 (RFC 5280) + CRL Revocation | Cryptographically binds usernames to Ed25519 public keys, defeating MITM. |
| **Network Relay** | `src/server.py` | TCP Sockets + Frame Buffering | Unicast relay forwarding ciphertext without accessing plaintext. |
| **Client Application** | `src/client.py` | Multi-threaded Socket Engine | Manages handshakes, certificate verification, and interactive encrypted chat. |
| **Adversarial Testing** | `tests/mitm_test.py` | Automated Dolev-Yao Attack Harness | Tests eavesdropping, key substitution, cert forgery, and tampering. |
| **Traffic Inspection** | `logs/traffic_capture.log` | Wireshark-compatible Frame Log | Records real-time packet transmissions and adversary interception events. |

---

## 3. Adversarial Testing Summary

```text
==========================================================================================
Attack Scenario                  | Attacker Goal                | Defense Result
------------------------------------------------------------------------------------------
1. Passive Eavesdropping         | Sniff chat plaintext         | BLOCKED (AES-256-GCM)
2. Unauthenticated DH (Phase 2)  | Split session & read text    | SUCCEEDED (Proves Phase 2 flaw)
3. Signed DH without CA (Phase 3)| Swap signing key in flight   | SUCCEEDED (Proves Phase 3 flaw)
4. Rogue CA Certificate (Phase 4)| Inject self-signed fake cert | BLOCKED (Untrusted Issuer)
5. Identity Mismatch (Phase 4)   | Mallory cert claiming Alice  | BLOCKED (CN != claimed sender)
6. Cert Replay with Key Swap     | Replay cert with rogue key   | BLOCKED (Public key mismatch)
7. Certificate Tampering         | Alter cert attributes        | BLOCKED (CA signature invalid)
8. Ciphertext Tampering          | Flip bits in transmission    | BLOCKED (Ed25519 sig + GCM tag)
9. Message Replay Attack         | Resend captured frame        | DOCUMENTED RESIDUAL LIMITATION
==========================================================================================
```

---

## 4. Key Takeaways & Protection Boundary

1. **Why DH alone fails:** Diffie-Hellman provides confidentiality against passive listeners, but cannot distinguish between a peer and an active man-in-the-middle.
2. **Why Signatures alone fail:** Digital signatures prove possession of *a* private key, but without identity binding, an attacker can substitute their own key during the handshake.
3. **Why the CA succeeds:** The Certificate Authority establishes an out-of-band **Root of Trust**. A peer only accepts public keys signed by the Root CA matching the claimed Common Name.
4. **Honest Protection Boundary:** The system protects content, integrity, and authenticity, but acknowledges residual risks: traffic metadata is visible to the relay, replayed messages without sequence counters will verify within the same session, and compromised client endpoints expose stored private keys.

---

## 5. Verification Commands

```bash
# Initialize CA and default certificates
python src/ca.py init

# Run all 36 unit and integration tests
python -m unittest discover tests -p "*test*.py" -v

# Run the adversarial MITM test simulation
python tests/mitm_test.py
```
