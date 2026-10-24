# Final Project Report: Secure Messaging System with Full Key Management

**Course:** BACSE203 Computer Networks  
**Project Reference:** Project 12 — Group A (Protocol & Systems Builds)  
**Difficulty:** Intermediate | **Course Outcome Addressed:** CO5 | **Syllabus Coverage:** Module 5  

---

## 1. Project Abstract & Objective

Modern computer networks require end-to-end security architectures capable of guaranteeing confidentiality, message integrity, and identity authenticity over untrusted transport infrastructure. 

The objective of **Project 12** is to build a complete, production-grade secure messaging system in Python that implements the entire cryptographic lifecycle:
1. **Key Negotiation:** Ephemeral Diffie-Hellman key exchange over RFC 3526 2048-bit MODP Group 14.
2. **Session Encryption:** High-throughput AES-256-GCM authenticated symmetric encryption with random nonces and Associated Authenticated Data (AAD).
3. **Message Authentication:** Asymmetric Ed25519 digital signatures providing non-repudiation and integrity verification.
4. **Identity Binding & Trust Chain:** A custom Certificate Authority (CA) issuing and validating standard X.509 v3 certificates to defeat public key substitution.
5. **Adversarial Testing:** Documented automated testing against an active Man-in-the-Middle (MITM) adversary ("Mallory") demonstrating attack success against weak phases and attack prevention under the full CA trust model.
6. **Threat Model & Security Boundary:** A rigorous STRIDE analysis delineating protected assets from residual operational risks.

---

## 2. Milestone Progression (Course Breakdown)

| Milestone | Target Months | Scope & Deliverables | Status |
|---|---|---|---|
| **#45** | Months 1–2 | Plaintext messaging skeleton; framing protocol (`\n`-delimited JSON); TCP server/client relay. | **COMPLETED** |
| **#46** | Months 2–3 | Diffie-Hellman (RFC 3526 Group 14); session key derivation (SHA-256); AES-256-GCM encryption; Ed25519 digital signatures. | **COMPLETED** |
| **#47** | Months 3–4 | Certificate Authority workflow (`src/ca.py`); X.509 v3 certificate issuance; 6-step trust chain validation; CRL revocation tracking. | **COMPLETED** |
| **#48** | Months 5–6 | Live MITM proxy (`attacks/mitm_proxy.py`) with Wireshark captures (`captures/`); automated adversarial test suite (`tests/mitm_test.py`); STRIDE threat model; final report and viva preparation. | **COMPLETED** |

---

## 3. System Architecture & Cryptographic Workflow

```
               PHASE 4: CERTIFICATE ISSUANCE & TRUST ESTABLISHMENT
               ===================================================
               +-------------------------------------------------+
               |                BACSE203 Root CA                 |
               |      Root Certificate (certs/ca.pem)            |
               |      Private Key (certs/ca_key.pem)             |
               +-----------------------+-------------------------+
                                       |
                 Issues X.509 Certs    |    Issues X.509 Certs
                 CN=alice, K_alice     |    CN=bob, K_bob
                                       v
               +-----------------------+-------------------------+
               |                                                 |
               v                                                 v
         +------------+                                   +------------+
         |   Alice    |                                   |    Bob     |
         +-----+------+                                   +------+-----+
               |                                                 |
               | PHASE 2 & 4: CERTIFIED DIFFIE-HELLMAN HANDSHAKE |
               | =============================================== |
               | Alice sends:                                    |
               |   - DH Public Value: A = g^a mod p              |
               |   - Ed25519 Signing Key: K_alice                |
               |   - CA-Signed X.509 Certificate                 |
               |   - Signature over (A, K_alice, Cert)           |
               | ----------------------------------------------> |
               |                                                 | Bob verifies:
               |                                                 | 1. Root CA signature on cert
               |                                                 | 2. Subject CN == "alice"
               |                                                 | 3. Cert PubKey == K_alice
               |                                                 | 4. Message signature valid
               |                                                 | Bob derives: s = A^b mod p
               |                                                 |
               | Bob replies:                                    |
               |   - DH Public Value: B = g^b mod p              |
               |   - Ed25519 Signing Key: K_bob                  |
               |   - CA-Signed X.509 Certificate                 |
               |   - Signature over (B, K_bob, Cert)             |
               | <---------------------------------------------- |
               |                                                 |
               | Alice verifies Bob's cert & signature           |
               | Alice derives: s = B^a mod p                    |
               |                                                 |
               | Both compute: SessionKey = SHA-256(s)           |
               |                                                 |
               | PHASE 3: AES-256-GCM ENCRYPTED CHAT             |
               | ===================================             |
               | Ciphertext, Nonce = AES_GCM_Encrypt(text, key)  |
               | Signature = Ed25519_Sign(Ciphertext, Nonce)     |
               |                                                 |
               | ── {nonce, ciphertext, signature} ────────────> |
               |                                                 | Verifies Signature
               |                                                 | Decrypts AES-GCM Tag
               v                                                 v
```

---

## 4. Cryptographic Primitives Specification

### 4.1 Diffie-Hellman Key Exchange (`src/dh.py`)
- **Group:** RFC 3526 MODP Group 14 (2048-bit prime $p$, generator $g=2$).
- **Private Exponent:** Chosen randomly via `secrets.randbelow(p - 3) + 2` with 2048 bits of entropy.
- **Shared Secret Computation:**
  $$s = (\text{peer\_public\_key})^{\text{private\_key}} \pmod p$$
- **Session Key Derivation:**
  $$\text{SessionKey} = \text{SHA-256}(\text{bytes}(s))$$
  Produces a uniformly distributed 32-byte (256-bit) symmetric key.

### 4.2 Symmetric Session Cipher (`src/crypto.py`)
- **Algorithm:** AES-256 in Galois/Counter Mode (GCM).
- **Nonce:** 12 random bytes (`os.urandom(12)`) per frame.
- **Authentication Tag:** 16 bytes appended to ciphertext.
- **Associated Authenticated Data (AAD):** `chat|<sender>|<target>`. Binds ciphertext cryptographically to sender and intended recipient, preventing frame re-targeting by the relay.

### 4.3 Digital Signatures (`src/signing.py`)
- **Algorithm:** Ed25519 (Edwards-curve Digital Signature Algorithm, RFC 8032).
- **Properties:** High performance, constant-time execution, immune to side-channel timing attacks, 128-bit security level.
- **Canonical Serialization:** JSON serialized deterministically (`sort_keys=True, separators=(',', ':')`) prior to hashing and signing.

### 4.4 Certificate Authority & Trust Chain (`src/ca.py`)
- **Format:** Standard RFC 5280 X.509 v3 certificates.
- **Signer:** Root Certificate Authority (`CN=BACSE203 Root CA`).
- **Subject Binding:** Directly binds the client's username (`CN=<username>`) to their 32-byte Ed25519 public key.
- **Revocation:** Dynamic serial tracking with persistent CRL (`certs/crl.txt`).

---

## 5. Adversarial MITM Testing Results

An automated adversarial evaluation was conducted using `tests/mitm_test.py` against an active attacker ("Mallory"):

```text
==========================================================================================
 ADVERSARIAL TESTING SUMMARY & PROTECTION BOUNDARY MATRIX
==========================================================================================
Attack Scenario                  | Adversary Action             | Defense Mechanism | Result    
------------------------------------------------------------------------------------------
Passive Eavesdropping            | Sniff ciphertext off wire    | Decryption failed | BLOCKED   
Unauthenticated DH (Phase 2)     | Intercept DH values & split  | Plaintext read    | SUCCEEDED 
Signed DH without CA (Phase 3)   | Substitute DH key + signing  | Bob accepted rogue| SUCCEEDED 
Active MITM (Phase 4)            | Inject cert from rogue CA    | Rejected: Untrusted| BLOCKED   
Active MITM (Phase 4)            | Mallory cert claiming Alice  | Rejected: Identity| BLOCKED   
Active MITM (Phase 4)            | Replay Alice cert with Mallory| Binding check fail| BLOCKED   
Active MITM (Phase 4)            | Modify bytes in certificate  | Signature invalid | BLOCKED   
Ciphertext Tampering             | Flip 1 bit in ciphertext     | Rejected by Tag   | BLOCKED   
Replay Attack                    | Resend captured valid frame  | Accepted (Doc)    | DOCUMENTED
==========================================================================================
```

### Key Takeaways:
1. **Pure DH is completely broken by active MITM:** Mallory can split the session into two independent keys, intercepting and tampering with all communications transparently.
2. **Signatures without CA fail during handshake:** If the receiver learns the public key directly over the wire, Mallory can swap both the public value and the public key, re-signing the message.
3. **Root CA validation completely defeats MITM:** Mallory cannot forge a Root CA signature without the CA's private key. The identity and key binding checks reject all substitution and tampering attempts.

---

## 6. Threat Model & Protection Boundary

### What the System Protects Against:
- **Eavesdropping:** AES-256-GCM ensures that passive listeners and the untrusted relay see only randomized ciphertext.
- **Message Tampering:** Any alteration to ciphertext, nonces, or headers triggers an `InvalidSignature` or `InvalidTag` exception and packet rejection.
- **Identity Spoofing & Impersonation:** CA signature verification ensures only legitimate certificate holders can initiate sessions.
- **Relay Re-targeting:** Associated Authenticated Data (AAD) prevents a rogue relay from delivering Alice's message for Bob to Carol.

### Documented Residual Risks:
1. **Replay Attacks:** The current wire format does not enforce sliding-window sequence numbers or strict UTC timestamps. Replaying a captured frame within the same session will decrypt again.
2. **Endpoint Compromise:** If an attacker gains root access to the client device, they can read private keys from process memory or unencrypted PEM files on disk.
3. **Metadata Leakage:** The relay server must observe `sender` and `target` to route packets. Traffic analysis can reveal communication frequency and contact networks.

---

## 7. Viva Voce Preparation Guide (Questions & Answers)

### Q1: Why did you choose Diffie-Hellman instead of simply encrypting the session key with RSA?
**Answer:**  
Diffie-Hellman provides **Perfect Forward Secrecy (PFS)**. Each handshake generates ephemeral private exponents $a$ and $b$ that exist only in volatile RAM and are destroyed after key derivation. If a client's long-lived identity key is compromised in the future, past recorded sessions cannot be decrypted. With pure RSA key transport, compromising the receiver's private RSA key allows an attacker to decrypt all historical traffic.

### Q2: Why is AES-256-GCM preferred over AES-256-CBC?
**Answer:**  
AES-CBC requires PKCS#7 padding and a separate HMAC for integrity (Encrypt-then-MAC). CBC is notoriously susceptible to padding oracle attacks (e.g., POODLE). In contrast, AES-GCM is an authenticated encryption mode (AEAD) based on CTR mode with a Galois Field multiplier (GHASH). It provides simultaneous confidentiality and cryptographic integrity verification without padding, and is computationally efficient.

### Q3: Why is a random 12-byte nonce required for every message in AES-GCM?
**Answer:**  
In GCM mode, reusing the same nonce with the same key destroys the authenticity guarantees. Specifically, if two messages are encrypted with the same key and nonce, an attacker can XOR the ciphertexts to eliminate the keystream ($C_1 \oplus C_2 = P_1 \oplus P_2$) and recover the GHASH authentication key, allowing them to forge future ciphertexts.

### Q4: Why are digital signatures still needed if AES-GCM already has an authentication tag?
**Answer:**  
AES-GCM's authentication tag is symmetric: it only proves that the ciphertext was created by *someone who possesses the shared session key*. If an attacker succeeded in a MITM handshake, the attacker also holds the session key. An asymmetric digital signature (Ed25519) proves that the message originated specifically from the holder of the private identity key, providing **non-repudiation** and **origin authentication**.

### Q5: How does the Certificate Authority prevent Man-in-the-Middle attacks during the DH exchange?
**Answer:**  
During the DH exchange, Alice transmits her public value $A$ along with an X.509 certificate signed by the Root CA. Bob checks the Root CA's digital signature on Alice's certificate, verifies that the Subject Common Name is `"alice"`, and verifies that the public key inside the certificate matches the key used to sign the DH value. An attacker cannot generate a valid certificate for `"alice"` because the attacker does not possess the Root CA's private signing key.

### Q6: What happens if an attacker replays Alice's certificate but uses their own DH key?
**Answer:**  
The attack fails at Step 6 of verification. The attacker would have to sign the DH message with their own private key, meaning the message's `signing_key` would belong to the attacker. Bob compares the public key extracted from Alice's certificate with the message's `signing_key`. Because they do not match, Bob rejects the handshake with `signing key does not match certificate public key`.

---

## 8. Repository Structure & Verification Instructions

```text
CN_SMS/
├── docs/
│   ├── REQUIREMENTS.md           # Course syllabus specifications
│   ├── plan.md                   # Six-phase implementation roadmap
│   ├── protocol.md               # Wire framing & cryptographic specification
│   ├── certificate_workflow.md   # Milestone 47 CA documentation
│   ├── mitm_analysis.md          # Milestone 48 MITM analysis report
│   ├── threat_model.md           # Milestone 48 STRIDE threat model
│   ├── final_report.md           # Comprehensive academic project report
│   └── phases/                   # Modular phase guides (Phase 2 to 6)
├── src/
│   ├── ca.py                     # Certificate Authority & X.509 tools
│   ├── client.py                 # Chat client with CA-validated DH handshake
│   ├── server.py                 # TCP relay server
│   ├── crypto.py                 # AES-256-GCM authenticated encryption
│   ├── dh.py                     # RFC 3526 Group 14 Diffie-Hellman math
│   ├── signing.py                # Ed25519 digital signature identity
│   ├── message_format.py         # Wire protocol serialization
│   └── utils.py                  # Logging helpers
├── certs/
│   ├── ca.pem                    # Root CA public certificate
│   ├── ca_key.pem                # Root CA private key (git-ignored, CA admin only)
│   ├── alice.pem                 # Alice identity certificate
│   ├── alice_key.pem             # Alice private signing key (git-ignored)
│   ├── bob.pem                   # Bob identity certificate
│   ├── bob_key.pem               # Bob private signing key (git-ignored)
│   └── crl.txt                   # Certificate Revocation List
├── attacks/
│   └── mitm_proxy.py             # Live man-in-the-middle proxy (Mallory)
├── captures/                     # Wireshark .pcapng captures of the live MITM runs
└── tests/
    ├── test_encryption_and_signing.py # Phase 3 unit tests
    ├── test_ca_and_trust.py           # Phase 4 CA & trust chain tests
    └── mitm_test.py                   # Phase 5 adversarial test harness
```

### Verification Commands:
```bash
# 1. Initialize CA and certificates
python src/ca.py init

# 2. Run all unit and integration tests (36 tests)
python -m unittest discover -s tests -p "*.py" -v

# 3. Run the live MITM demo (see README: Live MITM demo with Wireshark)
python src/server.py --port 9001
python attacks/mitm_proxy.py --mode swap

# 4. Run the automated adversarial MITM simulation
python tests/mitm_test.py

# 5. Standalone cryptographic primitives checks
python src/dh.py
python src/crypto.py
python src/signing.py
```

---

## 9. Conclusion

The completed **CN_SMS** project fulfills all requirements of BACSE203 Project 12. By progressing systematically through unauthenticated messaging, Diffie-Hellman key exchange, AES-256-GCM encryption, Ed25519 signatures, X.509 Certificate Authority trust chains, and adversarial testing, the project delivers an end-to-end secure messaging platform accompanied by rigorous security documentation and defense verification.
