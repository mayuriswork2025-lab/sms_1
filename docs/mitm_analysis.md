# Adversarial MITM Testing and Analysis Report

**BACSE203 Computer Networks — Project 12**  
*Milestone 48: Months 5–6 — Adversarial Testing & MITM Analysis*

---

## 1. Executive Summary

This report documents the adversarial testing of the Secure Messaging System. The evaluation subjects the communication channel to an active man-in-the-middle (MITM) adversary ("Mallory") who controls the relay infrastructure, intercepts network traffic, substitutes cryptographic parameters, forges certificates, and modifies messages in transit.

The primary objective is to evaluate:
1. Why unauthenticated Diffie-Hellman (**Phase 2**) is vulnerable to split-session key substitution.
2. Why digital signatures without identity binding (**Phase 3**) remain vulnerable to key substitution during the handshake.
3. How the Certificate Authority and trust chain (**Phase 4**) effectively detect and neutralize all active impersonation and tampering vectors.
4. The exact protection boundaries and residual risks (such as replay attacks and endpoint compromise).

---

## 2. Adversary Threat Model

We assume the standard **Dolev-Yao** network adversary model:
- The adversary controls the network channel (can sniff, drop, inject, reorder, replay, and alter packets).
- The adversary can run their own server relay or compromise the intermediate TCP relay.
- Cryptographic primitives (RFC 3526 DH Group 14, AES-256-GCM, Ed25519, SHA-256) are computationally secure. The adversary cannot invert hashes or compute discrete logarithms.
- The adversary **does not** possess the Root CA private key or either peer's private keys.

---

## 3. Test Scenarios and Technical Analysis

### Scenario 1: Passive Eavesdropping on Wire Traffic
- **Adversary Action:** Mallory sniffs network packets exchanged between Alice and Bob over port 9000.
- **Wire Capture:**
  ```text
  [alice:9001 -> server:9000] [chat] {
    "type": "chat",
    "sender": "alice",
    "target": "bob",
    "nonce": "OD6TU1lGxbZZYVLX",
    "ciphertext": "e57jkh5uQVduOa99rgP0bNL8ZmV2ultteyj5On+SqF5UqmA5D62i0jYRsIksQbTTcyTPFyYUylfrcg==",
    "signature": "simulated_sig"
  }
  ```
- **Analysis:** The message payload contains no plaintext. The 12-byte random nonce ensures semantic security (the same plaintext encrypted twice produces different ciphertexts). Decryption without the 256-bit symmetric key derived from DH fails with `DecryptionError: ciphertext failed authentication`.
- **Outcome:** **ATTACK PREVENTED (CONFIDENTIALITY PRESERVED)**.

---

### Scenario 2: Unauthenticated Diffie-Hellman MITM (Phase 2 Vulnerability)
- **Adversary Action:** Mallory intercepts Alice's public value $A = g^a \pmod p$ and Bob's public value $B = g^b \pmod p$. Mallory generates two distinct private keys $m_1$ and $m_2$, computes $M_1 = g^{m_1} \pmod p$ and $M_2 = g^{m_2} \pmod p$, and substitutes them:
  - Alice receives $M_1$ (believing it is $B$).
  - Bob receives $M_2$ (believing it is $A$).
- **Mathematical Execution:**
  $$\text{Alice computes: } K_{AM} = M_1^a = g^{m_1 a} \pmod p$$
  $$\text{Mallory computes with Alice: } K_{MA} = A^{m_1} = g^{a m_1} \pmod p \implies K_{AM} = K_{MA}$$
  $$\text{Bob computes: } K_{BM} = M_2^b = g^{m_2 b} \pmod p$$
  $$\text{Mallory computes with Bob: } K_{MB} = B^{m_2} = g^{b m_2} \pmod p \implies K_{BM} = K_{MB}$$
- **Result:** Alice transmits `"Transfer $1,000 to Bob"` encrypted with $K_{AM}$. Mallory intercepts, decrypts the plaintext, alters it to `"Transfer $10,000 to Mallory"`, re-encrypts with $K_{MB}$, and delivers it to Bob. Bob decrypts without error.
- **Outcome:** **ATTACK SUCCEEDED (VULNERABILITY CONFIRMED)**.  
  *Finding: Pure Diffie-Hellman provides confidentiality against passive observers but zero authentication against active adversaries.*

---

### Scenario 3: Signed DH without Certificate Binding (Phase 3 Vulnerability)
- **Adversary Action:** In Phase 3, Alice signs her DH public value with her Ed25519 identity key and sends her public key on the wire. Mallory intercepts the handshake, replaces Alice's DH value $A$ with $M$, replaces Alice's public signing key $K_{\text{alice\_pub}}$ with Mallory's public key $K_{\text{mallory\_pub}}$, and signs the packet with Mallory's private key.
- **Analysis:** Because Bob accepts $K_{\text{mallory\_pub}}$ on first sight without checking a trust anchor (TOFU), the signature check mathematically passes!
- **Outcome:** **ATTACK SUCCEEDED (VULNERABILITY CONFIRMED)**.  
  *Finding: Digital signatures only prove possession of a private key. Without binding that key to a verified identity, MITM during the initial exchange remains trivial.*

---

### Scenario 4: Active MITM against CA & Trust Chain (Phase 4 Defenses)

We subjected Phase 4 to four distinct adversarial vectors:

#### 4a. Rogue / Self-Signed Certificate Injection
- **Action:** Mallory generates her own Root CA ("Mallory Untrusted CA") and issues a certificate for `alice` containing Mallory's public key.
- **Verification:** Bob validates against `certs/ca.pem` (`CN=BACSE203 Root CA`).
- **Result:** The Root CA public key fails to verify the signature on the rogue certificate.
- **Log:** `Rejected DH public value from alice: certificate verification failed (Untrusted issuer)`
- **Outcome:** **ATTACK DETECTED & BLOCKED**.

#### 4b. Genuine Certificate with Identity Mismatch
- **Action:** Mallory registers legitimately with the Root CA as `mallory`. When attacking Alice's session, Mallory presents her genuine, validly signed certificate while claiming `sender: "alice"`.
- **Verification:** Bob extracts Subject Common Name `CN=mallory` and compares it to the claimed sender `"alice"`.
- **Log:** `Rejected DH public value from alice: certificate verification failed (Identity mismatch: certificate is for 'mallory', but expected 'alice')`
- **Outcome:** **ATTACK DETECTED & BLOCKED**.

#### 4c. Certificate Replay with Key Substitution
- **Action:** Mallory intercepts Alice's genuine certificate (`CN=alice`, PubKey = $K_{\text{alice}}$) and forwards it, but replaces the message's `signing_key` field with Mallory's key so she can complete the handshake.
- **Verification:** Bob extracts the public key from Alice's certificate and verifies:
  $$\text{Cert Public Key} == \text{Payload Signing Key}$$
- **Log:** `Rejected DH public value from alice: signing key does not match certificate public key`
- **Outcome:** **ATTACK DETECTED & BLOCKED**.

#### 4d. Certificate Tampering
- **Action:** Mallory attempts to alter the public key inside Alice's certificate DER bytes directly.
- **Verification:** Any modification alters the cryptographic hash of the To-Be-Signed (TBS) certificate bytes.
- **Result:** Root CA signature verification fails with `InvalidSignature`.
- **Outcome:** **ATTACK DETECTED & BLOCKED**.

---

### Scenario 5: In-Transit Tampering of Encrypted Messages
- **Adversary Action:** Mallory intercepts an established session chat message and flips a single bit in the base64 ciphertext or nonce.
- **Verification Sequence:**
  1. Bob verifies Alice's Ed25519 signature over `{type, sender, target, nonce, ciphertext}`. Because the ciphertext changed, signature verification returns `False`.
  2. Even if signature verification were bypassed, AES-GCM's 16-byte Poly1305/GHASH authentication tag check fails during decryption (`InvalidTag`).
- **Result:** The tampered message is discarded immediately. Plaintext is never displayed.
- **Outcome:** **ATTACK DETECTED & BLOCKED**.

---

### Scenario 6: Replay Attack Analysis (Protection Boundary)
- **Adversary Action:** Mallory captures a valid, signed encrypted frame from Alice to Bob (`"Transfer approved"`) and re-injects it onto the network 60 seconds later.
- **Observation:** Bob's client verifies the signature (it was validly signed by Alice) and decrypts the message again with the active session key.
- **Protection Boundary Analysis:** Without explicit monotonically increasing sequence numbers or timestamps inside the authenticated payload, replayed messages cannot be distinguished from newly sent messages within the lifetime of the same session key.
- **Residual Risk:** Documented as an acknowledged residual limitation in `docs/threat_model.md`.

---

## 4. Protection Matrix Summary

| Attack Vector | Attacker Objective | Phase 2 (DH) | Phase 3 (AES + Sig) | Phase 4 (CA + Trust Chain) |
|---|---|---|---|---|
| **Eavesdropping** | Read chat plaintext | Prevented | Prevented | **Prevented** |
| **DH Key Interception** | Establish split sessions | **VULNERABLE** | **VULNERABLE** | **PREVENTED** |
| **Public Key Substitution** | Impersonate peer | **VULNERABLE** | **VULNERABLE** | **PREVENTED** |
| **Rogue CA Injection** | Impersonate via fake cert | N/A | N/A | **PREVENTED** |
| **Identity Mismatch** | Spoof sender username | **VULNERABLE** | **VULNERABLE** | **PREVENTED** |
| **Payload Tampering** | Alter message content | **VULNERABLE** | Prevented | **PREVENTED** |
| **Certificate Tampering** | Modify cert attributes | N/A | N/A | **PREVENTED** |
| **Message Replay** | Re-execute prior message | Vulnerable | Vulnerable | **Documented Limitation** |

---

## 5. Packet Capture Artifact

The captured frame log is generated at:
```text
logs/traffic_capture.log
```
The log documents exact timestamps, port source/destination addresses, frame types, and adversary interception markers.

---

## 6. How to Reproduce

Run the full adversarial testing harness:
```bash
python tests/mitm_test.py
```
Or run as automated unittests:
```bash
python -m unittest tests/mitm_test.py -v
```
