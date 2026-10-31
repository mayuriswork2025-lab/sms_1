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

### Scenario 6: Replay Attack (blocked by signed sequence numbers)
- **Adversary Action:** Mallory captures a valid, signed encrypted frame from Alice to Bob (`"Transfer approved"`) and re-injects it later.
- **Defense:** Each chat frame carries a per-session sequence number `seq` inside the signed fields. Bob rejects any `seq` he has already accepted: `Rejected message from alice: replayed message (seq 1, already accepted up to 1)`.
- **Bypass attempt:** Changing `seq` to a new value invalidates Alice's signature, so the edited frame is rejected too.
- **Live test:** `python attacks/mitm_proxy.py --mode replay` resends every chat frame 2 seconds after the original. Bob accepts the original and rejects the copy.

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
| **Message Replay** | Re-execute prior message | Vulnerable | Vulnerable | **PREVENTED** (signed sequence numbers) |

---

## 5. Live MITM Test with Wireshark Captures

The scenarios above were first checked in an automated, in-process simulation (`tests/mitm_test.py`). That simulation uses mock sockets, so it is not network evidence. The results in this section come from a **live attack over real TCP connections**, with one team member operating the attacker and the traffic recorded in Wireshark.

### 5.1 Setup

```text
alice/bob --> 127.0.0.1:9000 [attacks/mitm_proxy.py] --> 127.0.0.1:9001 [src/server.py]
```

- **Attacker:** `attacks/mitm_proxy.py` in `swap` mode. Mallory replaces each DH public value with her own, re-signs it with her own Ed25519 key, and forwards the victim's real certificate unchanged.
- **Capture:** Wireshark on the Npcap loopback adapter, filter `tcp.port == 9000 || tcp.port == 9001`.
- **Operated by:** _<team member name>_

### 5.2 Run A: passive eavesdropping (`--mode watch`)

Mallory forwards traffic unchanged. Every chat frame carries only base64 ciphertext.

- Capture file: `captures/01-passive.pcapng`
- Screenshot: _<insert docs/images/01-passive-wireshark.png>_

### 5.3 Run B: DH key substitution without certificates (`--no-cert`) — attack succeeds

Both clients skip certificate checks, so they accept any signing key that arrives with a DH value.

Observed:
- Mallory's terminal: `SWAPPED alice's DH value and signing key with Mallory's own`, then `*** READ alice -> bob: 'My bank PIN is 1234' ***`
- Bob's terminal: the message is shown with `(signature verified)`. Bob cannot tell he is talking to Mallory.
- Wireshark: Alice's `public_key` on the port 9000 stream (Alice → Mallory) differs from the `public_key` on the port 9001 stream (Mallory → server). The substitution is visible on the wire.

- Capture file: `captures/02-mitm-success.pcapng`
- Screenshots: _<insert docs/images/02-mallory-reads.png>_, _<insert docs/images/02-wireshark-port9000.png>_, _<insert docs/images/02-wireshark-port9001.png>_

### 5.4 Run C: DH key substitution with certificates — attack blocked

Same attack, with certificate verification on (the default).

Observed:
- Bob's terminal: `[security] Rejected DH public value from alice: signing key does not match certificate public key`
- Alice's terminal: no session is created; `/msg bob ...` returns `No session with bob yet`.
- Mallory's terminal: no `READ` line. She obtains no plaintext.

Why it fails: Mallory can forward Alice's genuine certificate, but that certificate binds the name "alice" to Alice's public key. Mallory cannot produce a signature with Alice's private key, and if she substitutes her own signing key, it no longer matches the certificate. If she forges a certificate instead, it fails the CA signature check.

- Capture file: `captures/03-mitm-blocked.pcapng`
- Screenshots: _<insert docs/images/03-bob-rejects.png>_, _<insert docs/images/03-wireshark.png>_

### 5.5 Result

| Run | Certificates | Attack | Outcome |
|---|---|---|---|
| A | on | Passive sniffing | Only ciphertext visible |
| B | off (`--no-cert`) | DH key substitution | **Succeeds**: Mallory reads every message |
| C | on | DH key substitution | **Blocked**: handshake rejected, no session |
| D | on | Replay a captured chat frame (`--mode replay`) | **Blocked**: copy rejected as a replay |

---

## 6. How to Reproduce

Live attack (four terminals, from the project root):
```bash
python src/server.py --port 9001
python attacks/mitm_proxy.py --mode swap      # or --mode watch / --mode replay
python src/client.py --username bob [--no-cert]
python src/client.py --username alice [--no-cert]
```
In Alice's terminal: `/dh bob`, then `/msg bob <text>`.

Automated simulation of all scenarios:
```bash
python tests/mitm_test.py
python -m unittest tests/mitm_test.py -v
```
