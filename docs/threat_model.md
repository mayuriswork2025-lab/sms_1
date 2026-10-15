# Security Threat Model and Protection Boundary Analysis

**BACSE203 Computer Networks — Project 12**  
*Milestone 48: Months 5–6 — Threat Model and Protection Boundary*

---

## 1. System Overview & Scope

The **Secure Messaging System (CN_SMS)** provides end-to-end encrypted and authenticated peer-to-peer communication relayed through an untrusted central server.

```
+-----------------------------------------------------------------------------------------+
|                                    TRUST BOUNDARY                                       |
|                                                                                         |
|  +--------------------+         +--------------------+         +---------------------+  |
|  |    Alice Client    |         |    Relay Server    |         |     Bob Client      |  |
|  | - Private Key (a)  | <=====> | - Untrusted Router | <=====> | - Private Key (b)   |  |
|  | - Identity Key (K) |         | - Sees Ciphertext  |         | - Identity Key (K)  |  |
|  | - Session Key (s)  |         +--------------------+         | - Session Key (s)   |  |
|  +--------------------+                                        +---------------------+  |
|           ^                                                               ^             |
|           |                 +-----------------------+                     |             |
|           +---------------- |   BACSE203 Root CA    | --------------------+             |
|           (Trust Anchor)    | - Root Key (Offline)  |    (Trust Anchor)                 |
|                             | - Issues X.509 Certs  |                                   |
|                             +-----------------------+                                   |
+-----------------------------------------------------------------------------------------+
```

---

## 2. Protected Assets

| Asset | Description | Sensitivity | Security Objective |
|---|---|---|---|
| **Chat Plaintext** | The actual messages exchanged between users | High | Confidentiality |
| **DH Private Exponents** | The random values $a, b \in [2, p-2]$ | Critical | Confidentiality (Never transmitted) |
| **Derived Session Keys** | 256-bit AES symmetric keys $H(g^{ab} \pmod p)$ | Critical | Confidentiality (Ephemeral, in-memory) |
| **Client Private Keys** | Ed25519 identity signing keys | Critical | Confidentiality & Integrity |
| **Root CA Private Key** | Master private key used to sign certificates | Critical | Confidentiality & Offline Protection |
| **X.509 Certificates** | Public identity bindings (`CN`, Public Key) | Public | Integrity & Authenticity |
| **Relay Routing Tables** | Username-to-socket mapping on the server | Low | Availability & Correctness |

---

## 3. Threat Agents & Attacker Profiles

1. **Passive Network Eavesdropper (Eve):**  
   Observes packets traversing the network (e.g., public Wi-Fi, ISP, compromised routers). Attempts to inspect plaintext and infer communications.
2. **Active Network Adversary / Man-in-the-Middle (Mallory):**  
   Can drop, modify, inject, replay, and re-order packets. Can operate a malicious relay or intercept traffic between clients.
3. **Malicious or Compromised Server Relay:**  
   The chat server itself is assumed curious or untrusted. It routes traffic but attempts to read plaintext or impersonate clients.
4. **Malicious Registered User:**  
   Possesses a legitimate account and CA-signed certificate, but attempts to spoof other users, hijack sessions, or attack peers.
5. **Compromised Endpoint / Host Device:**  
   Malware or physical attacker gaining access to Alice's or Bob's machine.

---

## 4. STRIDE Threat Analysis

| Threat Category | Potential Attack Vector | System Defense Mechanism | Residual Risk / Status |
|---|---|---|---|
| **S - Spoofing** | Attacker claims to be Alice during handshake | X.509 Certificate issued by Root CA + Ed25519 digital signature over DH public value | **Defended.** Impersonation rejected without CA private key. |
| **T - Tampering** | Attacker alters ciphertext or DH public value in flight | AES-256-GCM authentication tag + Ed25519 signatures over canonical JSON | **Defended.** Decryption fails; signature verification fails. |
| **R - Repudiation** | Sender denies having transmitted a specific message | Asymmetric Ed25519 digital signature over chat payload | **Defended.** Only the holder of the sender's private key can produce the signature. |
| **I - Information Disclosure** | Attacker sniffs network traffic or server logs | End-to-end AES-256-GCM encryption with 256-bit ephemeral keys | **Defended.** Server and eavesdroppers only observe pseudorandom ciphertext. |
| **D - Denial of Service** | Flooding server with TCP connections or malformed frames | `socket.settimeout`, `MessageReader` frame delimiter validation | **Partially Defended.** Network flood / SYN floods require OS-level / firewall rate-limiting. |
| **E - Elevation of Privilege** | Client attempts to issue certificates or act as CA | Basic Constraints `CA=False` in client certificates; clients reject non-CA certs as issuers | **Defended.** End-entity certificates cannot act as intermediate CAs. |

---

## 5. Security Assumptions

The security guarantees of this system hold under the following standard assumptions:
1. **Computational Hardness:**
   - The Discrete Logarithm Problem (DLP) is computationally intractable for RFC 3526 2048-bit MODP Group 14.
   - Ed25519 and SHA-256 are cryptographically preimage and collision resistant.
   - AES-256-GCM provides IND-CPA and INT-CTXT security assuming nonces are never repeated for a given key.
2. **Root of Trust Integrity:**
   - The Root CA certificate (`certs/ca.pem`) is distributed authentically to clients before handshake execution.
   - The Root CA private key (`certs/ca_key.pem`) is protected against unauthorized access.
3. **Endpoint Integrity:**
   - Client endpoints are not infected with memory-scraping malware or keyloggers during execution.
4. **True Randomness:**
   - The underlying operating system provides cryptographically secure random numbers (`secrets`, `os.urandom`).

---

## 6. Protection Boundary & Residual Risks

A vital requirement of BACSE203 Project 12 is an honest, rigorous analysis of the **protection boundary** — acknowledging what the architecture does **not** protect against:

### 6.1 Replay Attacks (Within an Active Session)
- **Vulnerability:** Chat messages contain `{type, sender, target, nonce, ciphertext, signature}`. While `nonce` is randomized per message, the client does not maintain a sliding window of observed nonces, timestamps, or sequential message counter.
- **Impact:** An attacker who captures a validly signed message (e.g., `"Approve transaction"`) can replay the identical packet within the same session. Bob's client will decrypt it a second time.
- **Mitigation for Production:** Add a monotonically increasing sequence counter or UTC timestamp into `chat_signed_fields`, rejecting out-of-order or expired messages.

### 6.2 Metadata & Traffic Analysis
- **Vulnerability:** End-to-end encryption protects message *content*, but message *headers* (`type`, `sender`, `target`) must be read by the server to route packets.
- **Impact:** An eavesdropper or the server can observe who is talking to whom, connection durations, message frequencies, and approximate payload sizes.
- **Mitigation for Production:** Onion routing (Tor-like circuits), fixed-size padding, or mix networks.

### 6.3 Forward Secrecy across Handshake Sessions
- **Status:** **Protected.** Because each `/dh` handshake generates fresh random private exponents $a, b$, compromising a client's long-lived Ed25519 signing key in the future does **not** allow an attacker to decrypt past recorded sessions.
- **Limitation:** Within a single persistent session, all messages share the same session key until a new `/dh` handshake is renegotiated. Implementing a double-ratchet mechanism (e.g. Signal Protocol) would refresh symmetric keys per message.

### 6.4 Endpoint Key Storage
- **Vulnerability:** In the lab environment, private keys are stored unencrypted in PEM format (`certs/alice_key.pem`) or kept in process memory.
- **Impact:** A local attacker with filesystem access can exfiltrate private keys.
- **Mitigation for Production:** Encrypt private keys at rest with AES-GCM and a user passphrase (PBKDF2 / Argon2), or utilize OS-backed hardware security modules (HSM / TPM / Secure Enclave).

### 6.5 Centralized Single Root CA Failure
- **Vulnerability:** The system relies on a single Root CA. If the Root CA private key is compromised, an attacker can issue valid certificates for any username.
- **Mitigation for Production:** Certificate Transparency logs (RFC 6962), offline air-gapped root with intermediate CAs, or decentralized web-of-trust models.

---

## 7. Threat Model Conclusion

The implementation provides robust, cryptographically sound end-to-end confidentiality, data integrity, non-repudiation, and identity binding. By combining **Diffie-Hellman Group 14**, **AES-256-GCM**, **Ed25519 signatures**, and **X.509 Certificate Authority validation**, the system successfully neutralizes all active Man-in-the-Middle impersonation and tampering attacks, meeting all Project 12 syllabus requirements for BACSE203.
