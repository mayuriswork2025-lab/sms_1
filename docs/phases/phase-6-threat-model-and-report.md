# Phase 6: Threat Model & Final Report, explained simply

## Why do we need a threat model?

In beginner projects, students often say:  
*"Our system is 100% secure and unbreakable."*

In real-world computer security, **nothing is 100% unbreakable**.  
A good engineer doesn't pretend a system is magic; a good engineer explains **exactly what the system protects against, and where the boundaries are**.

That is what **Phase 6** is all about:
1. Writing down the **Threat Model**: defining who the enemy is, what assets we have, and what attacks we can stop.
2. Explaining the **Residual Risks**: the few things we *cannot* stop with cryptography alone.
3. Preparing the **Final Academic Report** and **Viva Q&A** so any team member can ace the evaluation.

---

## What the System Successfully Protects

| Security Goal | How we achieved it | Attack it stops |
|---|---|---|
| **Confidentiality** | AES-256-GCM encryption with 256-bit keys | Eavesdropper or server reading messages |
| **Integrity** | AES-GCM Auth Tag + Ed25519 digital signatures | Server or attacker flipping bits in messages |
| **Authentication** | Ed25519 private/public key pairs | Impostor sending messages claiming to be Alice |
| **Identity Binding** | X.509 certificates signed by Root CA | MITM substituting public keys during handshake |
| **Forward Secrecy** | Fresh random DH exponents $a, b$ every handshake | Future key leak decrypting past recorded chats |

---

## The Realistic Protection Boundaries (Residual Risks)

Here are the limits of our design and how real-world systems handle them:

### 1. Replay Attacks
- **What happens:** If Mallory captures a valid message (`"Transfer $100"`), she can send the identical bytes again later, and Bob will decrypt it.
- **Why:** Our current messages don't have sequential message counter numbers or expiration timestamps.
- **Production fix:** Add a sequence counter (`seq: 1, 2, 3...`) and reject any message that arrives out of order or was already seen.

### 2. Metadata Leakage
- **What happens:** Even though the server can't read the chat content, it still sees `sender: "alice"` and `target: "bob"`.
- **Why:** The relay needs to know which TCP socket to forward the message to!
- **Production fix:** Use onion routing (like Tor) or cover traffic.

### 3. Compromised Endpoints
- **What happens:** If a hacker installs a keylogger or malware on Alice's computer, the hacker can steal Alice's private key (`certs/alice_key.pem`) from her hard drive.
- **Why:** Cryptography secures the *network wire*, not an infected operating system.
- **Production fix:** Hardware security keys (like YubiKey) or TPM/Secure Enclave.

---

## Where to find the final deliverables

- `docs/threat_model.md`: Complete STRIDE threat analysis.
- `docs/final_report.md`: The complete academic project report, including **Viva Voce Q&A**.
- `tests/mitm_test.py`: Standalone adversarial MITM test runner.
- `logs/traffic_capture.log`: Packet capture log with adversary attack traces.
