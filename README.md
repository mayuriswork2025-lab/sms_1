# Secure Messaging System with Full Key Management

## Project 12 | BACSE203 Computer Networks

Group: Group A — Protocol & Systems Builds  
Difficulty: Intermediate  
Course outcome addressed: CO5  
Syllabus coverage: Module 5

---

## Quick start

This repository implements the full end-to-end cryptographic lifecycle:
- **Phase 1:** Delimited TCP client-server messaging.
- **Phase 2:** Ephemeral Diffie-Hellman key exchange (RFC 3526 Group 14).
- **Phase 3:** AES-256-GCM authenticated session encryption and Ed25519 digital signatures.
- **Phase 4:** Certificate Authority (`src/ca.py`), X.509 v3 identity certificates, and 6-step trust chain validation.
- **Phase 5:** Adversarial MITM testing harness (`tests/mitm_test.py`) and traffic capture (`logs/traffic_capture.log`).
- **Phase 6:** STRIDE threat model (`docs/threat_model.md`), comprehensive final report (`docs/final_report.md`), and Viva Voce preparation.

See `docs/protocol.md` and `docs/final_report.md` for full technical documentation.

### Install dependencies

```bash
pip install -r requirements.txt
```

### Initialize the Certificate Authority & Keys

```bash
python src/ca.py init
```
Generates the Root CA certificate (`certs/ca.pem`), Root CA private key (`certs/ca_key.pem`), and issues default certificates for `alice` and `bob`.

Chat is peer-to-peer, not broadcast: you must complete a `/dh` handshake
with a username before you can `/msg` them, and only that peer receives
the message — other connected clients (or the server's log) don't see it
routed to them.

### Run the server

From the project root:

```bash
python src/server.py
```

### Run the clients

Open a second terminal and start Alice:

```bash
python src/client.py --username alice
```

Open a third terminal and start Bob:

```bash
python src/client.py --username bob
```

### Exchange keys, then chat

In the Alice terminal:

```text
/dh bob
```

Both terminals print the public value they received from the other side,
followed by the derived session key in hex — the two should match. Then,
in the Alice terminal:

```text
/msg bob hello bob
```

In the Bob terminal, you should see:

```text
[alice] hello bob  (signature verified)
```

The server terminal only logs the ciphertext it relayed, never the text.
If a message fails signature verification or decryption, the receiver
prints `[security] Rejected message from <sender>: <reason>` instead.

Trying `/msg` with a peer you haven't run `/dh` with first is rejected
client-side with an error, rather than sent.

### One-shot mode

Send a single message and exit, performing the handshake automatically
first (the target peer must already be connected and listening):

```bash
python src/client.py --username alice --target bob --message "hello from alice"
```

### Exit

To exit a client, type:

```text
quit
```

To stop the server, press:

```text
Ctrl+C
```

### Run the tests

Run all 36 unit and integration tests (crypto, signatures, CA validation, trust chain, MITM defenses):
```bash
python -m unittest discover tests -p "*test*.py" -v
```

### Run the Adversarial MITM Simulation

Execute the automated adversarial test suite to simulate an active Man-in-the-Middle attacker ("Mallory"):
```bash
python tests/mitm_test.py
```
This logs packet frames to `logs/traffic_capture.log` and outputs a complete defense matrix.

### Try the crypto standalone

No server or second client needed — this simulates both sides locally and
prints the two independently derived shared secrets:

```bash
python src/dh.py
python src/crypto.py
python src/signing.py
python src/ca.py verify certs/alice.pem --username alice
```

---

## 1. Project Objective

Build an end-to-end encrypted messaging system in which the team implements the complete security workflow:

- Diffie-Hellman (DH) key exchange
- AES session encryption
- Digital signatures for authentication
- A certificate-authority (CA) workflow for identity binding
- A documented adversarial test where one team member acts as a man-in-the-middle (MITM)

The project focuses not only on building a working messaging application, but also on understanding the security boundary: what the design protects and what it does not protect.

---

## 2. Overview

This repository is intended to serve as the basis for a secure messaging application that allows two or more users to exchange encrypted messages over a network while preserving confidentiality, integrity, and authenticity.

The system is designed around a realistic cryptographic workflow:

1. Clients establish trust and identity through a certificate authority.
2. Users exchange keys using Diffie-Hellman to derive a shared session secret.
3. Messages are encrypted with AES using the negotiated session key.
4. Senders sign payloads digitally to verify authenticity and integrity.
5. A security analysis tests the system under adversarial conditions such as MITM attack scenarios.

---

## 3. Expected Deliverables

The project should include the following core components:

- Messaging client/server with end-to-end encryption of all message content
- Key-exchange and session-establishment protocol specification
- Working certificate-authority workflow with issuance and verification
- Adversarial MITM test with packet captures or logs showing attack success/failure
- Threat-model chapter analysing the protection boundary

---

## 4. Core Security Goals

### Confidentiality
Messages must remain unreadable to unauthorized parties, even if packets are intercepted on the network.

### Integrity
A recipient must be able to detect if a message has been modified in transit.

### Authentication
The communicating parties must verify that messages are truly from the expected sender and not from an impostor.

### Identity Binding
A certificate or trust framework should connect a public key to a known identity, preventing spoofing.

---

## 5. Security Workflow

### 5.1 Key Exchange
Use the Diffie-Hellman key exchange to establish a shared secret between two communicating peers without directly transmitting the secret over the network.

### 5.2 Session Encryption
Once the shared secret is established, use a symmetric encryption algorithm such as AES to encrypt message content for confidentiality and performance.

### 5.3 Digital Signatures
Use digital signatures to verify:

- The message originated from the claimed sender
- The content was not altered after signing

### 5.4 Certificate Authority
Implement a CA or simplified trust authority that:

- Issues identity certificates
- Binds a public key to a user identity
- Verifies certificates before accepting communication

This gives the system a chain of trust and protects against identity spoofing.

---

## 6. Suggested Architecture

A reasonable architecture for the project is:

- Client Application: connects to server, handles encryption, certificate verification, and message sending
- Server/Relay: handles communication between clients and message routing
- Key Exchange Module: performs Diffie-Hellman negotiation
- Cryptography Module: encrypts/decrypts messages using AES and signs/verifies payloads
- Certificate Authority Module: issues and validates certificates
- Logging/Packet Capture Module: records network traffic for analysis and adversarial testing

A typical message flow looks like this:

1. Client requests or receives certificate from CA
2. Client verifies the certificate chain
3. Clients perform DH exchange
4. Shared session key is derived
5. Message is signed and encrypted
6. Recipient verifies signature and decrypts message

---

## 7. Technologies

This project is intended to use the following tools and environment:

- Python
- Python cryptography library
- TCP sockets
- Wireshark for traffic capture and analysis
- Git for source control

### Recommended Python packages

- cryptography
- hashlib
- socket
- json
- ssl (if applicable)
- logging

---

## 8. Milestones

| # | Milestone |
|---|-----------|
| 45 | Months 1–2: Plaintext messaging skeleton; crypto primitives integration |
| 46 | Months 2–3: DH exchange, session keys, message encryption and signatures |
| 47 | Months 3–4: CA workflow, certificate validation, trust chain |
| 48 | Months 5–6: Adversarial testing, threat-model analysis, report and viva |

---

## 9. Development Workflow

### Phase 1: Foundation
- Set up the messaging skeleton
- Build basic client/server communication
- Add message sending and receiving in plaintext
- Integrate cryptographic libraries

### Phase 2: Secure Channel Setup
- Implement Diffie-Hellman exchange
- Derive session keys
- Send encrypted messages using AES
- Add digital signature generation and verification

### Phase 3: Trusted Identity
- Create CA functionality
- Issue certificates to users
- Validate certificates for communication peers
- Establish trust decisions

### Phase 4: Testing and Analysis
- Simulate MITM attack
- Capture traffic in Wireshark or logs
- Analyse whether the attack is detected or prevented
- Document security outcomes and limitations

---

## 10. Sample Project Structure

```text
secure_system/
├── README.md
├── docs/
│   └── REQUIREMENTS.md
├── src/
│   ├── client.py
│   ├── server.py
│   ├── crypto.py
│   ├── dh.py
│   ├── ca.py
│   └── utils.py
├── certs/
│   ├── ca.pem
│   ├── alice.pem
│   └── bob.pem
├── logs/
│   └── traffic_capture.log
├── tests/
│   └── test_security_flow.py
└── report/
    └── threat_model.md
```

This structure is a suggested layout and may be adapted to the project implementation.

---

## 11. Setup Instructions

### Prerequisites

- Python 3.9 or newer
- pip package manager
- Internet access to install dependencies (if needed)
- Wireshark for packet inspection

### Install dependencies

```bash
python -m venv venv
source venv/bin/activate
pip install cryptography
```

### Run the application

```bash
python src/server.py
python src/client.py
```

If the project uses a custom server/client architecture, the exact commands may vary depending on the implementation.

---

## 12. Example Secure Messaging Flow

```text
Alice -> CA: Request certificate
CA -> Alice: Issue identity certificate
Bob -> CA: Request certificate
CA -> Bob: Issue identity certificate
Alice <-> Bob: Perform Diffie-Hellman exchange
Alice -> Bob: Encrypt message with AES session key
Alice -> Bob: Sign encrypted payload
Bob: Verify signature and decrypt payload
```

---

## 13. Adversarial MITM Test

A key requirement of the assignment is an adversarial test where one participant acts as a man-in-the-middle.

### MITM Scenario

An attacker sits between Alice and Bob and attempts to:

- intercept exchanged keys
- alter encrypted messages
- impersonate one participant
- break the trust model

### What the design should protect against

- Eavesdropping on ciphertext without the session key
- Tampering that can be detected via signatures or integrity checks
- Certificate mismatch or unauthorized identity claims

### What the design may not fully protect against

- Weak key generation or poor implementation
- Compromised client devices
- Poor CA trust management
- Replay attacks if not explicitly handled
- Social engineering or insider compromise

This analysis should be documented in the project report.

---

## 14. Threat Model

The threat model should clearly describe:

- Assets: message content, keys, certificates, identity records
- Threats: interception, tampering, impersonation, replay, compromised nodes
- Trust boundaries: between clients, server, and CA
- Security assumptions: correct cryptographic implementation, valid certificate verification, secure storage of private keys
- Residual risk: areas where the system still relies on assumptions and operational security

---

## 15. Report Expectations

The final project report should include:

- System overview and objective
- Protocol design and message flow
- Key exchange, session key, and encryption details
- Signature and certificate validation process
- Threat model and security analysis
- MITM test scenario, traffic capture, and outcome
- Security conclusions and limitations
- Viva-ready explanation of the design

---

## 16. Evaluation Focus

The project is typically assessed on:

- Correctness of cryptographic workflows
- Security reasoning and threat analysis
- Quality of protocol design documentation
- Reliability of certificate validation and trust model
- Demonstration of adversarial testing and analysis

---

## 17. Notes

This project is intended to be a practical implementation of core computer network security concepts. It should demonstrate both the strengths and the limits of cryptographic protection in a real communication system.

The most important learning outcome is not simply "the app works," but understanding how identity, trust, encryption, and verification combine to provide secure communication.

---

## 18. License

This project is created for academic coursework and is intended for educational use.

---

## 19. Contributors

Add team member names here as the project is developed.

```text
Team Members:
- Student 1
- Student 2
- Student 3
```
