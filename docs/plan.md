# Secure Messaging System Project Plan

## Project
Secure Messaging System with Full Key Management

## Course reference
BACSE203 Computer Networks — Project 12

## Objective
Build an end-to-end encrypted messaging system that demonstrates:
- Diffie-Hellman key exchange
- AES session encryption
- digital signatures for authentication
- certificate-authority-based identity binding
- adversarial MITM testing and security analysis

---

## Phase-by-phase implementation plan

### Phase 1 — Plaintext messaging skeleton
Goal: Create the base network application and establish communication flow.

Tasks:
- Set up the project structure
- Create a Python TCP server
- Create a Python TCP client
- Allow one client to send messages to another
- Define a simple JSON message format
- Add logging for sent/received messages
- Verify the app works in plaintext mode

Expected outcome:
- Two clients can connect to the server
- Messages are delivered without encryption
- The team can understand the networking layer before adding crypto

Files to create:
- src/server.py
- src/client.py
- src/utils.py
- src/message_format.py

Validation:
- Run the server
- Launch two clients
- Send a message and confirm it appears at the receiving end

---

### Phase 2 — Diffie-Hellman key exchange
Goal: Establish a shared secret between peers without directly transmitting it.

Tasks:
- Implement a DH key generation process
- Exchange public values between communicating parties
- Derive a shared secret from the exchanged values
- Store the session key securely in memory
- Document the exchange process in a protocol spec

Expected outcome:
- Both peers independently compute the same shared secret
- The shared secret is never sent over the network directly

Files to create:
- src/dh.py
- src/protocol.md or docs/protocol.md

Validation:
- Print both generated public values and resulting shared key
- Confirm both sides derive the same value

---

### Phase 3 — AES session encryption and signatures
Goal: Secure the transmitted message content and verify authenticity.

Tasks:
- Use AES for symmetric message encryption
- Derive a session key from the DH exchange
- Encrypt message payloads before sending
- Decrypt messages on the receiver side
- Add digital signatures using asymmetric keys
- Verify signatures before accepting a message as authentic

Expected outcome:
- Messages are encrypted in transit
- Receiving client can verify the sender identity and message integrity

Files to create:
- src/crypto.py
- src/signing.py

Validation:
- Send a message from Alice to Bob
- Confirm Bob can decrypt and verify it
- Tamper with the payload and confirm signature verification fails

---

### Phase 4 — Certificate authority and trust chain
Goal: Bind identity to public keys using a lightweight CA workflow.

Tasks:
- Create a CA class or script
- Generate CA keys and root certificate
- Issue certificates to clients
- Store public key + identity mapping
- Verify peer certificates before communication
- Add a trust decision process

Expected outcome:
- A client accepts communication only from a valid certificate holder
- Identity spoofing is prevented within the project design

Files to create:
- src/ca.py
- certs/
- docs/certificate_workflow.md

Validation:
- Request and verify a certificate
- Attempt to communicate with an untrusted or mismatched identity
- Confirm verification fails

---

### Phase 5 — Adversarial MITM testing
Goal: Test whether the system survives an active attacker.

Tasks:
- Introduce a third party as the attacker
- Place the attacker between Alice and Bob
- Intercept or alter exchanged public keys, encrypted messages, or signatures
- Use Wireshark or logging to capture traffic
- Record whether the attack was detected or blocked

Expected outcome:
- The project demonstrates how the security design behaves under attack
- The report explains what the system protects and what it does not

Files to create:
- tests/mitm_test.py
- logs/traffic_capture.log
- docs/mitm_analysis.md

Validation:
- Run a MITM simulation
- Capture data before and after the attack
- Confirm if the attack failed because of signature verification, certificate checks, or shared secret protections

---

### Phase 6 — Threat model and final report
Goal: Document the security boundary honestly and clearly.

Tasks:
- Describe assets, threats, trust boundaries, and assumptions
- Explain what confidentiality, integrity, and authentication the design provides
- File a threat-model chapter
- Explain limitations such as weak key storage, compromised endpoints, replay attacks, or social engineering
- Summarize the project in a final report

Expected outcome:
- Final documentation clearly separates protection from residual risk
- The system can be explained in viva and evaluation

Files to create:
- docs/threat_model.md
- docs/final_report.md
- docs/summary.md

Validation:
- Check that the report includes:
  - objective
  - architecture
  - protocol design
  - MITM test result
  - threat model
  - conclusions and limitations

---

## Suggested repository structure

```text
secure_system/
├── README.md
├── docs/
│   ├── REQUIREMENTS.md
│   ├── plan.md
│   ├── protocol.md
│   ├── certificate_workflow.md
│   ├── mitm_analysis.md
│   ├── threat_model.md
│   └── final_report.md
├── src/
│   ├── client.py
│   ├── server.py
│   ├── dh.py
│   ├── crypto.py
│   ├── ca.py
│   ├── utils.py
│   └── signing.py
├── certs/
│   ├── ca.pem
│   ├── alice.pem
│   └── bob.pem
├── logs/
│   └── traffic_capture.log
├── tests/
│   └── mitm_test.py
├── .gitignore
└── requirements.txt
```

---

## Recommended branch plan

Use separate Git branches for each phase so the project is easy to follow as a course-like progression:

- main
- phase-01-plaintext-chat
- phase-02-dh-key-exchange
- phase-03-session-encryption-and-signatures
- phase-04-ca-and-trust
- phase-05-mitm-adversarial-test
- phase-06-threat-model-and-report

This makes it easier for teammates or evaluators to review the project in stages rather than as one large final solution.

---

## Suggested implementation order

1. Plaintext communication
2. Diffie-Hellman exchange
3. AES encryption
4. Digital signatures
5. CA workflow
6. MITM adversarial testing
7. Threat model and final write-up

This sequence follows the assignment milestones and keeps debugging manageable.

---

## Success criteria

The project is complete when:
- messages can be exchanged securely between clients
- keys are exchanged using DH
- message content is confidential through AES
- authenticity is enforced by signatures
- identity is bound through a certificate workflow
- adversarial MITM behavior is tested and documented
- the final report clearly explains the protection boundary

---

## Notes

This project should focus not only on building a working system, but also on understanding the limits of the design. The most important outcome is not simply that encryption works, but that the team can explain exactly what security it provides and where it does not.
