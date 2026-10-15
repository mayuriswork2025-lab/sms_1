**BACSE203 Computer Networks — Project Handbook** | Page 14

---

## Project 12
## Secure Messaging System with Full Key Management

**Group:** Group A — Protocol & Systems Builds
**Difficulty:** Intermediate
**Course outcomes addressed:** CO5 | **Syllabus coverage:** Module 5

### Objective

Build an end-to-end encrypted messaging system in which the team implements the complete security workflow: Diffie-Hellman key exchange, AES session encryption, digital signatures for authentication, and a certificate-authority process of their own design for identity binding. The final phase is a documented adversarial test in which one team member plays man-in-the-middle, and the report analyses precisely what the design does and does not protect against.

### Expected deliverables

- Messaging client/server with end-to-end encryption of all message content
- Key-exchange and session-establishment protocol specification
- Working certificate-authority workflow with issuance and verification
- Adversarial MITM test with captures showing attack success/failure
- Threat-model chapter analysing the protection boundary

### Milestone breakdown

| # | Milestone |
|---|-----------|
| 45 | Months 1–2: Plaintext messaging skeleton; crypto primitives integration |
| 46 | Months 2–3: DH exchange, session keys, message encryption and signatures |
| 47 | Months 3–4: CA workflow, certificate validation, trust chain |
| 48 | Months 5–6: Adversarial testing, threat-model analysis, report and viva |

### Required tools and environment

Python (cryptography library), TCP sockets, Wireshark, Git

---

**BACSE203 Computer Networks — Project Handbook** | Page 15