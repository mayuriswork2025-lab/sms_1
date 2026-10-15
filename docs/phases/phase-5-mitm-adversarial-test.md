# Phase 5: Adversarial MITM Testing, explained simply

## What is a Man-in-the-Middle (MITM) attack?

Imagine Alice wants to whisper a secret to Bob, but they are in different rooms. All their notes must be carried by a messenger named **Mallory**.

If Alice and Bob don't have a way to verify identity, Mallory can do two terrible things:
1. **Read their secrets:** Mallory opens the note, reads it, and folds it back up.
2. **Change their secrets:** Mallory writes a completely different note, pretends it came from Alice, and hands it to Bob!

In Phase 5, we write automated code that puts Mallory right in the middle of our network to test if our security holds up.

---

## The 6 Attack Scenarios Tested

### 1. Passive Eavesdropping
- **What Mallory does:** Sniffs the network cables and records all packets.
- **Can she read it?** **NO.** AES-256-GCM turns the message into random-looking ciphertext. Without the session key, Mallory cannot read a single word.

### 2. The Classic Diffie-Hellman Hack (Phase 2 Flaw)
- **What Mallory does:** When Alice sends her public DH number $A$, Mallory intercepts it and sends her own number $M$ to Bob instead.
- **Can she do it?** In Phase 2, **YES!** Alice ends up sharing a secret key with Mallory, and Bob shares a *different* secret key with Mallory. Mallory can decrypt, read, change, and re-encrypt every message. This test proves why Phase 2 alone is dangerous!

### 3. The Fake Signature Hack (Phase 3 Flaw)
- **What Mallory does:** In Phase 3, Alice signs her DH number. But Mallory intercepts the packet and replaces *both* Alice's DH number and Alice's public signing key with Mallory's own key.
- **Can she do it?** In Phase 3, **YES!** Because Bob didn't have a Certificate Authority yet, Bob accepted Mallory's public key thinking it was Alice's.

### 4. The Certificate Authority Defense (Phase 4 Victory!)
- **What Mallory tries:**
  1. Mallory creates a fake certificate signed by her own fake CA.  
     👉 **Result: BLOCKED!** Bob checks against the Root CA and rejects it.
  2. Mallory sends her own valid certificate, but claims she is Alice.  
     👉 **Result: BLOCKED!** Bob sees the Common Name says `mallory`, not `alice`.
  3. Mallory steals Alice's certificate and sends it with Mallory's signing key.  
     👉 **Result: BLOCKED!** Bob checks that the public key inside the certificate matches the signing key on the message.
  4. Mallory changes the bytes inside Alice's certificate.  
     👉 **Result: BLOCKED!** The CA's digital signature breaks.

### 5. In-Transit Message Tampering
- **What Mallory does:** Changes just 1 bit of an encrypted chat message while it travels through the server.
- **Can she do it?** **NO.** Alice's Ed25519 signature fails immediately. Even if the signature were ignored, AES-GCM's authentication tag detects the corruption and drops the packet.

### 6. Message Replay
- **What Mallory does:** Records a valid message from Alice (`"Transfer $100"`) and sends the exact same message again 5 minutes later.
- **Can she do it?** Currently **YES.** Because our protocol does not yet include timestamp or sequence number checks, replayed messages are decrypted successfully. This is our documented **protection boundary** that we explain in Phase 6.

---

## How to Run the Tests

To run the full adversarial test suite and see the attack matrix:
```bash
python tests/mitm_test.py
```

To see the captured network traffic:
```bash
type logs\traffic_capture.log
```
