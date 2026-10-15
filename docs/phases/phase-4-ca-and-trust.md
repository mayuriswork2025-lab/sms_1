# Phase 4: Certificate Authority & Trust Chain, explained simply

## Where phase 3 left us

In Phase 3, we added Ed25519 digital signatures to our Diffie-Hellman handshake and AES-256-GCM messages. This prevented anyone from tampering with a message after it was sent.

**The big catch in Phase 3:**  
When Alice sent her public signing key to Bob, Bob just accepted whatever public key arrived over the network!  
An attacker sitting in the middle (Mallory) could intercept Alice's message, replace Alice's signing key with Mallory's signing key, and Bob would think Mallory *was* Alice!

| Phase | What we have | Remaining vulnerability |
|---|---|---|
| **Phase 2 (DH)** | Shared secret derived without transmitting it | Eavesdropper in the middle can substitute keys |
| **Phase 3 (AES + Signatures)** | Encrypted messages & tamper detection | Attacker can swap the signing key during handshake |
| **Phase 4 (CA & Trust Chain)** | **Public key bound to identity** | None of the above: MITM is fully defeated! |

---

## What is a Certificate Authority (CA)?

A **Certificate Authority (CA)** is like a trusted passport office.

1. **Before chatting:** Alice goes to the CA and says:  
   *"Here is my name (`alice`) and my public signing key. Please vouch for me."*
2. **The CA inspects Alice:** The CA creates an **identity certificate** stating:  
   `"This certificate belongs to 'alice', and her public key is 2CXFMv3... Signed by BACSE203 Root CA."`
3. **During chat:** When Alice chats with Bob, she doesn't just send her key — she sends her **CA-signed certificate**.
4. **Bob checks the signature:** Bob already has the Root CA's public certificate. Bob verifies that the CA really signed Alice's certificate and that the name inside says `alice`.

If Mallory tries to forge a certificate, she can't, because she doesn't possess the CA's secret private key!

---

## The 6-Step Verification Check

Whenever Bob receives a handshake from Alice, his client performs six checks before trusting her:

1. **Format check:** Is the certificate a valid X.509 format?
2. **Issuer check:** Was it issued by our trusted Root CA (`certs/ca.pem`)?
3. **CA Signature check:** Is the CA's digital signature mathematically valid?
4. **Expiration check:** Is the certificate valid right now (not expired, not from the future)?
5. **Revocation check:** Is this certificate on the revocation list (CRL)?
6. **Identity check:** Does the Common Name inside the certificate (`CN=alice`) match the username sending the message?
7. **Key Binding check:** Does the public key inside the certificate match the key used to sign the DH values?

If **any single check fails**, Bob immediately rejects the connection with:
```text
[security] Rejected DH public value from alice: certificate verification failed (...)
```

---

## Where this lives in the code

- `src/ca.py`: The Certificate Authority implementation. Handles issuing, verifying, revoking, and saving X.509 certificates.
- `src/signing.py`: `SigningIdentity.load_or_generate` loads certificates from `certs/` and attaches them to client identities.
- `src/message_format.py`: `build_dh_public_message` carries the certificate field.
- `src/client.py`: `ChatClient` automatically loads the trusted Root CA, attaches its certificate during `/dh`, and validates peer certificates.
- `tests/test_ca_and_trust.py`: 11 tests verifying issuance, expiration, untrusted CA rejection, identity mismatch rejection, and full authenticated chat.

---

## Try it yourself

Initialize the Root CA and generate certificates for `alice` and `bob`:
```bash
python src/ca.py init
```

Verify Alice's certificate:
```bash
python src/ca.py verify certs/alice.pem --username alice
```

Try verifying Alice's certificate claiming to be Bob (rejected!):
```bash
python src/ca.py verify certs/alice.pem --username bob
```

Run all CA unit tests:
```bash
python -m unittest tests/test_ca_and_trust.py -v
```
