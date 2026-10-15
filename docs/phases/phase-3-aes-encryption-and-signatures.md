# Phase 3: AES encryption and digital signatures, explained simply

## Where phase 2 left us

After `/dh`, Alice and Bob share a secret 32-byte session key that the
server never saw. But chat messages were still sent as plain text, so the
server could read every one, and nothing stopped it from changing them.

Phase 3 fixes two things:

| Goal | Question it answers | Tool |
|---|---|---|
| Confidentiality | Can anyone besides Bob read this? | AES-256-GCM |
| Authenticity + integrity | Did Alice really send this, unchanged? | Ed25519 signatures |

## Part 1: AES locks the content

AES is a *symmetric* cipher: the same key locks and unlocks. Alice and
Bob already have the same key from Diffie-Hellman, so:

```
Alice:  ciphertext = AES_encrypt(session_key, "meet at 5")
Bob:    "meet at 5" = AES_decrypt(session_key, ciphertext)
```

The server only relays the ciphertext, a string like
`BqxpPrXSH00P/eiP3uoE8iLd...`, which is useless without the key.

We use AES in **GCM mode**, which adds two things:

- **A nonce** ("number used once"): 12 random bytes per message, so the
  same text encrypts differently every time. An eavesdropper can't tell
  when Alice repeats herself.
- **An authentication tag**: if anyone flips even one bit of the
  ciphertext, decryption fails instead of producing garbage.

## Part 2: Signatures prove who sent it

A signature uses a *key pair*, two linked keys:

- **Private key:** kept secret by Alice, used to **sign**.
- **Public key:** shared with everyone, used to **verify**.

Only Alice's private key can produce a signature that her public key
accepts. Changing a single character of the signed data makes
verification fail.

```
Alice:  signature = sign(alice_private, message)
Bob:    verify(alice_public, message, signature)  →  True / False
```

Each client creates its own Ed25519 key pair at startup and sends the
public half to its peer during the `/dh` handshake.

## Why do we need both?

GCM's tag already detects tampering, so why sign as well? GCM proves the
message came from *someone with the session key*. If an attacker
secretly sat in the middle of the DH handshake, that someone could be the
attacker. A signature ties the message to one specific person's key.

## Putting it together

```
Alice                                   Server                      Bob
encrypt "meet at 5" with session key
sign the ciphertext with private key
  ── {nonce, ciphertext, signature} ──▶  sees only gibberish  ──▶
                                                        1. verify signature
                                                        2. decrypt with session key
                                                        3. show "meet at 5"
```

If step 1 or 2 fails, Bob's client shows
`[security] Rejected message from alice: ...` and never displays the
text.

## Try it

```bash
python src/crypto.py      # encrypt, decrypt, and a rejected re-targeted message
python src/signing.py     # a signature that verifies, and one that fails after tampering
python -m unittest discover tests -v
```

## What's still missing

When Bob receives Alice's public signing key during `/dh`, he has no way
to check that it's *really* Alice's. An attacker in the middle could swap
in their own key. Phase 4 adds a certificate authority, a trusted party
that vouches "this public key belongs to alice". That's the last piece
needed to stop a man-in-the-middle.
