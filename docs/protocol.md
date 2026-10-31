# Wire protocol

## Framing

Every message is a single JSON object followed by a `\n` delimiter, sent
over a persistent TCP connection between a client and the server. TCP does
not preserve message boundaries, so both sides buffer incoming bytes and
only parse a message once a full `\n`-terminated frame has arrived
(`src/protocol/reader.py`). The JSON encoding and the delimiter are both
owned by `src/protocol/json_protocol.py`; a different `WireProtocol`
implementation (e.g. a binary or encrypted format) could be swapped in
without changing anything else in `server.py` or `client.py`.

## Message types

| `type`      | Direction         | Fields                                   | Purpose |
|-------------|--------------------|-------------------------------------------|---------|
| `login`     | client -> server   | `username`                                | Registers the connection under a username. |
| `system`    | server -> client   | `sender`, `message`                       | Server-generated notices (e.g. welcome message). |
| `chat`      | client -> server -> one client | `sender`, `target`, `nonce`, `ciphertext`, `signature` | AES-256-GCM encrypted, Ed25519-signed chat message, relayed by the server to `target` only (unicast). There is no plaintext field. The client refuses to send one before a `/dh` handshake with `target` has produced a session key. |
| `leave`     | client -> server   | (none)                                     | Client is disconnecting; server closes the connection. |
| `dh_public` | client -> server -> one client | `sender`, `target`, `public_key`, `signing_key`, `signature`, `certificate` (optional/Phase 4) | Diffie-Hellman public value plus sender's Ed25519 signing key and optional Root CA-signed X.509 certificate, signed by that key. Relayed by server to `target` only (unicast). |

## Diffie-Hellman key exchange

Goal: two clients (Alice and Bob) derive a shared secret without ever
putting that secret on the wire. Implemented in `src/dh.py`; the network
handshake lives in `client.py`'s `/dh <username>` command and
`ChatClient.handle_dh_public`.

**Group parameters.** Both parties use the same publicly known (p, g):
RFC 3526's 2048-bit MODP Group 14, with generator `g = 2`. Publishing these
values is standard practice and does not weaken the exchange — DH's
security rests on the discrete-log problem being hard for this group, not
on the group being secret.

See `docs/phases/phase-2-dh-key-exchange.md` for a short, beginner-friendly
explanation of how the exchange works before diving into the wire-level
walkthrough below.

**Handshake (2 messages):**

```
Alice                          Server                          Bob
  |-- dh_public(target=bob) -----> |                              |
  |                                |-- dh_public(sender=alice) -->|
  |                                |                          [Bob generates
  |                                |                           his own keys,
  |                                |                           derives the
  |                                |                           shared secret]
  |                                |<-- dh_public(target=alice) --|
  |<-- dh_public(sender=bob) ------|                              |
[Alice derives the
 shared secret]
```

1. Alice runs `/dh bob`. Her client generates a private key `a` (a random
   integer) and computes her public value `A = g^a mod p`. It stores `a`
   locally (keyed by `bob`) and sends `{"type": "dh_public", "sender":
   "alice", "target": "bob", "public_key": A}` to the server.
2. The server looks up the connection currently registered as `bob` and
   forwards the message to that connection only — it never sees `a`, `b`,
   or the resulting shared secret, only the public value `A`.
3. Bob's client receives the message. Since he has no `alice` handshake in
   progress, he treats it as an incoming request: generates his own
   private key `b`, computes `B = g^b mod p`, computes the shared secret
   `s = A^b mod p`, and replies with his own `dh_public` message carrying
   `B`.
4. Alice's client receives Bob's reply, looks up her stored `a`, and
   computes `s = B^a mod p`.
5. Both sides now hold the same `s` (proven: `A^b = (g^a)^b = g^(ab) =
   (g^b)^a = B^a mod p`). Each side runs `s` through HKDF-SHA256
   (`derive_session_key`) to get a fixed-size 256-bit session key, ready to
   use as an AES key in phase 3.

**What crosses the network:** only `A` and `B` (the public values). `a`,
`b`, and `s` never leave the process that generated them.

**Validation:** running `python src/dh.py` performs the same math locally
for two simulated parties and asserts the derived secrets match. Running
two `client.py` instances and typing `/dh <peer>` performs the same
exchange for real, over the socket connection, and prints the resulting
session key hex on both sides so they can be compared by eye.

## Session encryption and signatures (phase 3)

Goal: chat content is unreadable to the server, and the receiver can
prove who sent a message and that nobody changed it. Implemented in
`src/crypto.py` (AES-256-GCM) and `src/signing.py` (Ed25519). See
`docs/phases/phase-3-aes-encryption-and-signatures.md` for a beginner-friendly
explanation.

**Keys involved:**

| Key | Type | Lifetime | Used for |
|-----|------|----------|----------|
| Session key | 32-byte AES key, `HKDF-SHA256(DH shared secret)` | One per peer per handshake | Encrypting chat content |
| Identity key pair | Ed25519 | One per client process | Signing DH values and chat messages |

**Signed handshake.** Each `dh_public` message now also carries the
sender's Ed25519 public key (`signing_key`) and a `signature` over
`{type, sender, target, public_key, signing_key}`. The receiver verifies
that signature before using the DH value, and rejects the message if it
fails or if `target` isn't its own username, and it rejects any DH value
outside `[2, P-2]` (such values would force a predictable shared secret).
On success it stores `signing_key` as that peer's identity key for later
chat messages.

**Server-side checks.** The relay refuses a second login under a username
that is already connected, and drops any frame whose `sender` differs from
the name the sending connection logged in with.

**Sending a chat message** (`ChatClient.seal_chat`):

1. Encrypt the text with AES-256-GCM under the peer's session key, with a
   fresh random 12-byte nonce. Associated data is `chat|<sender>|<target>`,
   so the ciphertext only decrypts for that exact sender and target pair.
2. Increment the per-peer counter and attach it as `seq` (1, 2, 3, ...).
   The counter resets to 0 whenever a new DH session with that peer starts.
3. Sign `{type, sender, target, seq, nonce, ciphertext}` with the sender's
   Ed25519 private key (encrypt-then-sign).
4. Send `seq`, `nonce`, `ciphertext` and `signature`, with the binary values
   base64-encoded. No plaintext goes on the wire.

```json
{"type": "chat", "sender": "alice", "target": "bob", "seq": 1,
 "nonce": "<base64>", "ciphertext": "<base64>", "signature": "<base64>"}
```

**Receiving a chat message** (`ChatClient.open_chat`), in this order:

1. `target` must be our own username.
2. We must hold a session key and a signing key for `sender`.
3. `seq` must be present and be an integer.
4. The signature must verify under `sender`'s stored signing key.
5. `seq` must be higher than the last one accepted from `sender` in this
   session. Otherwise the frame is a replay and is rejected.
6. GCM decryption must succeed. This also re-checks integrity and the
   sender/target binding. Only then is `seq` recorded as accepted.

If any step fails, the message is dropped and the client prints
`[security] Rejected message from <sender>: <reason>`. The text is never
shown.

Signatures are serialized canonically (`json.dumps` with sorted keys and
fixed separators) so the signer and verifier sign and check identical
bytes.

**Why both GCM and signatures?** GCM's tag proves the message came from
*someone holding the session key*, which after a MITM'd handshake could be
the attacker. The signature proves it came from the holder of a specific
identity key. Once phase 4 binds that key to a username through the CA,
that means it came from that user.

**Validation:**

```bash
python -m unittest discover tests -v
```

`tests/test_encryption_and_signing.py` performs a full alice/bob handshake
in-process, checks that Bob decrypts and verifies Alice's message, and
confirms that each of these is rejected: a flipped ciphertext byte, a
flipped nonce byte, a message signed by a different key claiming to be
Alice, a message from a peer with no session, and a tampered DH public
value. `python src/crypto.py` and `python src/signing.py` run small
standalone demos.

## Certificate Authority & Identity Binding (phase 4)

Goal: Defeat active Man-in-the-Middle key substitution during handshake by
binding each client's Ed25519 signing key to their username via an X.509
certificate signed by a trusted Root Certificate Authority (`src/ca.py`).
See `docs/certificate_workflow.md` and `docs/phases/phase-4-ca-and-trust.md`.

**Keys & Certificates involved:**
- `certs/ca.pem`: Trusted Root CA certificate pre-distributed to clients.
- `certs/<user>.pem`: Client X.509 v3 certificate binding `CN=<username>` to the public key.
- `certs/<user>_key.pem`: Client private signing key.

**Handshake with Certificate Validation:**
1. Alice sends `dh_public` carrying `public_key`, `signing_key`, `certificate`,
   and `signature` over all fields.
2. Bob verifies Alice's certificate:
   - Root CA signature on certificate is valid.
   - Current UTC timestamp is within certificate validity window.
   - Serial number is not revoked on CRL.
   - Subject Common Name equals `"alice"`.
   - Subject public key equals `signing_key`.
3. Bob verifies Alice's message signature over `dh_public_signed_fields`.
4. Bob replies with his own DH public value and Root CA-signed certificate.
5. Alice performs identical 6-step verification on Bob's certificate.

## Adversarial Testing (phase 5)

An active Man-in-the-Middle test harness (`tests/mitm_test.py`) tests the
system under attack from adversary "Mallory":
- **Eavesdropping:** AES-256-GCM protects confidentiality (Blocked).
- **Unauthenticated DH (Phase 2):** Mallory splits session (Succeeded, proves flaw).
- **Signed DH without CA (Phase 3):** Mallory swaps keys (Succeeded, proves flaw).
- **Active MITM with CA (Phase 4):**
  - Rogue CA cert: Blocked (Untrusted issuer).
  - Identity mismatch: Blocked (CN != claimed sender).
  - Cert replay with key swap: Blocked (Public key mismatch).
  - Cert tampering: Blocked (Invalid CA signature).
- **Ciphertext tampering:** Blocked (Invalid signature and GCM tag).
- Live attack: `attacks/mitm_proxy.py` (swap mode) succeeds against clients run with `--no-cert` and is rejected when certificates are verified. Wireshark captures are in `captures/`.

See `docs/mitm_analysis.md` and `docs/phases/phase-5-mitm-adversarial-test.md`.

## Threat Model & Protection Boundary (phase 6)

See `docs/threat_model.md` and `docs/final_report.md` for full STRIDE analysis.

**Documented Residual Risks:**
- **Replay attacks:** Mitigated. Chat frames carry a signed per-session `seq`; the receiver rejects any `seq` it has already accepted.
- **Metadata visibility:** Relay server observes `sender` and `target` to route packets.
- **Endpoint compromise:** Private keys stored on disk in PEM format.
