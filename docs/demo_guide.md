# Demo Guide

Step-by-step script for the final demo. Every command runs from the project root. The expected output shown under each step is what the code prints; if you see it, that step worked.

## 0. Setup (once per machine)

```bash
pip install -r requirements.txt
python src/ca.py init
python -m unittest discover -s tests -p "*.py"
```

`init` creates the Root CA and the `alice` and `bob` keys and certificates in `certs/`. On a fresh clone it makes a new CA for this machine, so git shows `certs/*.pem` as modified. Don't commit those files.

Never show `certs/*_key.pem` on screen: they are private keys.

Expected: `Ran 50 tests ... OK`

## 1. Chat (connect)

Three terminals:

```bash
python src/server.py                       # T1
python src/client.py --username bob        # T2
python src/client.py --username alice      # T3
```

In Alice's terminal: `/msg bob hello`

Expected: `[msg] No session with bob yet. Run '/dh bob' first.` Nothing is ever sent unencrypted.

## 2. Key exchange (Diffie-Hellman)

Standalone: `python src/dh.py` prints `Match: True`.

Live, in Alice's terminal: `/dh bob`

Expected: Alice and Bob each print `Session key (hex): ...`, and the two values are identical.

## 3. Certificate Authority

```bash
python src/ca.py verify certs/alice.pem
python src/ca.py verify certs/alice.pem --username bob
```

Expected: the first prints `Verification result: PASS`, the second prints `FAIL` with `Identity mismatch: certificate is for 'alice', but expected 'bob'`. During `/dh`, Bob also prints `[ca] Validated identity certificate for alice`.

The CA is offline: it signs certificates in advance and does not need to be running during the chat.

## 4. Digital signatures and encryption

```bash
python src/signing.py
python src/crypto.py
```

Expected: `Valid: True` and `Tampered valid: False`; `Decrypted: hello bob` and `Re-targeted ciphertext rejected: OK`.

Live, in Alice's terminal: `/msg bob hello bob`

Expected: Bob prints `[alice] hello bob  (signature verified)`. The server prints only `ciphertext=...`.

## 5. Wireshark

1. Capture on **Adapter for loopback traffic capture** (install Wireshark with Npcap and tick "Support loopback traffic capture").
2. Display filter: `tcp.port == 9000 || tcp.port == 9001`
3. Repeat steps 2 and 4, then right-click a packet → **Follow → TCP Stream**.

Expected: the DH `public_key` and the `certificate` are visible (they are public); the chat message appears only as base64 `ciphertext`.

## 6. MITM attacks

Stop everything (Ctrl+C, or `quit` in the clients). Each run uses four terminals, started in this order. Start the Wireshark capture first.

### Run A: passive eavesdropping

```bash
python src/server.py --port 9001                  # T1  real server
python attacks/mitm_proxy.py --mode watch         # T2  Mallory on port 9000
python src/client.py --username bob               # T3
python src/client.py --username alice             # T4
```

In Alice's terminal: `/dh bob`, then `/msg bob My bank PIN is 1234`

Expected: Mallory prints only `chat alice -> bob: ciphertext=...`. Save as `captures/01-passive.pcapng`.

### Run B: key substitution without certificates (attack succeeds)

```bash
python src/server.py --port 9001
python attacks/mitm_proxy.py --mode swap
python src/client.py --username bob --no-cert
python src/client.py --username alice --no-cert
```

In Alice's terminal: `/dh bob`, then `/msg bob My bank PIN is 1234`

Expected:
- Mallory: `*** READ alice -> bob: 'My bank PIN is 1234' ***`
- Bob: `[alice] My bank PIN is 1234  (signature verified)`. Bob does not notice.
- Alice's and Bob's `Session key (hex)` values are **different**: each shares a key with Mallory.
- Wireshark: Alice's `public_key` on the port 9000 stream differs from the one on the port 9001 stream.

Save as `captures/02-mitm-success.pcapng`.

### Run C: key substitution with certificates (attack blocked)

Same as run B, but without `--no-cert`:

```bash
python src/server.py --port 9001
python attacks/mitm_proxy.py --mode swap
python src/client.py --username bob
python src/client.py --username alice
```

Expected:
- Bob: `[security] Rejected DH public value from alice: signing key does not match certificate public key`
- Alice: `[msg] No session with bob yet. Run '/dh bob' first.`
- Mallory: no `READ` line.

Save as `captures/03-mitm-blocked.pcapng`.

### Run D: replay (blocked)

```bash
python src/server.py --port 9001
python attacks/mitm_proxy.py --mode replay
python src/client.py --username bob
python src/client.py --username alice
```

In Alice's terminal: `/dh bob`, then `/msg bob Transfer approved`. Wait two seconds.

Expected: Mallory prints `REPLAYING captured chat alice -> bob (seq 1)`; Bob accepts the message once, then prints `[security] Rejected message from alice: replayed message (seq 1, already accepted up to 1)`.

### Run E: automated attack summary

```bash
python tests/mitm_test.py
```

Expected: a table with every attack marked `BLOCKED`.

## How to read the result

| You see | Meaning |
|---|---|
| `*** READ ... ***` in Mallory's terminal | Attack succeeded |
| `[security] Rejected ...` in Bob's terminal | Attack blocked |
| Alice's and Bob's session keys differ | A MITM is in the path |
| Alice's and Bob's session keys match | No MITM; the channel is secure |

## Why run B succeeds and run C fails

Mallory replaces each DH value with her own. Alice's signature no longer fits, and Mallory can't sign as Alice, so she signs with her own key and puts her own signing key in the message. She forwards Alice's real certificate, because a forged one would fail the CA signature check.

- **Without certificates**, Bob only checks that the message is signed by the key inside it. It is, by Mallory's key, so he accepts it.
- **With certificates**, Bob also checks that the signing key matches the key in Alice's CA-signed certificate. Mallory's key doesn't, so the handshake is rejected and no session key exists for her to use.

## Screenshots for the report

Save in `docs/images/`. They fill the placeholders in `docs/mitm_analysis.md` section 5.

| File | Run | Must show |
|---|---|---|
| `01-passive-wireshark.png` | A | Follow TCP Stream with only base64 ciphertext |
| `02-mallory-reads.png` | B | Mallory's `READ` line and Bob's `(signature verified)` |
| `02-wireshark-port9000.png` | B | Alice's `public_key` on port 9000 |
| `02-wireshark-port9001.png` | B | The different, swapped `public_key` on port 9001 |
| `03-bob-rejects.png` | C | Bob's `[security] Rejected DH public value ...` line |
| `03-wireshark.png` | C | The handshake frames, with no chat session following |

## Troubleshooting

- `address already in use`: a server or proxy from the previous run is still open. Close it and start again.
- `[ca] No certificate for alice`: run `python src/ca.py init`.
- `No session with bob yet` in a normal run: run `/dh bob` first, and start Bob before Alice.
