# Phase 2: Diffie-Hellman key exchange, explained simply

## The problem

Alice and Bob only have a channel that runs through a server (and maybe an
eavesdropper) who can read every message. How do they agree on a secret
number without ever sending that secret itself?

## The pieces

| Symbol | Public or private? | What it is |
|---|---|---|
| `p`, `g` | Public | Agreed in advance, baked into the code on both sides |
| `a`, `b` | Private | Alice's and Bob's own random numbers, never shared |
| `A`, `B` | Public | `A = g^a mod p`, `B = g^b mod p` — the values actually sent |

`p` and `g` being public doesn't help an attacker — security comes
entirely from `a` and `b` staying secret. The exponent is the private
part; `g` and `p` are just the fixed rules of the game.

## The exchange

Alice sends `A`, Bob sends `B` (through the server). That's it — `a`, `b`,
and the final secret never touch the network.

## Landing on the same secret

No verification step happens here. Each side just combines their *own*
private number with the *other* side's public value:

```
Alice: B^a mod p = (g^b)^a mod p = g^(ba) mod p
Bob:   A^b mod p = (g^a)^b mod p = g^(ab) mod p
```

`ba == ab`, so both land on the same number — without either side ever
learning the other's private key. `dh.py` then hashes that raw number
(SHA-256) into a clean 256-bit session key for phase 3's AES to use.

## The catch

No verification step means DH can't tell a real public value from one an
attacker swapped in mid-flight. A malicious server could hand Alice and
Bob each its own public value and complete two separate handshakes,
undetected. That's the classic DH MITM weakness — exactly what phase 5's
adversarial test targets, and why phases 3–4 add signatures and a CA.

## Where this lives in the code

- `src/dh.py` — the math. Run `python src/dh.py` for a local demo.
- `src/client.py` — `/dh <username>` and `_handle_dh_public` wire it into
  a real two-client handshake.
- `src/server.py` — `_handle_dh_public` relays the message; it never sees
  `a`, `b`, or the shared secret.

See `docs/protocol.md` for the wire-level message format and sequence.
