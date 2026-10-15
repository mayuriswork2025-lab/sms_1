"""Diffie-Hellman key exchange primitives.

Two parties each generate a private key, exchange the resulting public
values over the network, and independently compute the same shared
secret. The private key and the shared secret are never transmitted.

The group parameters (P, G) are the well-known RFC 3526 Group 14
(2048-bit MODP) values -- a standard, publicly agreed-upon prime and
generator. Publishing them changes nothing about security: DH's
guarantee rests on the discrete-log problem being hard, not on the
prime being secret.
"""

import hashlib
import secrets

# RFC 3526, 2048-bit MODP Group 14.
P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD"
    "129024E088A67CC74020BBEA63B139B22514A08798E3404"
    "DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C"
    "245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406"
    "B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE"
    "45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD"
    "24CF5F83655D23DCA3AD961C62F356208552BB9ED529077"
    "096966D670C354E4ABC9804F1746C08CA18217C32905E46"
    "2E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF"
    "06F4C52C9DE2BCBF6955817183995497CEA956AE515D226"
    "1898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
G = 2


def generate_private_key() -> int:
    """Pick a random private exponent in [2, P-2]."""
    return secrets.randbelow(P - 3) + 2


def compute_public_key(private_key: int) -> int:
    """g^private_key mod p -- the value that gets sent to the peer."""
    return pow(G, private_key, P)


def compute_shared_secret(private_key: int, peer_public_key: int) -> int:
    """peer_public_key^private_key mod p -- equal on both sides."""
    return pow(peer_public_key, private_key, P)


def derive_session_key(shared_secret: int) -> bytes:
    """Hash the raw shared secret down to a fixed-size symmetric key.

    The raw DH output shouldn't be used directly as a cipher key (it's
    not uniformly distributed over all byte strings the way a good key
    should be); hashing it is the standard fix and gives phase 3 a
    ready-made AES-256 key.
    """
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
    return hashlib.sha256(secret_bytes).digest()


if __name__ == "__main__":
    alice_private = generate_private_key()
    alice_public = compute_public_key(alice_private)

    bob_private = generate_private_key()
    bob_public = compute_public_key(bob_private)

    print(f"Alice's public value:  {alice_public}")
    print(f"Bob's public value:    {bob_public}")

    alice_secret = compute_shared_secret(alice_private, bob_public)
    bob_secret = compute_shared_secret(bob_private, alice_public)

    print(f"Alice's shared secret: {alice_secret}")
    print(f"Bob's shared secret:   {bob_secret}")
    print(f"Match: {alice_secret == bob_secret}")

    print(f"Derived session key (hex): {derive_session_key(alice_secret).hex()}")
