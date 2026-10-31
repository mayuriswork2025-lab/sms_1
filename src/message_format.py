try:
    from src.protocol import default_protocol
except ImportError:
    from protocol import default_protocol


def build_login_message(username: str) -> bytes:
    payload = {
        "type": "login",
        "username": username,
    }
    return default_protocol.encode(payload)


def build_chat_message(
    sender: str,
    target: str,
    nonce: str,
    ciphertext: str,
    signature: str,
    seq: int = 0,
) -> bytes:
    payload = {
        "type": "chat",
        "sender": sender,
        "target": target,
        "seq": seq,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "signature": signature,
    }
    return default_protocol.encode(payload)


def build_dh_public_message(
    sender: str,
    target: str,
    public_key: int,
    signing_key: str,
    signature: str,
    certificate: str = "",
) -> bytes:
    payload = {
        "type": "dh_public",
        "sender": sender,
        "target": target,
        "public_key": str(public_key),
        "signing_key": signing_key,
        "signature": signature,
    }
    if certificate:
        payload["certificate"] = certificate
    return default_protocol.encode(payload)


def chat_signed_fields(sender: str, target: str, nonce: str, ciphertext: str, seq: int = 0) -> dict:
    """The chat fields covered by the sender's signature (everything except the signature).

    seq is a per-session message counter. Because it is signed, an attacker
    can't change it, and the receiver rejects any seq it has already seen,
    so a captured frame can't be replayed.
    """
    return {"type": "chat", "sender": sender, "target": target, "seq": seq, "nonce": nonce, "ciphertext": ciphertext}


def dh_public_signed_fields(
    sender: str,
    target: str,
    public_key: int | str,
    signing_key: str,
    certificate: str = "",
) -> dict:
    """The dh_public fields covered by the sender's signature."""
    fields = {
        "type": "dh_public",
        "sender": sender,
        "target": target,
        "public_key": str(public_key),
        "signing_key": signing_key,
    }
    if certificate:
        fields["certificate"] = certificate
    return fields
