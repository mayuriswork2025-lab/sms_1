import json

from .base import Payload, ProtocolDecodeError, WireProtocol


class JSONProtocol(WireProtocol):
    """Newline-delimited JSON wire format. The default for this project."""

    @property
    def delimiter(self) -> bytes:
        return b"\n"

    def encode(self, payload: Payload) -> bytes:
        return json.dumps(payload).encode("utf-8") + self.delimiter

    def decode(self, raw: bytes) -> Payload:
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ProtocolDecodeError(str(exc)) from exc
