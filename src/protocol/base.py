from abc import ABC, abstractmethod
from typing import Any, Dict

Payload = Dict[str, Any]


class ProtocolDecodeError(ValueError):
    """Raised when a raw frame cannot be decoded into a payload."""


class WireProtocol(ABC):
    """Defines how message payloads are serialized to bytes and framed on the wire.

    Implementations own both the encoding (e.g. JSON, a binary struct format,
    an encrypted envelope) and the delimiter used to mark message boundaries,
    so callers never need to know which scheme is in use.
    """

    @property
    @abstractmethod
    def delimiter(self) -> bytes:
        """Byte sequence marking the end of one encoded message frame."""

    @abstractmethod
    def encode(self, payload: Payload) -> bytes:
        """Serialize a payload dict into bytes, including the trailing delimiter."""

    @abstractmethod
    def decode(self, raw: bytes) -> Payload:
        """Deserialize one delimiter-stripped frame back into a payload dict.

        Raises ProtocolDecodeError if the frame is malformed.
        """
