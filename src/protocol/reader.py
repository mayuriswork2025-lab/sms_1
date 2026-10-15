from typing import Iterator

from .base import WireProtocol


class MessageReader:
    """Buffers raw socket bytes and yields complete, delimiter-framed message frames.

    TCP has no concept of message boundaries: a single recv() call may return
    a partial frame, several frames, or both. Feeding all incoming bytes
    through one MessageReader per connection keeps that assembly logic in a
    single place regardless of which WireProtocol is in use.
    """

    def __init__(self, protocol: WireProtocol) -> None:
        self._protocol = protocol
        self._buffer = b""

    def feed(self, data: bytes) -> Iterator[bytes]:
        self._buffer += data
        delimiter = self._protocol.delimiter

        while delimiter in self._buffer:
            raw, self._buffer = self._buffer.split(delimiter, 1)
            if raw:
                yield raw

    def decode(self, raw: bytes):
        return self._protocol.decode(raw)
