import socket
import threading
from typing import Dict, Tuple

try:
    from src.protocol import MessageReader, ProtocolDecodeError, default_protocol
    from src.utils import log_message
except ImportError:
    from protocol import MessageReader, ProtocolDecodeError, default_protocol
    from utils import log_message

HOST = "127.0.0.1"
PORT = 9000
LISTEN_BACKLOG = 5
RECV_BUFFER_SIZE = 4096
SOCKET_TIMEOUT_SECONDS = 1.0
LOG_PREVIEW_CHARS = 32

class ClientRegistry:
    """Thread-safe mapping of connected sockets to usernames."""

    def __init__(self) -> None:
        self._clients: Dict[socket.socket, str] = {}
        self._lock = threading.Lock()

    def register(self, connection: socket.socket, requested_username: str | None) -> str:
        with self._lock:
            username = requested_username or f"user_{len(self._clients) + 1}"
            self._clients[connection] = username
        return username

    def remove(self, connection: socket.socket) -> str | None:
        with self._lock:
            return self._clients.pop(connection, None)

    def find(self, username: str) -> socket.socket | None:
        with self._lock:
            for connection, name in self._clients.items():
                if name == username:
                    return connection
        return None


class ChatServer:
    """Accepts clients and relays targeted messages between them."""

    def __init__(self, host: str = HOST, port: int = PORT) -> None:
        self.host = host
        self.port = port
        self.registry = ClientRegistry()

    def start(self) -> None:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(LISTEN_BACKLOG)
        log_message(f"Server started on {self.host}:{self.port}")

        try:
            while True:
                connection, address = server_socket.accept()
                thread = threading.Thread(target=self.handle_client, args=(connection, address), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            log_message("Server shutting down...")
        finally:
            server_socket.close()

    def handle_client(self, connection: socket.socket, address: Tuple[str, int]) -> None:
        username = None
        # TCP is a byte stream, not a message stream: one recv() can return part
        # of a message, several messages, or both. MessageReader buffers raw
        # bytes and only hands back frames once a full delimiter-terminated
        # message has arrived.
        reader = MessageReader(default_protocol)
        should_disconnect = False
        try:
            connection.settimeout(SOCKET_TIMEOUT_SECONDS)
            while True:
                try:
                    raw = connection.recv(RECV_BUFFER_SIZE)
                except socket.timeout:
                    continue
                except OSError:
                    break

                if not raw:
                    break

                for frame in reader.feed(raw):
                    try:
                        payload = reader.decode(frame)
                    except ProtocolDecodeError:
                        log_message(f"Invalid message from {address}: {frame!r}")
                        continue

                    message_type = payload.get("type")

                    if message_type == "login":
                        username = self.handle_login(connection, address, payload)
                    elif message_type == "chat":
                        self.relay(username, payload, "Chat message")
                    elif message_type == "dh_public":
                        self.relay(username, payload, "DH public value")
                    elif message_type == "leave":
                        should_disconnect = True
                        break

                if should_disconnect:
                    break
        finally:
            self.disconnect(connection)

    def handle_login(self, connection: socket.socket, address: Tuple[str, int], payload: dict) -> str:
        username = self.registry.register(connection, payload.get("username"))
        log_message(f"New client connected: {username} from {address}")

        welcome = default_protocol.encode({
            "type": "system",
            "sender": "server",
            "message": f"Welcome, {username}! You are now connected."
        })
        connection.sendall(welcome)
        return username

    def relay(self, username: str | None, payload: dict, label: str) -> None:
        """Forward a peer-targeted payload to its target, unchanged."""
        sender = payload.get("sender") or username or "anonymous"
        target = payload.get("target")

        if payload.get("type") == "chat":
            # The server only ever sees ciphertext; logging it shows what an
            # eavesdropper on the relay would see.
            ciphertext = payload.get("ciphertext", "")
            preview = ciphertext[:LOG_PREVIEW_CHARS] + ("..." if len(ciphertext) > LOG_PREVIEW_CHARS else "")
            log_message(f"{label} from {sender} to {target}: ciphertext={preview}")
        else:
            log_message(f"{label} from {sender} for {target}")

        target_connection = self.registry.find(target) if target else None
        if target_connection is None:
            log_message(f"{label} delivery failed: {target} is not connected")
            return

        target_connection.sendall(default_protocol.encode(payload))

    def disconnect(self, connection: socket.socket) -> None:
        username = self.registry.remove(connection)
        if username:
            log_message(f"Client disconnected: {username}")
        connection.close()


if __name__ == "__main__":
    ChatServer().start()
