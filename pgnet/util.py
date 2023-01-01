"""Common constants and classes."""

from typing import Optional, Callable
from loguru import logger
import asyncio
import functools
import arrow
import json
from dataclasses import dataclass, field
import websockets
from websockets.legacy.protocol import WebSocketCommonProtocol as WebSocket
import nacl.public
from nacl.encoding import Base64Encoder


DEFAULT_PORT = 38929
ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "localhostadmin"
REQUEST_GAME_DIR = "__pgnet__.game_dir"
REQUEST_JOIN_GAME = "__pgnet__.join_game"
REQUEST_LEAVE_GAME = "__pgnet__.leave_game"
REQUEST_CREATE_GAME = "__pgnet__.create_game"
REQUEST_HEARTBEAT_UPDATE = "__pgnet__.heartbeat_update"
STATUS_OK = 0
STATUS_BAD = 1
STATUS_UNEXPECTED = 2


class DisconnectedError(Exception):
    """Raised when a connection should no longer be open.

    It is expected that the cause of the error is passed as the first
    argument as a string.
    """
    pass


class CipherError(Exception):
    """Raised when failing to encrypt plaintext or decrypt ciphertext."""
    pass


@dataclass
class Packet:
    """The dataclass used to send messages from client to server.

    Payload must be JSON-able.
    """

    message: str
    payload: dict = field(default_factory=dict, repr=False)
    created_on: Optional[str] = None
    username: Optional[str] = None
    disconnecting: bool = False

    def __post_init__(self):
        """Set creation date."""
        self.created_on = self.created_on or arrow.now().for_json()

    def serialize(self) -> dict:
        """Convert into a string."""
        data = {k: getattr(self, k) for k in self.__dataclass_fields__.keys()}
        try:
            return json.dumps(data)
        except Exception as e:
            m = f"Failed to serialize. See above exception.\n{self.debug_repr}"
            raise TypeError(m) from e

    @classmethod
    def deserialize(cls, raw_data: str, /) -> "Packet":
        """Convert a string into a Packet."""
        try:
            data = json.loads(raw_data)
        except Exception as e:
            m = f"Failed to deserialize. See above exception.\n{raw_data=}"
            raise TypeError(m) from e
        return cls(**data)

    @property
    def debug_repr(self) -> str:
        """Repr with more data."""
        return f"{self!r}+{self.payload}"


@dataclass
class Response:
    """The dataclass used to respond from server to client.

    Payload must be JSON-able.
    """

    message: str
    payload: dict = field(default_factory=dict, repr=False)
    status: int = STATUS_OK
    created_on: Optional[str] = None
    disconnecting: bool = False
    game: Optional[str] = None

    def __post_init__(self):
        """Set creation date."""
        self.created_on = self.created_on or arrow.now().for_json()

    def serialize(self) -> dict:
        """Convert into a string."""
        data = {k: getattr(self, k) for k in self.__dataclass_fields__.keys()}
        try:
            return json.dumps(data)
        except Exception as e:
            m = f"Failed to serialize. See above exception.\n{self.debug_repr}"
            raise TypeError(m) from e

    @classmethod
    def deserialize(cls, raw_data: str, /) -> "Response":
        """Convert a string into a Response."""
        try:
            data = json.loads(raw_data)
        except Exception as e:
            m = f"Failed to deserialize. See above exception.\n{raw_data=}"
            raise TypeError(m) from e
        return cls(**data)

    @property
    def debug_repr(self) -> str:
        """Repr with more data."""
        return f"{self!r}+{self.payload}"


class Tunnel:
    """A shared key for end to end encryption of strings.

    Given a personal private key and an external public key, will encrypt
    and decrypt string messages. Tunnels should be obtained via a `Key` class.
    See `Key` class  documentation for more details.
    """
    def __init__(self, priv: nacl.public.PrivateKey, pubkey: str):
        """See class documentation for more details."""
        pub = nacl.public.PublicKey(pubkey.encode(), encoder=Base64Encoder)
        self._box = nacl.public.Box(priv, pub)
        self._pubkey = pubkey  # For the repr

    def encrypt(self, plaintext: str) -> str:
        """Encrypt a message."""
        try:
            encrypted_message = self._box.encrypt(
                plaintext.encode(),
                encoder=Base64Encoder,
            )
            ciphertext = encrypted_message.decode()
            return ciphertext
        except Exception as e:
            raise CipherError("Failed to encrypt the plaintext.") from e

    def decrypt(self, ciphertext: str) -> str:
        """Decrypt a message."""
        try:
            ciphertext = ciphertext.encode()
            plaintext = self._box.decrypt(ciphertext, encoder=Base64Encoder).decode()
            return plaintext
        except Exception as e:
            raise CipherError("Failed to decrypt the ciphertext.") from e

    def __repr__(self) -> str:
        """Object repr."""
        return f"<{self.__class__.__qualname__} pubkey={self._pubkey[:6]}...>"


class Key:
    """A key manager for end to end encryption of strings.

    Each instance of this class represents a private-public key pair. It can
    also generate Tunnels (shared keys) with other public keys by using
    `Key.get_tunnel`. These let you encrypt and decrypt messages with other
    public keys.

    The Key and Tunnel classes are thin wrappers around pynacl's PrivateKey
    and Box classes that can handle public keys and messages as strings. If
    this is not required, it is recommended to use pynacl's API directly.
    """

    def __init__(self):
        """See class documentation for details."""
        self._private_key = nacl.public.PrivateKey.generate()
        self._public_key = self._private_key.public_key
        self._tunnels: dict[str, Tunnel] = {}

    @property
    def pubkey(self) -> str:
        """The public key in string format."""
        return self._public_key.encode(encoder=Base64Encoder).decode()

    def get_tunnel(self, pubkey: str) -> Tunnel:
        """Get a Tunnel for the given pubkey."""
        tunnel = self._tunnels.get(pubkey)
        if not tunnel:
            tunnel = self._tunnels[pubkey] = Tunnel(self._private_key, pubkey)
        return tunnel

    def __repr__(self) -> str:
        """Object repr."""
        return f"<{self.__class__.__qualname__} pubkey={self.pubkey}>"


@dataclass
class Connection:
    """A wrapper for a websockets' websocket with end to end encryption.

    Methods will raise a DisconnectedError with the reason for failing to
    communicate with the websocket.
    """

    websocket: WebSocket = field(repr=False)
    tunnel: Optional[Tunnel] = None
    remote: str = ""

    def __post_init__(self):
        """Set the remote from the websocket."""
        address, port, *_ = self.websocket.remote_address
        if address == "::1":
            address = "localhost"
        self.remote = f"{address}:{port}"

    @staticmethod
    def _exception_disconnect(f: Callable, /):
        """Decorator raising DisconnecetedError on connection or cipher exceptions."""
        @functools.wraps(f)
        async def wrapper(*args, **kwargs):
            try:
                return await f(*args, **kwargs)
            except websockets.exceptions.ConnectionClosed as e:
                raise DisconnectedError("Connection closed.") from e
            except asyncio.exceptions.TimeoutError as e:
                raise DisconnectedError("Connection timed out.") from e
            except CipherError as e:
                raise DisconnectedError("Failed to encrypt message.") from e
        return wrapper

    @_exception_disconnect
    async def send(self, message: str, /, *, timeout: float = 5.0):
        """Send a string to `self.websocket`, encrypt if `self.tunnel` is set."""
        if self.tunnel:
            message = self.tunnel.encrypt(message)
        await asyncio.wait_for(self.websocket.send(message), timeout=timeout)

    @_exception_disconnect
    async def recv(self, *, timeout: float = 5.0) -> str:
        """Receive a string from `self.websocket`, decrypt if `self.tunnel` is set."""
        message: str = await asyncio.wait_for(self.websocket.recv(), timeout=timeout)
        if self.tunnel:
            message = self.tunnel.decrypt(message)
        return message

    async def close(self):
        """Close the websocket."""
        await self.websocket.close()


class BaseGame:
    """Subclass this to implement the back end and pass to server as the game.

    If a game is not persistent (default), it will be deleted by the server
    when all users have left. However if it is persistent, it will continue to
    exists after all users have left, and it can save/load game data on disk
    when the server shuts down and restarts.
    """

    persistent: bool = False
    """Set as persistent to allow the game to persist even without players."""
    heartbeat_rate: float = 10
    """How many times per second the client should check for updates."""

    def __init__(self, name: str, save_string: Optional[str] = None):
        """Initialized with the name given by the user that created the game.

        Args:
            name: Game name, as given by the user that opened the game.
            save_string: Game data loaded from disk from last server session.
        """
        pass

    def user_joined(self, username: str):
        """Called when a user joins the game."""
        pass

    def user_left(self, username: str):
        """Called when a user leaves the game."""
        pass

    def handle_packet(self, packet: Packet) -> Response:
        """Packet handling for heartbeat updates and game requests.

        Prefer to override `BaseGame.handle_game_packet` and
        `BaseGame.handle_heartbeat`.
        """
        if packet.message == REQUEST_HEARTBEAT_UPDATE:
            return self.handle_heartbeat(packet)
        return self.handle_game_packet(packet)

    def handle_game_packet(self, packet: Packet) -> Response:
        """Override this method to implement packet handling."""
        return Response(
            f"No packet handling configured for {self.__class__.__qualname__}",
            status=STATUS_UNEXPECTED,
        )

    def handle_heartbeat(self, packet: Packet) -> Response:
        """Override this method to implement heartbeat updates."""
        return Response(
            f"No heartbeat update configured for {self.__class__.__qualname__}"
        )

    def get_save_string(self) -> str:
        """Override this method to save game data to disk.

        This method is called by the server when shutting down. In the next
        session, the server will recreate the game with this string passed in
        the __init__.
        """
        return ""

    def update(self):
        """Called on an interval by the server."""
        pass


def enable_logging(enable: bool = True, /):
    """Enable/disable logging from the pgnet library."""
    if enable:
        logger.enable("pgnet")
    else:
        logger.disable("pgnet")
