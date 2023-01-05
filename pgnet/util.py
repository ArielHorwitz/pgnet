"""Common utilities for pgnet."""

from typing import Optional, Callable
from loguru import logger
import asyncio
import enum
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


class REQUEST:
    """Strings used as a message in `Packet` for common requests.

    It is recommended to use the `pgnet.Client` API instead of these. `Game` classes
    should avoid using the string values here as messages in a `Packet` - such packets
    will be specially handled by the server.
    """

    GAME_DIR: str = "__pgnet__.game_dir"
    """Request the games directory."""
    JOIN_GAME: str = "__pgnet__.join_game"
    """Request to join a game."""
    LEAVE_GAME: str = "__pgnet__.leave_game"
    """Request to leave a game."""
    CREATE_GAME: str = "__pgnet__.create_game"
    """Request to create and join a game."""
    HEARTBEAT_UPDATE: str = "__pgnet__.heartbeat_update"
    """Request a heartbeat update from the game."""


@enum.unique
class Status(enum.IntEnum):
    """Integer status codes for a `Response` to client requests.

    These are used internally by `pgnet.Server`. It is possible but not required to use
    these in games and clients.
    """

    OK: int = 0
    """Indicates success without issues."""
    BAD: int = 1
    """Indicates fatal error."""
    UNEXPECTED: int = 2
    """Indicates an issue."""


class DisconnectedError(Exception):
    """Raised when a connection has been or should be closed.

    The cause of the error is passed as the first argument as a string.
    """
    pass


class CipherError(Exception):
    """Raised when failing to encrypt plaintext or decrypt ciphertext."""
    pass


@dataclass
class Packet:
    """The dataclass used to send messages from client to server.

    Clients need only concern themselves with `Packet.message` and `Packet.payload`.
    """

    message: str
    """Message text."""
    payload: dict = field(default_factory=dict, repr=False)
    """Dictionary of arbitrary data. Must be JSON-able."""
    created_on: Optional[str] = None
    """The creation time of the packet."""
    username: Optional[str] = field(default=None, repr=False)
    """Used by the server for identification.

    Setting this on the client side has no effect.
    """

    def __post_init__(self):
        """Set creation date."""
        self.created_on = self.created_on or arrow.now().for_json()

    def serialize(self) -> str:
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

    Games and Clients need only concern themselves with `Response.message`,
    `Response.payload`, and `Response.status`.
    """

    message: str
    """Message text."""
    payload: dict = field(default_factory=dict, repr=False)
    """Dictionary of arbitrary data. Must be JSON-able."""
    status: int = Status.OK
    """`Status` code for handling the request that this is responding to."""
    created_on: Optional[str] = None
    """The creation time of the packet."""
    disconnecting: bool = field(default=False, repr=False)
    """Used by the server to notify the client that the connection is being closed."""
    game: Optional[str] = field(default=None, repr=False)
    """Used by the server to notify the client of their current game name."""

    def __post_init__(self):
        """Set creation date."""
        self.created_on = self.created_on or arrow.now().for_json()

    def serialize(self) -> str:
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
        return (
            f"{self!r}(game={self.game!r}, disconnecting={self.disconnecting})"
            f"+{self.payload}"
        )


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

    Each instance of this class represents a private-public key pair. It can also
    generate a `Tunnel` (shared key) with other public keys by using `Key.get_tunnel`.
    These let you encrypt and decrypt messages with other public keys.

    The `Key` and `Tunnel` classes are thin wrappers around `pynacl`'s `PrivateKey` and
    `Box` classes that can handle public keys and messages as strings.
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
        """Get a `Tunnel` for a given pubkey."""
        tunnel = self._tunnels.get(pubkey)
        if not tunnel:
            tunnel = self._tunnels[pubkey] = Tunnel(self._private_key, pubkey)
        return tunnel

    def __repr__(self) -> str:
        """Object repr."""
        return f"<{self.__class__.__qualname__} pubkey={self.pubkey}>"


@dataclass
class Connection:
    """Wrapper for `websocket` with end to end encryption.

    Methods will raise a `DisconnectedError` with the reason for failing to communicate
    with the websocket.
    """

    websocket: WebSocket = field(repr=False)
    """The websocket of this connection."""
    tunnel: Optional[Tunnel] = None
    """The `Tunnel` assigned for this connection.

    If set, packets sent and responses received will be encrypted and decrypted using
    the tunnel.
    """
    remote: str = ""
    """Full address of the other end of the connection."""

    def __post_init__(self):
        """Set the remote from the websocket."""
        address, port, *_ = self.websocket.remote_address
        if address == "::1":
            address = "localhost"
        self.remote = f"{address}:{port}"

    @staticmethod
    def _exception_disconnect(f: Callable, /):
        """Decorator raising `DisconnecetedError` on connection or cipher exceptions."""
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
        """Send a string to `Connection.websocket`.

        Will be encrypted using `Connection.tunnel` if set.
        """
        if self.tunnel:
            message = self.tunnel.encrypt(message)
        await asyncio.wait_for(self.websocket.send(message), timeout=timeout)

    @_exception_disconnect
    async def recv(self, *, timeout: float = 5.0) -> str:
        """Receive a string from `Connection.websocket`.

        Will be decrypted using `Connection.tunnel` if set.
        """
        message: str = await asyncio.wait_for(self.websocket.recv(), timeout=timeout)
        if self.tunnel:
            message = self.tunnel.decrypt(message)
        return message

    async def close(self):
        """Close the websocket."""
        await self.websocket.close()


class Game:
    """Subclass to implement game logic.

    This class should not be initialized directly, it is initialized by the server.
    """

    persistent: bool = False
    """Set as persistent to allow the game to persist even without players.

    This is required for saving and loading (see also: `Game.get_save_string`).
    """
    heartbeat_rate: float = 10
    """How many times per second the client should check for updates.

    See `Game.handle_heartbeat`.
    """

    def __init__(self, name: str, save_string: Optional[str] = None):
        """The server initializes this class for every game started.

        Args:
            name: Game instance name.
            save_string: Game data loaded from disk from last server session as given by
                `Game.get_save_string`.
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

        Most use cases should override `Game.handle_game_packet` and
        `Game.handle_heartbeat` instead of this method.
        """
        if packet.message == REQUEST.HEARTBEAT_UPDATE:
            return self.handle_heartbeat(packet)
        return self.handle_game_packet(packet)

    def handle_game_packet(self, packet: Packet) -> Response:
        """Override this method to implement packet handling.

        See also: `pgnet.Client.send`.
        """
        return Response(
            f"No packet handling configured for {self.__class__.__qualname__}",
            status=Status.UNEXPECTED,
        )

    def handle_heartbeat(self, packet: Packet) -> Response:
        """Override this method to implement heartbeat updates.

        See also: `Game.heartbeat_rate`, `pgnet.Client.heartbeat_payload`,
        `pgnet.Client.on_heartbeat`.
        """
        return Response(
            f"No heartbeat update configured for {self.__class__.__qualname__}"
        )

    def get_save_string(self) -> str:
        """Override this method to save game data to disk.

        If `Game.persistent`, this method is called by the server periodically and when
        shutting down. In the next session, the server will recreate the game with this
        string passed as *`save_string`* to `Game.__init__`.

        .. note:: `pgnet.Server` must be configured to enable saving and loading.
        """
        return ""

    def update(self):
        """Called on an interval by the server.

        Override this method to implement background game logic tasks.
        """
        pass


def enable_logging(enable: bool = True, /):
    """Enable/disable logging from the PGNet library."""
    if enable:
        logger.enable("pgnet")
    else:
        logger.disable("pgnet")


__all__ = (
    "Game",
    "Packet",
    "Response",
    "REQUEST",
    "Status",
    "Tunnel",
    "Key",
    "Connection",
    "CipherError",
    "DisconnectedError",
    "enable_logging",
)
