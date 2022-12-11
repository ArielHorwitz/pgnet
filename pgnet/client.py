"""Base client class.

Use `BaseClient.async_connect` to connect to the server. Use `BaseClient.queue`
to send packets and set a callback when a response returns.

For extra security, use `verify_server_pubkey` when initializing a client.
"""

from typing import Optional, Callable, Any
from loguru import logger
import asyncio
from dataclasses import dataclass
import websockets
from websockets.client import WebSocketClientProtocol
from .util import (
    Packet,
    Response,
    Connection,
    Key,
    DEFAULT_PORT,
    DisconnectedError,
    REQUEST_GAME_DIR,
    REQUEST_JOIN_GAME,
    REQUEST_LEAVE_GAME,
    STATUS_OK,
)


ResponseCallback = Callable[[Response], Any]


@dataclass
class ClientConnection(Connection):
    """Subclass of Connection with a combined method for sending and receiving."""

    game: Optional[str] = None
    _websocket_busy: bool = False

    async def send_recv(self, packet: Packet) -> Response:
        """Send packet and receive response via Baseclass `send` and `recv`."""
        if self._websocket_busy:
            logger.warning(f"Packet is waiting for busy websocket... {packet}")
        while self._websocket_busy and self.websocket.open:
            await asyncio.sleep(0.1)
        self._websocket_busy = True
        try:
            await self.send(packet.serialize())
            response: str = await self.recv()
            return Response.deserialize(response)
        finally:
            self._websocket_busy = False


class BaseClient:
    """See module documentation for details."""

    def __init__(
        self,
        *,
        address: str = "localhost",
        port: int = DEFAULT_PORT,
        username: str = "guest",
        password: str = "",
        verify_server_pubkey: Optional[str] = None,
        on_connection: Optional[Callable[[bool], Any]] = None,
        on_status: Optional[Callable[[str], Any]] = None,
        on_game: Optional[Callable[[Optional[str]], Any]] = None,
    ):
        """See module documentation for details.

        Args:
            address: Server IP address
            port: Server port number
            username: The user's username.
            password: The user's password.
            verify_server_pubkey: If set, will compare against the public
                key of the server and disconnect if it's public key does
                not match.
            on_connection: Callback for when connecting or disconnecting.
            on_status: Callback for when client's status changes.
            on_game: Callback for when joining or leaving a game.
        """
        self._key: Key = Key()
        self._status: str = "New client."
        self._server_connection: Optional[WebSocketClientProtocol] = None
        self._connected: bool = False
        self._do_close: bool = False
        self._packet_queue: list[tuple[Packet, ResponseCallback]] = []
        self._game: Optional[str] = None
        self.address: str = address
        self.port: int = port
        self.username: str = username
        self.password: str = password
        self.verify_server_pubkey: Optional[str] = verify_server_pubkey
        self.on_connection = on_connection
        self.on_status = on_status
        self.on_game = on_game

    async def async_connect(self):
        """Connect to a server.

        Allows the handshake to fully populate a ClientConnection, which may
        then be used to process the packet queue. The client only considers
        itself connected when the packet queue can be processed.
        """
        if self._server_connection is not None:
            raise RuntimeError("Cannot open more than one connection per client.")
        full_address = f"{self.address}:{self.port}"
        self._server_connection = websockets.connect(f"ws://{full_address}")
        self._set_status(f"Connecting to {full_address}...", logger.info)
        connection: Optional[ClientConnection] = None
        try:
            try:
                websocket = await self._server_connection
            except OSError as e:
                logger.debug(f"{e=}")
                raise DisconnectedError("Failed to call server.")
            connection = ClientConnection(websocket)
            self._set_status("Logging in...", logger.info)
            await self._handle_handshake(connection)
            self._set_connection(True)
            self._set_status(f"Connected to: {connection.remote}", logger.info)
            await self._handle_user_connection(connection)
        except DisconnectedError as e:
            logger.debug(f"{e=}")
            self._set_status(f"Disconnected: {e.args[0]}")
        finally:
            if connection:
                await connection.close()
            self._set_connection(False)
            self._server_connection = None
            logger.info(f"Connection terminated {self}")

    @property
    def connected(self) -> bool:
        """If we are connected to the server."""
        return self._connected

    def close(self):
        """Close the connection."""
        self._do_close = True

    @property
    def status(self) -> str:
        """Latest status of the client."""
        return self._status

    def get_games_dir(self, callback: Callable, /):
        """Get the games directory from the server and pass the response to callback."""
        self.send(Packet(REQUEST_GAME_DIR), callback, do_next=True)

    def join_game(self, game_name: str, /):
        """Request from the server to join a game."""
        self.send(Packet(REQUEST_JOIN_GAME, dict(name=game_name)), do_next=True)

    def leave_game(self):
        """Request from the server to leave the game."""
        self.send(Packet(REQUEST_LEAVE_GAME), do_next=True)

    @property
    def game(self) -> Optional[str]:
        """Currently joined game."""
        return self._game

    def send(
        self,
        packet: Packet,
        callback: Optional[ResponseCallback] = None,
        /,
        do_next: bool = False,
    ):
        """Add a packet to the queue. Optionally configure a callback for the response.

        Callbacks are not ensured, as a queue can be arbitrarily cleared using
        `BaseClient.flush_queue`.
        """
        if not self._connected:
            logger.warning(f"Cannot queue packets while disconnected: {packet}")
            return
        packet_count = len(self._packet_queue)
        if packet_count >= 5:
            logger.warning(f"{packet_count} packets pending, adding: {packet}")
        packet_callback = (packet, callback)
        if do_next:
            self._packet_queue.insert(0, packet_callback)
        else:
            self._packet_queue.append(packet_callback)

    def flush_queue(self):
        """Remove any packets and their respective callbacks from the packet queue."""
        if self._packet_queue:
            logger.debug(f"Discarding messages:  {self._packet_queue}")
        self._packet_queue = []

    async def _handle_handshake(self, connection: ClientConnection):
        """Handle a new connection's handshake sequence. Modifies the connection object.

        First trade public keys and assign the connection's `tunnel`. Then log in
        with our username.
        """
        # Trade public keys
        packet = Packet("key_trade", dict(pubkey=self._key.pubkey))
        response = await connection.send_recv(packet)
        pubkey = response.payload.get("pubkey")
        if not pubkey or not isinstance(pubkey, str):
            raise DisconnectedError("Missing public key string from server.")
        if self.verify_server_pubkey:
            if pubkey != self.verify_server_pubkey:
                raise DisconnectedError("Unverified server public key.")
            logger.debug(f"Server pubkey verified: {pubkey=}")
        connection.tunnel = self._key.get_tunnel(pubkey)
        logger.debug(f"Assigned tunnel: {connection}")
        # Authenticate
        payload = dict(username=self.username, password=self.password)
        packet = Packet("handshake", payload)
        response = await connection.send_recv(packet)
        if response.status != STATUS_OK:
            m = response.message
            logger.info(m)
            raise DisconnectedError(m)

    async def _handle_user_connection(self, connection: ClientConnection):
        """Handle the connection after handshake - process the packet queue."""
        self._do_close = False
        while not self._do_close:
            # Wait for queued packets
            if not self._packet_queue:
                await asyncio.sleep(0.01)
                continue
            # Send and callback with response
            packet, callback = self._packet_queue.pop(0)
            response = await connection.send_recv(packet)
            if response.status != STATUS_OK:
                logger.info(f"Status code: {response.debug_repr}")
            if callback:
                callback(response)
            # Disconnect if alerted
            if response.disconnecting:
                logger.info(f"Disconnected.\n{packet}\n{response.debug_repr}")
                raise DisconnectedError(response.message)
            # Handle changing games
            self._set_game(response.game)
        raise DisconnectedError("Client closed connection.")

    def _set_status(self, status: str, logger: Optional[Callable] = None):
        """Set the client status message with associated callback."""
        self._status = status
        if logger:
            logger(status)
        if self.on_status:
            self.on_status(status)

    def _set_connection(self, set_as: bool, /):
        """Set the client connection status with associated callback."""
        if self._connected == set_as:
            return
        self._connected = set_as
        if self.on_connection:
            self.on_connection(set_as)

    def _set_game(self, game_name: Optional[str]):
        """Set the client game name with associated callback."""
        if game_name != self._game:
            if game_name is None:
                self._set_status(f"Left game: {self._game}")
            else:
                self._set_status(f"Joined game: {game_name}")
            self._game = game_name
            if self.on_game:
                self.on_game(game_name)

    def __repr__(self) -> str:
        """Object repr."""
        return (
            f"<{self.__class__.__qualname__} "
            f"address={self.address!r} port={self.port!r} "
            f"{id(self)}>"
        )
