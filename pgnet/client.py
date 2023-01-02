"""Home of the `BaseClient` class."""

from typing import Optional, Callable, Any, Type
from loguru import logger
import asyncio
from dataclasses import dataclass
import websockets
from websockets.client import WebSocketClientProtocol
from .server import BaseServer
from .util import (
    Packet,
    Response,
    Connection,
    Key,
    BaseGame,
    DEFAULT_PORT,
    DisconnectedError,
    REQUEST_GAME_DIR,
    REQUEST_CREATE_GAME,
    REQUEST_JOIN_GAME,
    REQUEST_LEAVE_GAME,
    REQUEST_HEARTBEAT_UPDATE,
    STATUS_OK,
)


DEFAULT_HEARTBEAT_RATE = 10
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
    """The client that manages communication with the server.

    Use `BaseClient.async_connect` to connect to the server.

    Once connected, use `BaseClient.get_games_dir`, `BaseClient.create_game`,
    `BaseClient.join_game`, and `BaseClient.leave_game` to join or leave a game.

    It is possible to bind callbacks to client events by subclassing and overriding or
    by setting `BaseClient.on_connection`, `BaseClient.on_status`, and
    `BaseClient.on_game`.

    When in game (`BaseClient.game` is not *None*), use `BaseClient.send` to send a
    `pgnet.Packet` to `pgnet.BaseGame.handle_game_packet` and receive a
    `pgnet.Response`.

    For extra security, use `verify_server_pubkey` when initializing a client
    (not required).
    """

    def __init__(self):  # noqa: D107
        self._key: Key = Key()
        self._status: str = "New client."
        self._server_connection: Optional[WebSocketClientProtocol] = None
        self._connected: bool = False
        self._do_close: bool = False
        self._packet_queue: list[tuple[Packet, ResponseCallback]] = []
        self._game: Optional[str] = None
        self._heartbeat_interval = 1 / DEFAULT_HEARTBEAT_RATE

    async def async_connect(
        self,
        *,
        address: str,
        username: str,
        password: str = "",
        port: int = DEFAULT_PORT,
        verify_server_pubkey: Optional[str] = None,
    ):
        """Connect to a server.

        This procedure will automatically create an end-to-end encrypted
        connection (optionally verifying the public key first), and authenticate
        the username and password. Only after succesfully completing these steps
        will the client be considered connected.

        Args:
            address: Server IP address.
            username: The user's username.
            password: The user's password.
            port: Server port number.
            verify_server_pubkey: If set, will compare against the public
                key of the server and disconnect if it's public key does
                not match.
        """
        if self._server_connection is not None:
            raise RuntimeError("Cannot open more than one connection per client.")
        full_address = f"{address}:{port}"
        self._server_connection = websockets.connect(
            f"ws://{full_address}",
            close_timeout=1,
        )
        self._set_status(f"Connecting to {full_address}...", logger.info)
        connection: Optional[ClientConnection] = None
        heartbeat: Optional[asyncio.Task] = None
        try:
            try:
                websocket = await self._server_connection
            except OSError as e:
                logger.debug(f"{e=}")
                raise DisconnectedError("Failed to call server.")
            connection = ClientConnection(websocket)
            self._set_status("Logging in...", logger.info)
            await self._handle_handshake(
                connection,
                username,
                password,
                verify_server_pubkey,
            )
            self._set_connection(True)
            self._set_status(
                f"Logged in as {username} @ {connection.remote}",
                logger.info,
            )
            heartbeat = asyncio.create_task(self._async_heartbeat())
            await self._handle_user_connection(connection)
        except DisconnectedError as e:
            logger.debug(f"{e=}")
            if connection:
                await connection.close()
            if heartbeat:
                heartbeat.cancel()
            self._set_connection(False)
            self._server_connection = None
            self._set_status(f"Disconnected: {e.args[0]}")
            logger.info(f"Connection terminated {self}")
            return
        logger.warning(f"Connection terminated without DisconnectedError {connection}")

    async def async_connect_localhost(
        self,
        game: Type[BaseGame],
        /,
        *,
        username: str = "Player",
        password: str = "",
        server_factory: Callable[[Any], BaseServer] = BaseServer,
    ):
        """A localhost alternative to `BaseClient.async_connect`.

          Creates a localhost server and connects to it. This allows to play and test
          locally without needing to run a separate process for the server. This server
          will *not* listen globally.

        Args:
            game: The `BaseGame` class that is required by the server.
            username: The user's name.
            password: The user's password.
            server_factory: Callable that returns a BaseServer instance. This can be
                used to pass custom arguments to the server initialization.
        """
        server: BaseServer = server_factory(
            game,
            listen_globally=False,
            require_user_password=False,
        )
        started = asyncio.Future()
        server_coro = server.async_run(on_start=lambda *a: started.set_result(1))
        server_task = asyncio.create_task(server_coro)
        server_task.add_done_callback(lambda *a: self.close())
        await asyncio.wait((server_task, started), return_when=asyncio.FIRST_COMPLETED)
        await self.async_connect(
            address="localhost",
            username=username,
            password=password,
            verify_server_pubkey=server.pubkey,
        )
        self.close()
        server.shutdown()

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

    def create_game(
        self,
        name: str,
        /,
        password: Optional[str] = None,
        *,
        callback: Optional[ResponseCallback] = None,
    ):
        """Request from the server to join a game."""
        payload = dict(name=name)
        if password:
            payload["password"] = password
        self.send(Packet(REQUEST_CREATE_GAME, payload), callback, do_next=True)

    def join_game(
        self,
        name: str,
        /,
        password: Optional[str] = None,
        *,
        callback: Optional[ResponseCallback] = None,
    ):
        """Request from the server to join a game."""
        payload = dict(name=name)
        if password:
            payload["password"] = password
        self.send(Packet(REQUEST_JOIN_GAME, payload), callback, do_next=True)

    def leave_game(
        self,
        *,
        callback: Optional[ResponseCallback] = None,
    ):
        """Request from the server to leave the game."""
        self.send(Packet(REQUEST_LEAVE_GAME), callback, do_next=True)

    @property
    def game(self) -> Optional[str]:
        """Currently joined game name."""
        return self._game

    def send(
        self,
        packet: Packet,
        callback: Optional[ResponseCallback] = None,
        /,
        do_next: bool = False,
    ):
        """Add a packet to the queue.

        If a callback was given, the response will be passed to it. Callbacks
        are not ensured, as the queue can be arbitrarily cleared using
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
        """Clear packets and their respective callbacks from the queue."""
        if self._packet_queue:
            logger.debug(f"Discarding messages:  {self._packet_queue}")
        self._packet_queue = []

    def on_connection(self, connected: bool):
        """Called when connected or disconnected."""
        pass

    def on_status(self, status: str):
        """Called with feedback on client status."""
        pass

    def on_game(self, game_name: str):
        """Called when joining or leaving a game."""
        pass

    def on_heartbeat(self, heartbeat: Response):
        """Override this method to implement heartbeat updates.

        The *heartbeat* Response is given by
        `pgnet.util.BaseGame.handle_heartbeat`. The heartbeat rate is set by
        `pgnet.util.BaseGame.heartbeat_rate`.
        """
        pass

    def heartbeat_payload(self) -> dict:
        """Override this method to add data to the heartbeat request payload.

        This payload is passed to `pgnet.util.BaseGame.handle_heartbeat`. The
        heartbeat rate is set by `pgnet.util.BaseGame.heartbeat_rate`.
        """
        return dict()

    async def _async_heartbeat(self):
        """Periodically update while connected and in game.

        Will create a heartbeat request using `BaseClient.heartbeat_payload`
        and pass the response to `BaseClient.on_heartbeat`.
        """
        while True:
            await asyncio.sleep(self._heartbeat_interval)
            if self.connected and self.game:
                packet = Packet(REQUEST_HEARTBEAT_UPDATE, self.heartbeat_payload())
                self.send(packet, self.on_heartbeat)

    async def _handle_handshake(
        self,
        connection: ClientConnection,
        username: str,
        password: str,
        verify_server_pubkey: Optional[str],
    ):
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
        if verify_server_pubkey is not None:
            if pubkey != verify_server_pubkey:
                raise DisconnectedError("Unverified server public key.")
            logger.debug(f"Server pubkey verified: {pubkey=}")
        connection.tunnel = self._key.get_tunnel(pubkey)
        logger.debug(f"Assigned tunnel: {connection}")
        # Authenticate
        packet = Packet("handshake", dict(username=username, password=password))
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
            self._handle_game_change(response)
            if callback:
                callback(response)
            # Disconnect if alerted
            if response.disconnecting:
                logger.info(f"Disconnected.\n{packet}\n{response.debug_repr}")
                raise DisconnectedError(response.message)
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
        logger.debug(f"Setting connection as: {set_as}")
        self._connected = set_as
        if self.on_connection:
            self.on_connection(set_as)

    def _handle_game_change(self, response: Response):
        """Handle game change.

        Set the client game name and heartbeat rate, then call event callback.
        """
        game_name = response.game
        if game_name != self._game:
            if game_name is None:
                self._set_status(f"Left game: {self._game}")
            else:
                self._set_status(f"Joined game: {game_name}")
            hb_rate = response.payload.get("heartbeat_rate", DEFAULT_HEARTBEAT_RATE)
            self._heartbeat_interval = 1 / hb_rate
            logger.debug(f"{self._heartbeat_interval=}")
            self._game = game_name
            if self.on_game:
                self.on_game(game_name)


__all__ = (
    "BaseClient",
)
