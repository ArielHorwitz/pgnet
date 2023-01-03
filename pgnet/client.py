"""Home of the `Client` class."""

from typing import Optional, Callable, Any, Type
from loguru import logger
import asyncio
from dataclasses import dataclass
import websockets
from websockets.client import WebSocketClientProtocol
from .server import Server
from .util import (
    Packet,
    Response,
    Connection,
    Key,
    Game,
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


class Client:
    """The client that manages communication with the server.

    ## Initializing
    This class should not be initialized directly, instead use `Client.remote` or
    `Client.local`.
    ```python3
    # This client will connect to a remote server
    remote_client = Client.remote(address="1.2.3.4", username="player")
    # This client will create a local server and connect to it
    local_client = Client.local(game=MyGame, username="player")
    ```

    ## Connecting and starting a game
    Use `Client.async_connect` to connect to the server. Once connected, use
    `Client.get_games_dir`, `Client.create_game`, `Client.join_game`, and
    `Client.leave_game` to join or leave a game.

    ## Using the packet queue
    When in game (`Client.game` is not *None*), use `Client.send` to send a
    `pgnet.Packet` to `pgnet.Game.handle_game_packet` and receive a `pgnet.Response`.

    ## Client events
    It is possible to bind callbacks to client events by subclassing and overriding or
    by setting `Client.on_connection`, `Client.on_status`, and `Client.on_game`.

    """

    def __init__(
        self,
        *,
        address: str,
        username: str,
        password: str,
        port: int,
        server: Optional[Server],
        verify_server_pubkey: str,
    ):
        """This class should not be initialized directly.

        .. note:: Use `Client.local` or `Client.remote` to create a client.
        """
        self._key: Key = Key()
        self._status: str = "New client."
        self._server_connection: Optional[WebSocketClientProtocol] = None
        self._connected: bool = False
        self._do_disconnect: bool = False
        self._packet_queue: list[tuple[Packet, ResponseCallback]] = []
        self._game: Optional[str] = None
        self._heartbeat_interval = 1 / DEFAULT_HEARTBEAT_RATE
        # Connection details
        self._username = username
        self._password = password
        self._address = address
        self._port = port
        self._server = server
        self._verify_server_pubkey = verify_server_pubkey

    @classmethod
    def local(
        cls,
        *,
        game: Type[Game],
        username: str,
        password: str = "",
        port: int = DEFAULT_PORT,
        server_factory: Callable[[Any], Server] = Server,
    ) -> "Client":
        """Create a client that uses its own local server. See also `Client.remote`.

        Only the *game* and *username* arguments are required.

        Args:
            game: `Game` class to pass to the local server.
            username: The user's username.
            password: The user's password.
            port: Server port number.
            server_factory: If provided, will be used to create the local server. Must
                accept the same arguments as `pgnet.Server`. This is useful for using a
                server subclass or to pass custom arguments to the local server.
        """
        server = server_factory(
            game,
            listen_globally=False,
            registration_enabled=True,
            require_user_password=False,
        )
        return cls(
            address="localhost",
            username=username,
            password=password,
            port=port,
            server=server,
            verify_server_pubkey=server.pubkey,
        )

    @classmethod
    def remote(
        cls,
        *,
        address: str,
        username: str,
        password: str = "",
        port: int = DEFAULT_PORT,
        verify_server_pubkey: str = "",
    ) -> "Client":
        """Create a client that connects to a remote server. See also `Client.local`.

        Args:
            address: Server IP address.
            username: The user's username.
            password: The user's password.
            port: Server port number.
            verify_server_pubkey: If provided, will compare against the public key of
                the server and disconnect if they do not match.
        """
        return cls(
            address=address,
            username=username,
            password=password,
            port=port,
            server=None,
            verify_server_pubkey=verify_server_pubkey,
        )

    async def async_connect(self):
        """Connect to a server.

        This procedure will automatically create an end-to-end encrypted connection
        (optionally verifying the public key first), and authenticate the username and
        password. Only after succesfully completing these steps will the client be
        considered connected and ready to process the packet queue from `Client.send`.
        """
        if self._server is None:
            logger.debug("Connecting remotely...")
            return await self._async_connect_remote()
        else:
            logger.debug("Connecting locally...")
            return await self._async_connect_local()

    def disconnect(self):
        """Close the connection."""
        self._do_disconnect = True

    def get_games_dir(self, callback: Callable, /):
        """Get the games directory from the server and pass the response to callback."""
        self.send(Packet(REQUEST_GAME_DIR), callback, do_next=True)

    def create_game(
        self,
        name: str,
        /,
        *,
        password: Optional[str] = None,
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
        *,
        password: Optional[str] = None,
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

    def send(
        self,
        packet: Packet,
        callback: Optional[ResponseCallback] = None,
        /,
        do_next: bool = False,
    ):
        """Add a packet to the queue.

        If a callback was given, the response will be passed to it. Callbacks are not
        ensured, as the queue can be arbitrarily cleared using `Client.flush_queue`.
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
        """Called when connected or disconnected. See also: `Client.connected`."""
        pass

    @property
    def connected(self) -> bool:
        """If we are connected to the server. See also: `Client.on_connection`."""
        return self._connected

    def on_status(self, status: str):
        """Called with feedback on client status. See also: `Client.status`."""
        pass

    @property
    def status(self) -> str:
        """Last status feedback message. See also: `Client.on_status`."""
        return self._status

    def on_game(self, game_name: str):
        """Called when joining or leaving a game. See also: `Client.game`."""
        pass

    @property
    def game(self) -> Optional[str]:
        """Currently joined game name. See also: `Client.on_game`."""
        return self._game

    def on_heartbeat(self, heartbeat: Response):
        """Override this method to implement heartbeat updates.

        The *heartbeat* Response is given by `pgnet.util.Game.handle_heartbeat`. The
        heartbeat rate is set by `pgnet.util.Game.heartbeat_rate`.
        """
        pass

    def heartbeat_payload(self) -> dict:
        """Override this method to add data to the heartbeat request payload.

        This payload is passed to `pgnet.util.Game.handle_heartbeat`. The heartbeat rate
        is set by `pgnet.util.Game.heartbeat_rate`.
        """
        return dict()

    async def _async_connect_remote(self):
        """Connect to the server.

        Gets a websocket to create a `ClientConnection` object. This is passed to the
        handshake handler to be populated, and then to the user connection for handling
        the packet queue. The heartbeat task is managed here.
        """
        if self._server_connection is not None:
            raise RuntimeError("Cannot open more than one connection per client.")
        full_address = f"{self._address}:{self._port}"
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
            await self._handle_handshake(connection)
            self._set_connection(True)
            self._set_status(
                f"Logged in as {self._username} @ {connection.remote}",
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

    async def _async_connect_local(self):
        """Wraps `Client._async_connect_remote to cleanup/teardown the local server."""
        assert isinstance(self._server, Server)
        started = asyncio.Future()
        server_coro = self._server.async_run(on_start=lambda *a: started.set_result(1))
        server_task = asyncio.create_task(server_coro)
        server_task.add_done_callback(lambda *a: self.disconnect())
        await asyncio.wait((server_task, started), return_when=asyncio.FIRST_COMPLETED)
        await self._async_connect_remote()
        self.disconnect()
        self._server.shutdown()

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
        if self._verify_server_pubkey:
            if pubkey != self._verify_server_pubkey:
                raise DisconnectedError("Unverified server public key.")
            logger.debug(f"Server pubkey verified: {pubkey=}")
        connection.tunnel = self._key.get_tunnel(pubkey)
        logger.debug(f"Assigned tunnel: {connection}")
        # Authenticate
        handshake_payload = dict(username=self._username, password=self._password)
        packet = Packet("handshake", handshake_payload)
        response = await connection.send_recv(packet)
        if response.status != STATUS_OK:
            m = response.message
            logger.info(m)
            raise DisconnectedError(m)

    async def _async_heartbeat(self):
        """Periodically update while connected and in game.

        Will create a heartbeat request using `Client.heartbeat_payload` and pass the
        response to `Client.on_heartbeat`.
        """
        while True:
            await asyncio.sleep(self._heartbeat_interval)
            if self.connected and self.game:
                packet = Packet(REQUEST_HEARTBEAT_UPDATE, self.heartbeat_payload())
                self.send(packet, self.on_heartbeat)

    async def _handle_user_connection(self, connection: ClientConnection):
        """Handle the connection after handshake - process the packet queue."""
        self._do_disconnect = False
        while not self._do_disconnect:
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
    "Client",
)
