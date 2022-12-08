"""Base client class.

Create a BaseClient and use `BaseClient.async_connect` coroutine
to connect to the server.

Use `BaseClient.queue` to send packets and set a callback when a
response returns.

Warning: Passwords are currently being passed in plaintext.
"""

from typing import Optional, Callable, Any
from loguru import logger
import asyncio
import arrow
import websockets
from websockets.client import WebSocketClientProtocol as ClientWebSocket
from .common import (
    Packet,
    Response,
    DEFAULT_PORT,
    DisconnectedError,
    REQUEST_GAME_DIR,
    REQUEST_JOIN_GAME,
    REQUEST_LEAVE_GAME,
    STATUS_OK,
)


ResponseCallback = Callable[[Response], None]


class BaseClient:
    """See module documentation for details."""

    def __init__(
        self,
        *,
        username: str = "guest",
        password: str = "",
        address: str = "localhost",
        port: int = DEFAULT_PORT,
        on_connection: Optional[Callable[[bool], Any]] = None,
        on_status: Optional[Callable[[str], Any]] = None,
        on_game: Optional[Callable[[Optional[str]], Any]] = None,
        on_games_dir: Optional[Callable[[dict], Any]] = None,
        connect_timeout: float = 5,
        disconnect_timeout: float = 5,
        response_timeout: float = 2,
        reconnect_cooldown: float = 0.5,
        max_reconnect_attempts: int = 2,
    ):
        """See module documentation for details.

        Args:
            username: The user's username.
            password: The user's password.
            address: IP address of server.
            port: Port number of server.
            on_connection: Callback for when connecting or disconnecting.
            on_status: Callback for when client's status changes.
            on_games_dir: Callback for when the games directory is updated.
            on_game: Callback for when joining or leaving a game.
            connect_timeout: Seconds before timing out when connecting.
            disconnect_timeout: Seconds before timing out when disconnecting.
            response_timeout: Seconds before timing out when waiting for response.
            reconnect_cooldown: Seconds before trying to reconnect.
            max_reconnect_attempts: Number of times to try to reconnect.
        """
        self._status: str = "New client."
        self.__do_close: bool = True
        self.__connected: bool = False
        self.__connection: Optional[websockets.legacy.client.Connect] = None
        self._websocket: Optional[ClientWebSocket] = None
        self._websocket_busy: bool = False
        self.__games_dir: dict[str, dict] = []
        self.__requested_game: Optional[str] = None
        self.__game: Optional[str] = None
        self.__packet_queue: list[tuple[asyncio.Future, ResponseCallback]] = []
        self.username: str = username
        self.password: str = password
        self.address: str = address
        self.port: int = port
        self.full_address: str = f"{address}:{port}"
        self.response_timeout = response_timeout
        self.connect_timeout = connect_timeout
        self.disconnect_timeout = disconnect_timeout
        self.reconnect_cooldown = reconnect_cooldown
        self.max_reconnect_attempts = max_reconnect_attempts
        self.on_connection = on_connection
        self.on_status = on_status
        self.on_games_dir = on_games_dir
        self.on_game = on_game

    async def async_connect(
        self,
        *,
        interval_callback: Optional[Callable] = None,
        interval_seconds: int = 5,
    ):
        """Connect to the server."""
        if self.__connection:
            raise RuntimeError(
                f"Cannot create more than one connection concurrently per client {self}"
            )
        self.__do_close = False
        self.__connection = websockets.connect(
            f"ws://{self.full_address}",
            open_timeout=self.connect_timeout,
            close_timeout=self.disconnect_timeout,
        )
        websocket: Optional[ClientWebSocket] = None
        self._set_status(f"Connecting to {self.full_address}...", logger.info)
        reconnect_attempts = 0
        while True:
            try:
                try:
                    websocket = await self.__connection
                except OSError as e:
                    raise DisconnectedError("Failed to call server.", e)
                self._set_connection(True)
                await self._handle_handshake(websocket)
                reconnect_attempts = 0
                self._websocket = websocket
                await self._handle_user_connection(
                    websocket,
                    interval_callback,
                    interval_seconds,
                )
            except DisconnectedError as e:
                logger.info(repr(e))
                self._set_status(f"Disconnected: {e.args[0]}")
            self._websocket = None
            if websocket:
                await websocket.close()
            self._set_connection(False)
            reconnect_attempts += 1
            exhausted = reconnect_attempts > self.max_reconnect_attempts
            if self.__do_close or exhausted:
                break
            self._set_status(
                f"Attempting to reconnect to {self.full_address}...",
                logger.info,
            )
            await asyncio.sleep(self.reconnect_cooldown)
        self.__connection = None
        logger.info(f"Connection terminated {self}")

    def close(self):
        """Close the connection."""
        self.__do_close = True

    @property
    def connected(self) -> bool:
        """If we are connected to the server."""
        return self.__connected

    @property
    def status(self) -> str:
        """Human-readable client status."""
        return self._status

    def update_games_dir(self):
        """Update the games directory from the server."""
        asyncio.create_task(self._async_update_games_dir())

    @property
    def games_dir(self):
        """Latest games directory on the server."""
        return self.__games_dir

    @property
    def game(self) -> Optional[str]:
        """Currently joined game."""
        return self.__game

    def join_game(self, game_name: str):
        """Request from the server to join a game."""
        self.__requested_game = game_name

    def leave_game(self):
        """Request from the server to leave the game."""
        if self.game:
            self.queue(Packet(REQUEST_LEAVE_GAME), do_next=True)

    def queue(
        self,
        packet: Packet,
        callback: Optional[ResponseCallback] = None,
        /,
        do_next: bool = False,
    ):
        """Add packet to the queue. Optionally configure a callback for the response.

        Callbacks are not ensured, as a queue can be arbitrarily cleared using
        `BaseClient.flush_queue`.
        """
        if not self.__connected:
            logger.warning(f"Cannot queue packets while disconnected: {packet}")
            return
        if not self.__game:
            logger.warning(f"Cannot queue packets while not in game: {packet}")
            return
        packet_count = len(self.__packet_queue)
        if packet_count >= 5:
            logger.warning(
                f"Overloading queue ({packet_count} packets pending)"
                f" with packet: {packet}"
            )
        packet_callback = (packet, callback)
        if do_next:
            self.__packet_queue.insert(0, packet_callback)
        else:
            self.__packet_queue.append(packet_callback)

    def flush_queue(self):
        """Remove any packets and their respective callbacks from the packet queue."""
        if self.__packet_queue:
            logger.debug(f"Discarding messages:  {self.__packet_queue}")
        self.__packet_queue = []

    @property
    def websocket_busy(self) -> bool:
        """Determine if the client is currently sending and receiving a message."""
        return self._websocket_busy

    async def _handle_handshake(self, websocket: ClientWebSocket):
        """Handle a new connection by logging in with the handshake sequence."""
        self._set_status(f"Handshaking with {self.full_address}", logger.info)
        while True:
            payload = dict(
                username=self.username,
                password=self.password,
            )
            packet = Packet("handshake", payload)
            response = await self._async_send(websocket, packet)
            if response.status == STATUS_OK:
                logger.debug(f"Handshake success: {response.message}")
                self._set_status(f"Connected to: {self.full_address}", logger.info)
                return
            reason = response.message
            if response.disconnecting:
                reason = response.payload.get("reason", "No reason given.")
                logger.info(reason)
                raise DisconnectedError(reason)
            logger.info(response.message)
            self._set_status(response.message)
            await asyncio.sleep(self.reconnect_cooldown)

    async def _async_update_games_dir(self):
        """Update the games directory."""
        if not self.connected:
            logger.warning(
                "Cannot async update games directory when disconnected.",
            )
            return
        games_dir_response = await self._async_send(
            self._websocket,
            Packet(REQUEST_GAME_DIR),
        )
        self._on_games_dir(games_dir_response)

    def _on_games_dir(self, response: Response):
        self.__games_dir = response.payload.get("games", {})
        if self.on_games_dir:
            self.on_games_dir(self.__games_dir)

    async def _handle_user_connection(
        self,
        websocket: ClientWebSocket,
        interval_callback: Optional[Callable],
        interval_seconds: int,
    ):
        """Handle the connection when logged in."""
        while True:
            await self._handle_lobby(websocket)
            await self._handle_game_queue(
                websocket,
                interval_callback,
                interval_seconds,
            )

    async def _handle_lobby(self, websocket: ClientWebSocket):
        self.__game = None
        await self._async_update_games_dir()
        while not self.__game:
            await asyncio.sleep(0.2)
            if self.__do_close:
                raise DisconnectedError("Client closed connection.")
            if not self.__requested_game:
                continue
            requested_name = self.__requested_game
            packet = Packet(REQUEST_JOIN_GAME, dict(name=requested_name))
            response = await self._async_send(websocket, packet)
            self.__requested_game = None
            if response.game is None:
                continue
            self.__game = response.game
            if self.on_game:
                self.on_game(self.__game)
            self._set_status(f"Joined game: {self.__game}")
            return

    async def _handle_game_queue(
        self,
        websocket: ClientWebSocket,
        interval_callback: Optional[Callable],
        interval_seconds: int,
    ) -> bool:
        """Handle the connection while in game."""
        self.flush_queue()
        next_callback = arrow.now()
        while self.__game:
            if self.__do_close:
                raise DisconnectedError("Client closed connection.")
            # Check interval and wait for queued packets
            await asyncio.sleep(0.01)
            if interval_callback and next_callback <= arrow.now():
                interval_callback()
                next_callback = arrow.now().shift(seconds=interval_seconds)
            if not self.__packet_queue:
                continue
            # Send and callback with response
            packet, callback = self.__packet_queue.pop(0)
            response = await self._async_send(websocket, packet)
            if response.status != STATUS_OK:
                logger.debug(f"Status code: {response}")
            if callback:
                callback(response)
            if response.disconnecting:
                logger.info(f"Disconnected.\n{packet}\n{response.debug_repr}")
                reason = response.payload.get("reason", "No reason given.")
                raise DisconnectedError(reason)
            if response.game != self.__game:
                self._set_status(f"Left game: {self.__game}")
                self.__game = None
                if self.on_game:
                    self.on_game(response.game)

    async def _async_send(
        self,
        websocket: ClientWebSocket,
        packet: Packet,
        *,
        wait_for_socket: bool = True,
    ) -> Response:
        """Send and receive from server.

        Packets should be sent via `BaseClient.queue`, as this method
        does not handle anything other than the websocket communication,
        and is unaware of higher level protocols such as handshaking and
        lobbies.
        """
        response: Optional[Response] = None
        while self._websocket_busy:
            if not self.connected:
                logger.debug(f"Lost connection while waiting for websocket. {packet=}")
                return
            await asyncio.sleep(0.1)

        self._websocket_busy = True
        try:
            await asyncio.wait_for(
                websocket.send(packet.serialize()),
                timeout=self.response_timeout,
            )
            response: str = await asyncio.wait_for(
                websocket.recv(),
                timeout=self.response_timeout,
            )
            self._websocket_busy = False
            return Response.deserialize(response)
        # Catch any connection and timeout errors, initiate disconnect sequence
        except websockets.exceptions.ConnectionClosed:
            m = "Connection closed."
            if response:
                m = f"{m} {response.message}"
            self._websocket_busy = False
            raise DisconnectedError(m)
        except asyncio.exceptions.TimeoutError:
            self._websocket_busy = False
            raise DisconnectedError("Connection timed out.")

    def _set_status(self, status: str, logger: Optional[Callable] = None):
        self._status = status
        if logger:
            logger(status)
        if self.on_status:
            self.on_status(status)

    def _set_connection(self, set_as: bool, /):
        if self.__connected == set_as:
            return
        self.__connected = set_as
        if self.on_connection:
            self.on_connection(set_as)

    def __repr__(self) -> str:
        """Object repr."""
        return (
            f"<{self.__class__.__qualname__} "
            f"address={self.address!r} port={self.port!r} "
            f"{id(self)}>"
        )
