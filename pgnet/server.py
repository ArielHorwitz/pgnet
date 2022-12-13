"""Base server class.

Use `BaseServer.async_run` coroutine to start the server. To connect
backend functionality, subclass from `BaseGame` and register it in the
server.

By default, the server is configured to listen on localhost. To listen
globally, use address "". It is highly recommended to configure an admin
password when listening globally.
"""

from loguru import logger
from typing import Optional, Callable, Type, Any
import asyncio
import time
import websockets
from dataclasses import dataclass, field
from websockets.server import WebSocketServerProtocol as ServerWebSocket
import hashlib
from .util import (
    Packet,
    Response,
    DisconnectedError,
    Key,
    Connection,
    BaseGame,
    DEFAULT_PORT,
    REQUEST_GAME_DIR,
    REQUEST_JOIN_GAME,
    REQUEST_LEAVE_GAME,
    REQUEST_CREATE_GAME,
    DEFAULT_ADMIN_PASSWORD,
    ADMIN_USERNAME,
    STATUS_BAD,
    STATUS_UNEXPECTED,
)


MAX_USERNAME_LEN = 20


def hash_password(password: str) -> str:
    """Hash a string using Python's hashlib."""
    return hashlib.sha256(password.encode()).hexdigest()


@dataclass
class UserConnection(Connection):
    """Subclass of Connection with de/serialization and server-related attributes."""

    username: Optional[str] = None
    game: Optional[str] = None

    async def send(self, response: Response, *args, **kwargs):
        """Override base method to serialize response."""
        await super().send(response.serialize(), *args, **kwargs)

    async def recv(self, *args, **kwargs) -> Packet:
        """Override base method to deserialize packet."""
        message = await super().recv(*args, **kwargs)
        return Packet.deserialize(message)


@dataclass
class _LobbyGame:
    """BaseGame instance wrapper for management by server."""

    game: BaseGame
    name: str
    password: Optional[str]
    connected_users: set[str] = field(default_factory=set)

    @property
    def password_protected(self) -> bool:
        """If the game is password protected."""
        return bool(self.password)

    def add_user(self, username: str, password: str) -> bool:
        """Return if user was successfully added."""
        if password != self.password:
            logger.debug("Incorrect password.")
            return False
        self.connected_users.add(username)
        self.game.add_user(username)
        return True

    def remove_user(self, username):
        """Remove user from game."""
        if username in self.connected_users:
            self.connected_users.remove(username)
            self.game.remove_user(username)

    @property
    def expired(self):
        """If the game is over and can be deleted."""
        return not self.connected_users and not self.game.persistent

    def handle_packet(self, packet: Packet) -> Response:
        """Relay packet handling to game instance."""
        response = self.game.handle_packet(packet)
        return response

    def __repr__(self) -> str:
        """Object repr."""
        return f"<{self.__class__.__qualname__} {self.name!r} {id(self)}>"


class BaseServer:
    """See module documentation for details."""

    def __init__(
        self,
        game: Type[BaseGame],
        /,
        *,
        address: str = "localhost",
        port: int = DEFAULT_PORT,
        admin_password: str = DEFAULT_ADMIN_PASSWORD,
        registration_enabled: bool = True,
        on_connection: Optional[Callable[[str, bool], Any]] = None,
        verbose_logging: bool = False,
    ):
        """Initialize the server.

        Args:
            address: Set to "" to listen globally (default: "localhost").
            port: Port number to listen on.
            admin_password: Password for admin user with elevated priviliges.
            registration_enabled: Allow new users to register.
            on_connection: Callback for when a username connects or disconnects.
            verbose_logging: Log packets and responses.
        """
        self._key: Key = Key()
        self._stop: Optional[asyncio.Future] = None
        self._passwords: dict[str, str] = {
            ADMIN_USERNAME: hash_password(admin_password),
        }
        self._games: dict[str, _LobbyGame] = {}
        self._user_connections: dict[str, Optional[UserConnection]] = {}
        self._kicked_users: set[str] = set()
        self._game: Type[BaseGame] = game
        self.address: str = address
        self.port: int = port
        self.registration_enabled: bool = registration_enabled
        self.on_connection: Optional[Callable[[str, bool], Any]] = on_connection
        self.verbose_logging: bool = verbose_logging
        logger.debug(f"{self._game=}")
        logger.debug(f"{self._key=}")
        print(f"{admin_password=}")  # Use print instead of logger for password

    async def async_run(self, *, on_start: Optional[Callable] = None) -> int:
        """Start the server.

        The server will listen for connections and pass them off to the
        connection handler.

        Args:
            on_start: Callback for when the server is online and handling messages.

        Returns:
            Exit code as given by the `shutdown` command. -1 indicates a
                request to reboot the server.
        """
        if self._stop:
            raise RuntimeError("Can only run the server once per instance.")
        self._stop = asyncio.Future()
        serving_args = (self._connection_handler, self.address, self.port)
        try:
            async with websockets.serve(*serving_args):
                logger.info(f"Handling messages {self}")
                if on_start:
                    on_start()
                await self._stop
        except OSError as e:
            added = OSError(f"Server fail. Perhaps one is already running? {self}")
            raise added from e
        result = self._stop.result()
        logger.info(f"Server stop {result=} {self}")
        return result

    def shutdown(self, result: int = 0, /):
        """Stop the server."""
        if self._stop and not self._stop.done():
            self._stop.set_result(result)

    def kick_username(self, username: str):
        """Kick and blacklist a given username from the server."""
        if username == ADMIN_USERNAME:
            logger.warning("Cannot kick admin.")
            return
        self._kicked_users.add(username)

    async def _connection_handler(self, websocket: ServerWebSocket):
        """Handle new connections.

        Allows the handshake to fully populate a UserConnection, which may then
        be handled as a logged in user.
        """
        connection = UserConnection(websocket)
        logger.info(f"New connection: {connection}")
        try:
            await self._handle_handshake(connection)
            self._add_user_connection(connection)
            logger.info(f"User logged in: {connection}")
            await self._handle_user(connection)
        except DisconnectedError as e:
            logger.debug(f"{e=}")
        finally:
            logger.info(f"Closed connection: {connection}")
            self._remove_user_connection(connection)

    async def _handle_handshake(self, connection: UserConnection):
        """Handle a new connection's handshake sequence. Modifies the connection object.

        First trade public keys and assign the connection's `tunnel`. Then authenticate
        and assign the connection's `username`.
        """
        # Trade public keys
        packet = await connection.recv()
        pubkey = packet.payload.get("pubkey")
        if not pubkey or not isinstance(pubkey, str):
            response = Response(
                "Missing public key string.",
                status=STATUS_BAD,
                disconnecting=True,
            )
            await connection.send(response)
            raise DisconnectedError("Incompatible protocol: missing pubkey.")
        response = Response("key_trade", dict(pubkey=self._key.pubkey))
        await connection.send(response)
        connection.tunnel = self._key.get_tunnel(pubkey)
        logger.debug(f"Assigned tunnel: {connection}")
        # Authenticate
        packet = await connection.recv()
        username = packet.payload.get("username")
        password = packet.payload.get("password")
        if password:
            password = hash_password(password)
        fail = self._check_auth(username, password)
        if fail:
            # Respond with problem and disconnect
            response = Response(fail, status=STATUS_BAD, disconnecting=True)
            await connection.send(response)
            raise DisconnectedError("Failed to authenticate.")
        connection.username = username
        logger.debug(f"Assigned username: {connection}")
        if username == ADMIN_USERNAME:
            logger.warning(f"Authenticated as admin: {connection}")
        await connection.send(Response("Authenticated."))

    def _check_auth(self, username: str, password: str) -> Optional[str]:
        """Return failure reason or None."""
        if not username:
            return "Missing non-empty username."
        if username in self._kicked_users:
            return "Username kicked."
        if username in self._user_connections:
            return "Username already connected."
        if username not in self._passwords:
            not_admin = ADMIN_USERNAME.lower() not in username.lower()
            not_long = len(username) <= MAX_USERNAME_LEN
            name_allowed = not_admin and not_long
            if self.registration_enabled and name_allowed:
                self._passwords[username] = password
                logger.info(f"Registered {username=}")
                return None
            elif not self.registration_enabled:
                return "Username not found, registration blocked."
            else:
                return "Username not allowed."
        if password != self._passwords.get(username):
            return "Incorrect password."
        return None

    def _add_user_connection(self, connection: UserConnection):
        """Add the connection to connected users table."""
        username = connection.username
        assert username not in self._user_connections
        self._user_connections[username] = connection
        if self.on_connection:
            self.on_connection(username, True)

    def _remove_user_connection(self, connection: UserConnection):
        """Remove the connection from connected users table if exists."""
        username = connection.username
        if username not in self._user_connections:
            # User is not connected
            return
        self._remove_user_from_game(connection.username)
        del self._user_connections[username]
        if self.on_connection:
            self.on_connection(username, False)

    async def _handle_user(self, connection: UserConnection):
        """Handle a logged in user connection - handle packets and return responses."""
        username = connection.username
        while True:
            # Wait for packet from user
            packet = await connection.recv(timeout=3600.0)
            # Important! We must set the packet's authenticated username.
            packet.username = username
            do_log = self.verbose_logging
            if do_log:
                logger.debug(packet)
            if username in self._kicked_users:
                response = Response("Kicked.", disconnecting=True)
            else:
                response: Response = self._handle_packet(packet)
            if do_log:
                logger.debug(f"--> {response}")
            assert isinstance(response, Response)
            # Also important, to set the game of the response for the client.
            response.game = self._user_connections[username].game
            await connection.send(response)
            # The packet handler may have determined we are disconnecting
            if response.disconnecting:
                raise DisconnectedError(response.message)

    def _handle_packet(self, packet: Packet) -> Response:
        """Handle a packet from a logged in user."""
        if packet.message == REQUEST_GAME_DIR:
            return self._game_dir_response()
        if packet.message == REQUEST_JOIN_GAME:
            return self._handle_join_game(packet)
        if packet.message == REQUEST_LEAVE_GAME:
            return self._handle_leave_game(packet)
        if packet.message == REQUEST_CREATE_GAME:
            return self._handle_create_game(packet)
        if packet.username == ADMIN_USERNAME:
            response = self._handle_admin_packet(packet)
            if response:
                return response
        game_name: Optional[str] = self._user_connections[packet.username].game
        if not game_name:
            return self._canned_lobby_response
        return self._handle_game_packet(packet, game_name)

    def _remove_user_from_game(self, username: str):
        """Remove user from game and delete the game if expired."""
        connection = self._user_connections[username]
        game = self._games.get(connection.game)
        if not game:
            logger.debug(f"No game to remove from: {connection}")
            return
        connection.game = None
        game.remove_user(username)
        if game.expired:
            del self._games[game.name]

    def _game_dir_response(self) -> Response:
        """Create a Response with dictionary of games details."""
        games_dict = {}
        for name, game in self._games.items():
            games_dict[game.name] = dict(
                name=game.name,
                users=len(game.connected_users),
                password_protected=game.password_protected,
            )
        return Response("See payload for games list.", dict(games=games_dict))

    def _handle_join_game(self, packet: Packet) -> Response:
        """Handle a request to join the game specified in the payload."""
        current_name: Optional[str] = self._user_connections[packet.username].game
        if current_name:
            return Response("Must leave game first.", status=STATUS_UNEXPECTED)
        new_name: Optional[str] = packet.payload.get("name")
        if not new_name:
            return Response("Please specify a game.", status=STATUS_UNEXPECTED)
        if new_name == current_name:
            return Response("Already in game.", status=STATUS_UNEXPECTED)
        game = self._games.get(new_name)
        if not game:
            return self._handle_create_game(packet)
        password = packet.payload.get("password")
        success = game.add_user(packet.username, password)
        if not success:
            return Response("Failed to join.", status=STATUS_UNEXPECTED)
        self._user_connections[packet.username].game = new_name
        return Response("Joined game.")

    def _handle_leave_game(self, packet: Packet) -> Response:
        """Handle a request to leave the game."""
        name: Optional[str] = self._user_connections[packet.username].game
        if not name:
            return Response("Not in game.", status=STATUS_UNEXPECTED)
        self._remove_user_from_game(packet.username)
        return Response("Left game.")

    def _handle_create_game(self, packet: Packet) -> Response:
        """Handle request to create a new game specified in the payload."""
        current_game = self._user_connections[packet.username].game
        if current_game:
            return Response("Must leave game first.", status=STATUS_UNEXPECTED)
        name = packet.payload.get("name")
        if not name:
            return Response("Missing non-empty name.", status=STATUS_UNEXPECTED)
        if name in self._games:
            return Response("Name already exists.", status=STATUS_UNEXPECTED)
        password = packet.payload.get("password")
        new_game = _LobbyGame(
            self._game(name),
            name=name,
            password=password,
        )
        self._games[new_game.name] = new_game
        joined = new_game.add_user(packet.username, password)
        assert joined
        self._user_connections[packet.username].game = new_game.name
        return Response("Created new game.")

    def _handle_game_packet(self, packet: Packet, game_name: str) -> Response:
        """Routes a packet from a logged in user to the game's packet handler.

        Will use the response's `disconnecting` attribute to remove the user
        from the game, and then clear the attribute.
        """
        game = self._games[game_name]
        response: Response = game.handle_packet(packet)
        assert isinstance(response, Response)
        if response.disconnecting:
            self._remove_user_from_game(packet.username)
            response.disconnecting = False
        return response

    def _handle_admin_packet(self, packet: Packet) -> Optional[Response]:
        """Handle packets from the admin.

        The packet message is compared to methods of the class in the format
        of `_admin_commandname`.
        """
        admin_command = f"_admin_{packet.message}"
        if hasattr(self, admin_command):
            admin_handler = getattr(self, admin_command)
            return admin_handler(packet)
        return None

    # Admin commands
    def _admin_shutdown(self, packet: Packet) -> Response:
        """Shutdown the server."""
        self.shutdown()
        return Response("Shutting down...")

    def _admin_reboot(self, packet: Packet) -> Response:
        """Reboot the server."""
        self.shutdown(-1)
        return Response("Attempting to reboot...")

    def _admin_help(self, packet: Packet) -> Response:
        """Return available admin commands."""
        commands = []
        for attribute in dir(self):
            if attribute.startswith("_admin_"):
                commands.append(str(attribute)[len("_admin_"):])
        commands = ", ".join(commands)
        help = f"Commands: {commands}"
        return Response(help)

    def _admin_register(self, packet: Packet) -> Response:
        """Toggle registration.

        Pass nothing to toggle, or "set" parameter in payload to enable/disable.
        """
        set_as = bool(packet.payload.get("set", not self.registration_enabled))
        self.registration_enabled = set_as
        return Response(f"Registration enabled: {set_as}")

    def _admin_kick(self, packet: Packet) -> Response:
        """The "username" in payload will get kicked."""
        username = packet.payload.get("username", "")
        self.kick_username(username)
        return Response(f"Kicked user {username!r}")

    def _admin_verbose(self, packet: Packet) -> Response:
        """Toggle verbose logging.

        Pass nothing to toggle, or "set" parameter in payload to enable/disable.
        """
        set_as = bool(packet.payload.get("set", not self.verbose_logging))
        self.verbose_logging = set_as
        return Response(f"Verbose logging enabled: {set_as}")

    def _admin_debug(self, packet: Packet) -> Response:
        """Return debugging info."""
        non_kicked = set(self._passwords.keys()) - self._kicked_users
        debug = "\n".join([
            packet.debug_repr,
            "Kicked users:",
            *(f" -- {u}" for u in sorted(self._kicked_users)),
            "All users:",
            *(f" -- {u}" for u in sorted(non_kicked)),
            "Connected users:",
            *(f"  {conn}" for u, conn in sorted(self._user_connections.items())),
            "Games:",
            *(
                f" -- {g.name:<40} | {', '.join(str(u) for u in g.connected_users)}"
                for name, g in sorted(self._games.items())
            ),
            f"Pubkey: {self._key.pubkey}",
        ])
        return Response("Debug", dict(debug=debug))

    def _admin_sleep(self, packet: Packet) -> Response:
        """Simulate slow response by blocking for the time specified in payload.

        Warning: this actually blocks the entire server. Time is capped at 5 seconds.
        """
        max_sleep = 5
        s = int(packet.payload.get("time") or 1)
        s = min(max_sleep, s)
        time.sleep(s)
        return Response(f"Slept for {s} seconds")

    _canned_lobby_response = Response(
        "Please create/join a game.",
        dict(commands=[
            REQUEST_GAME_DIR,
            REQUEST_CREATE_GAME,
            REQUEST_JOIN_GAME,
            REQUEST_LEAVE_GAME,
        ]),
        status=STATUS_UNEXPECTED,
    )

    def __repr__(self) -> str:
        """Object repr."""
        return (
            f"<{self.__class__.__qualname__} "
            f"address={self.address!r} port={self.port!r} "
            f"{id(self)}>"
        )
