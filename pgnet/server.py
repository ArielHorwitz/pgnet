"""Base server class.

Use `BaseServer.async_run` coroutine to start the server. To connect
backend functionality, subclass from `BaseGame` and register it in the
server.

By default, the server is configured to listen on localhost. To listen
globally, use address "". It is highly recommended to configure an admin
password when listening globally.

Warning: do not use in production. Security is very shallow and
communicated in plaintext.

Todo:
- Kick address (not just username)
- Kick address on spam
- Hash and salt passwords
- Use at least a basic form of (public-private key) encryption
"""

from loguru import logger
from typing import Optional, Type
import asyncio
import time
import websockets
from dataclasses import dataclass, field
from websockets.server import WebSocketServerProtocol as ServerWebSocket
from .common import (
    Packet,
    Response,
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


@dataclass
class _LobbyGame:
    game: BaseGame
    name: str
    password: Optional[str]
    connected_users: set[str] = field(default_factory=set)

    @property
    def password_protected(self) -> bool:
        return bool(self.password)

    def add_user(self, username: str, password: str) -> bool:
        """Return if user was added."""
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

    def handle_packet(self, packet: Packet) -> Response:
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
        max_handshake_attempts: int = 2,
        verbose_logging: bool = False,
    ):
        """Initialize the server.

        Args:
            address: Set to "" to listen globally (default: "localhost").
            port: Port number to listen on.
            admin_password: Password for admin user with elevated priviliges.
            registration_enabled: Allow new users to register.
            max_handshake_attempts: Maximum number of tries to allow a client to
                handshake successfully.
            verbose_logging: Log packets and responses.
        """
        self.__stop: Optional[asyncio.Future] = None
        self.__passwords: dict[str, str] = {ADMIN_USERNAME: admin_password}
        self.__games: dict[str, _LobbyGame] = {}
        self.__connected_users: dict[str, Optional[str]] = {}  # username to game name
        self.__kicked_users: set[str] = set()
        self.__game: Type[BaseGame] = game
        self.address: str = address
        self.port: int = port
        self.registration_enabled: bool = registration_enabled
        self.max_handshake_attempts: int = max_handshake_attempts
        self.verbose_logging: bool = verbose_logging
        print(f"{admin_password=}")  # Use print instead of logger for "sensitive" info

    async def async_run(self) -> int:
        """Start the server.

        The server will listen for connections and pass them off to the websocket
        handler. Returns an exit code, where -1 is a request to reboot.
        """
        self.__stop = asyncio.Future()
        serving_args = (self._connection_handler, self.address, self.port)
        try:
            async with websockets.serve(*serving_args):
                logger.info(f"Handling messages {self}")
                await self.__stop
        except OSError as e:
            added = OSError(f"Server fail. Perhaps one is already running? {self}")
            raise added from e
        r = self.__stop.result()
        logger.info(f"Server stop result {r=} {self}")
        return r

    def on_connection(self, username: str, connected: bool):
        """Override this method to respond to connections and disconnections."""
        logger.info(f"{connected=} {username=}")

    def shutdown(self, result: int = 0, /):
        """Stop the server."""
        if self.__stop and not self.__stop.done():
            self.__stop.set_result(result)

    def kick_username(self, username: str):
        """Kick and blacklist a given username from the server."""
        if username == ADMIN_USERNAME:
            logger.warning("Cannot kick admin.")
            return
        self.__kicked_users.add(username)

    def __repr__(self) -> str:
        """Object repr."""
        return (
            f"<{self.__class__.__qualname__} "
            f"address={self.address!r} port={self.port!r} "
            f"{id(self)}>"
        )

    async def _connection_handler(self, websocket: ServerWebSocket):
        """Handle new connections.

        A handshake provides an authenticated username and privilege level
        (is admin). Then each message received is passed to the packet handler.
        """
        source = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        username: Optional[str] = None
        logger.info(f"New connection from: {source!r}")
        try:
            username = await self._handle_handshake(websocket)
            if username:
                await self._handle_user(username, websocket)
        except websockets.exceptions.ConnectionClosed:
            pass
        logger.info(f"Client connection {source!r} closed.")
        self._remove_user_connection(username)

    async def _handle_handshake(self, websocket: ServerWebSocket) -> Optional[str]:
        """Produce an authenticated username from a connection or None."""
        source = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        max_attempts = remaining_attempts = self.max_handshake_attempts
        while True:
            message = await websocket.recv()
            packet = Packet.deserialize(message)
            remaining_attempts -= 1
            # Authenticate
            username = packet.payload.get("username")
            password = packet.payload.get("password")
            if packet.message != "handshake":
                fail = "Missing handshake message."
            else:
                fail = self._check_auth(username, password)
            if not fail:
                if username == ADMIN_USERNAME:
                    logger.warning(f"Handshake authenticated as admin from: {source!r}")
                self._add_user_connection(username)
                m = f"Handshake from {source!r} success: {username=}"
                logger.info(m)
                await websocket.send(Response(m).serialize())
                return username
            # Respond with problem
            elif remaining_attempts:
                response = Response(
                    fail,
                    dict(remaining_attempts=remaining_attempts),
                    status=STATUS_UNEXPECTED,
                )
                await websocket.send(response.serialize())
            # Stop at max attempts
            else:
                fail = f"{fail} (max attempts reached)"
                response = Response(
                    "Disconnecting: failed to handshake.",
                    dict(reason=fail, max_attempts=max_attempts),
                    status=STATUS_BAD,
                    disconnecting=True,
                )
                logger.info(f"{response.debug_repr}")
                await websocket.send(response.serialize())
                return None

    def _check_auth(self, username: str, password: str) -> Optional[str]:
        """Return failure reason or None."""
        if not username:
            return "Missing non-empty username."
        if username in self.__kicked_users:
            return "Username kicked."
        if username in self.__connected_users:
            return "Username already connected."
        if username not in self.__passwords:
            name_allowed = ADMIN_USERNAME.lower() not in username.lower()
            if self.registration_enabled and name_allowed:
                self.__passwords[username] = password
                logger.info(f"Registered {username=}")
                return None
            elif not self.registration_enabled:
                return "Username not found, registration blocked."
            else:
                return "Username not allowed."
        if password != self.__passwords.get(username):
            return "Incorrect password."
        return None

    def _add_user_connection(self, username: str):
        if username in self.__connected_users:
            return
        self.__connected_users[username] = None
        if self.on_connection:
            self.on_connection(username, True)

    def _remove_user_connection(self, username: str):
        if username not in self.__connected_users:
            return
        del self.__connected_users[username]
        if self.on_connection:
            self.on_connection(username, False)

    async def _handle_user(self, username: str, websocket: ServerWebSocket):
        """Handle a logged in user connection."""
        async for message in websocket:
            do_log = self.verbose_logging
            packet = Packet.deserialize(message)
            packet.username = username
            if do_log:
                logger.debug(packet)
            if username in self.__kicked_users:
                response = Response(
                    "Disconnecting: kicked.",
                    dict(reason="Kicked."),
                    disconnecting=True,
                )
            else:
                response: Response = self._handle_packet(packet)
            if do_log:
                logger.debug(f"--> {response}")
            response.game = self.__connected_users[username]
            assert isinstance(response, Response)
            await websocket.send(response.serialize())
            if response.disconnecting:
                return

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
        game_name: Optional[str] = self.__connected_users[packet.username]
        if not game_name:
            return Response("Please join a game.")
        return self._handle_game_packet(packet, game_name)

    def _game_dir_response(self) -> Response:
        """Create a Response with dictionary of games details."""
        games_dict = {}
        for name, game in self.__games.items():
            games_dict[game.name] = dict(
                name=game.name,
                users=len(game.connected_users),
                password_protected=game.password_protected,
            )
        return Response("See payload for games list.", dict(games=games_dict))

    def _handle_join_game(self, packet: Packet) -> Response:
        """Handle a request to join the game specified in the payload."""
        current_name: Optional[str] = self.__connected_users[packet.username]
        if current_name:
            return Response("Must leave game first.", status=STATUS_UNEXPECTED)
        new_name: Optional[str] = packet.payload.get("name")
        if not new_name:
            return Response("Please specify a game.", status=STATUS_UNEXPECTED)
        if new_name == current_name:
            return Response("Already in game.", status=STATUS_UNEXPECTED)
        game = self.__games.get(new_name)
        if not game:
            return self._handle_create_game(packet)
        password = packet.payload.get("password")
        success = game.add_user(packet.username, password)
        if not success:
            return Response("Failed to join.", status=STATUS_BAD)
        self.__connected_users[packet.username] = new_name
        return Response("Joined game.")

    def _handle_leave_game(self, packet: Packet) -> Response:
        """Handle a request to leave the game."""
        name: Optional[str] = self.__connected_users[packet.username]
        if not name:
            return Response("Not in game.", status=STATUS_UNEXPECTED)
        self.__connected_users[packet.username] = None
        game = self.__games.get(name)
        game.remove_user(packet.username)
        if not game.connected_users:
            del self.__games[name]
        return Response("Left game.")

    def _handle_create_game(self, packet: Packet) -> Response:
        current_game = self.__connected_users[packet.username]
        if current_game:
            return Response("Must leave game first.", status=STATUS_UNEXPECTED)
        name = packet.payload.get("name")
        if not name:
            return Response("Missing non-empty name.", status=STATUS_UNEXPECTED)
        if name in self.__games:
            return Response("Name already exists.", status=STATUS_UNEXPECTED)
        password = packet.payload.get("password")
        new_game = _LobbyGame(
            self.__game(name),
            name=name,
            password=password,
        )
        self.__games[new_game.name] = new_game
        joined = new_game.add_user(packet.username, password)
        assert joined
        self.__connected_users[packet.username] = new_game.name
        return Response("Created new game.")

    def _handle_game_packet(self, packet: Packet, game_name: str) -> Response:
        """Routes a packet from a logged in user to the game's packet handler.

        Will use the response's `disconnecting` attribute to remove the user
        from the game, and then clear the attribute.
        """
        game = self.__games[game_name]
        response: Response = game.handle_packet(packet)
        assert isinstance(response, Response)
        if response.disconnecting:
            self.__connected_users[packet.username] = None
            game.remove_user(packet.username)
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
        return Response("Rebooting...")

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
        non_kicked = set(self.__passwords.keys()) - self.__kicked_users
        debug = "\n".join([
            packet.debug_repr,
            "Kicked users:",
            *(f" -- {u}" for u in sorted(self.__kicked_users)),
            "All users:",
            *(f" -- {u}" for u in sorted(non_kicked)),
            "Connected users:",
            *(
                f" -- {u:<40} | {g}"
                for u, g in sorted(self.__connected_users.items())
            ),
            "Games:",
            *(
                f" -- {g.name:<40} | {', '.join(str(u) for u in g.connected_users)}"
                for name, g in sorted(self.__games.items())
            ),
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
