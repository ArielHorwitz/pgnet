"""Home of the `Server` class."""

from loguru import logger
from typing import Optional, Callable, Type, Any
import arrow
import asyncio
import json
from pathlib import Path
import re
import os
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
    Game,
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


GAME_UPDATE_INTERVAL = 0.1
AUTOSAVE_INTERVAL = 300  # 5 minutes
MAX_USERNAME_LEN = 20
RE_WHITESPACE = re.compile(r"\W")
SALT_SIZE = 20
DEFAULT_SAVE_FILE = ".pgnet-server-data.json"


@dataclass
class User:
    """User authentication info."""

    name: str
    salt: str
    hashed_password: str

    @classmethod
    def from_name_password(cls, name: str, password: str):
        """Create a new user from a raw (unsalted/unhashed) password."""
        salt = cls._generate_salt()
        hashed_password = cls._hash_password(password, salt)
        return cls(name, salt=salt, hashed_password=hashed_password)

    def compare_password(self, password: str):
        """Compare a raw (unsalted/unhashed) password to our password."""
        return self._hash_password(password, self.salt) == self.hashed_password

    @staticmethod
    def _generate_salt() -> str:
        return os.urandom(SALT_SIZE).hex()

    @staticmethod
    def _hash_password(password: str, salt: str) -> str:
        """Hash a string using Python's hashlib."""
        return hashlib.sha256(f"{salt}{password}".encode()).hexdigest()


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
class LobbyGame:
    """`Game` instance wrapper for management by server."""

    game: Game = field(repr=False)
    name: str
    password: Optional[str]
    connected_users: set[str] = field(default_factory=set)

    @property
    def heartbeat_rate(self) -> float:
        """Updates per second."""
        return self.game.heartbeat_rate

    @property
    def password_protected(self) -> bool:
        """If the game is password protected."""
        return bool(self.password)

    def add_user(self, username: str, password: str) -> Optional[str]:
        """Return reason if user was not successfully added."""
        if password != self.password:
            return "Incorrect password."
        self.connected_users.add(username)
        self.game.user_joined(username)
        return None

    def remove_user(self, username):
        """Remove user from game."""
        if username in self.connected_users:
            self.connected_users.remove(username)
            self.game.user_left(username)

    def get_save_string(self) -> Optional[str]:
        """Called by the server when shutting down."""
        if self.game.persistent:
            return self.game.get_save_string()
        return None

    @property
    def expired(self):
        """If the game is over and can be deleted."""
        return not self.connected_users and not self.game.persistent

    def handle_packet(self, packet: Packet) -> Response:
        """Relay packet handling to game instance."""
        response = self.game.handle_packet(packet)
        return response

    def update(self):
        """Called on an interval by the server."""
        self.game.update()


class Server:
    """The server that hosts games.

    Subclass from `Game` and pass it as the *game* argument for the server. Then,
    use the `Server.async_run` coroutine to start the server.

    By default, the server is configured to listen on localhost. To listen
    globally, set *`listen_globally`* and *`admin_password`*. Make sure that any
    required network rules are set (e.g. port forwarding).
    """

    def __init__(
        self,
        game: Type[Game],
        /,
        *,
        listen_globally: bool = False,
        port: int = DEFAULT_PORT,
        admin_password: Optional[str] = None,
        registration_enabled: bool = True,
        require_user_password: bool = True,
        on_connection: Optional[Callable[[str, bool], Any]] = None,
        verbose_logging: bool = False,
        save_file: Optional[str | Path] = None,
    ):
        """Initialize the server.

        Args:
            listen_globally: Listen globally instead of localhost only.
                Requires that admin_password must be set.
            port: Port number to listen on.
            admin_password: Password for admin user with elevated priviliges.
                Must be set to listen globally.
            registration_enabled: Allow new users to register.
            require_user_password: Require that users have non-empty passwords.
            on_connection: Callback for when a username connects or disconnects.
            verbose_logging: Log *all* packets and responses.
            save_file: Location of file to save and load server sessions.
        """
        if listen_globally and not admin_password:
            raise RuntimeError("Cannot listen globally without admin password.")
        admin_password = admin_password or DEFAULT_ADMIN_PASSWORD
        self._key: Key = Key()
        self._stop: Optional[asyncio.Future] = None
        self._require_user_password = require_user_password
        self._users: dict[str, User] = dict()
        self._register_user(ADMIN_USERNAME, admin_password)
        self._games: dict[str, LobbyGame] = {}
        self._connections: dict[str, Optional[UserConnection]] = {}
        self._kicked_users: set[str] = set()
        self._game_cls: Type[Game] = game
        self._save_file: Path = Path(save_file or DEFAULT_SAVE_FILE)
        self._address: str = "" if listen_globally else "localhost"
        self._port: int = port
        self.registration_enabled: bool = registration_enabled
        self.on_connection: Optional[Callable[[str, bool], Any]] = on_connection
        self.verbose_logging: bool = verbose_logging
        logger.debug(f"{self._save_file.absolute()=}")
        logger.debug(f"{self._game_cls=}")
        logger.debug(f"{self._key=}")
        print(f"{admin_password=}")  # Use print instead of logger for password
        self._load_from_disk()

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
            raise RuntimeError("Cannot run the server more than once concurrently.")
        self._stop = asyncio.Future()
        serving_args = (self._connection_handler, self._address, self._port)
        try:
            async with websockets.serve(*serving_args):
                logger.info(f"Handling messages {self}")
                if on_start:
                    on_start()
                await self._listening_loop(self._stop)
        except OSError as e:
            added = OSError(f"Server fail. Perhaps one is already running? {self}")
            raise added from e
        self._save_to_disk()
        result = self._stop.result()
        logger.info(f"Server stop {result=} {self}")
        self._stop = None
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

    @property
    def pubkey(self) -> str:
        """Public key for end to end encryption."""
        return self._key.pubkey

    async def _listening_loop(self, stop_future: asyncio.Future):
        next_autosave = arrow.now().shift(seconds=AUTOSAVE_INTERVAL)
        next_interval = arrow.now().shift(seconds=GAME_UPDATE_INTERVAL)
        while not stop_future.done():
            await asyncio.sleep(0.1)
            if arrow.now() >= next_autosave:
                self._save_to_disk()
                next_autosave = arrow.now().shift(seconds=AUTOSAVE_INTERVAL)
            if arrow.now() >= next_interval:
                for game in self._games.values():
                    game.update()
                next_interval = arrow.now().shift(seconds=GAME_UPDATE_INTERVAL)

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
        response = Response("key_trade", dict(pubkey=self.pubkey))
        await connection.send(response)
        connection.tunnel = self._key.get_tunnel(pubkey)
        logger.debug(f"Assigned tunnel: {connection}")
        # Authenticate
        packet = await connection.recv()
        username = packet.payload.get("username")
        password = packet.payload.get("password")
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
        if username in self._connections:
            return "Username already connected."
        if username not in self._users:
            missing_password = self._require_user_password and not password
            if (
                self.registration_enabled
                and self._name_allowed(username)
                and not missing_password
            ):
                self._register_user(username, password)
                return None
            elif not self.registration_enabled:
                return "Username not found, registration blocked."
            elif missing_password:
                return "User password required."
            else:
                return "Username not allowed."
        user = self._users[username]
        if not user.compare_password(password):
            return "Incorrect password."
        return None

    @staticmethod
    def _name_allowed(name: str, /) -> bool:
        """If a name is allowed."""
        not_admin = ADMIN_USERNAME.lower() not in name.lower()
        not_long = len(name) <= MAX_USERNAME_LEN
        not_empty = len(name) > 0
        no_whitespace = not bool(RE_WHITESPACE.search(name))
        return not_admin and not_long and not_empty and no_whitespace

    def _register_user(self, username: str, password: str, /):
        """Register new user."""
        assert username not in self._users
        if self._require_user_password and not password:
            raise ValueError("Server requires password for users.")
        user = User.from_name_password(username, password)
        self._users[username] = user
        logger.info(f"Registered {username=}")

    def _add_user_connection(self, connection: UserConnection):
        """Add the connection to connected users table."""
        username = connection.username
        assert username not in self._connections
        self._connections[username] = connection
        if self.on_connection:
            self.on_connection(username, True)

    def _remove_user_connection(self, connection: UserConnection):
        """Remove the connection from connected users table if exists."""
        username = connection.username
        if username not in self._connections:
            return
        self._remove_user_from_game(connection.username)
        del self._connections[username]
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
            response.game = self._connections[username].game
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
        game_name: Optional[str] = self._connections[packet.username].game
        if not game_name:
            return self._canned_lobby_response
        return self._handle_game_packet(packet, game_name)

    def _remove_user_from_game(self, username: str):
        """Remove user from game and delete the game if expired."""
        connection = self._connections[username]
        game = self._games.get(connection.game)
        if not game:
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

    def _create_game(
        self,
        name: str,
        password: Optional[str] = None,
        game_data: Optional[str] = None,
    ) -> LobbyGame:
        """Create a new game."""
        assert name not in self._games
        game = self._game_cls(name, save_string=game_data)
        lobbygame = LobbyGame(game, name, password)
        self._games[name] = lobbygame
        return lobbygame

    def _destroy_game(self, game_name: str):
        """Destroy an existing game."""
        game = self._games[game_name]
        while game.connected_users:
            self._remove_user_from_game(list(game.connected_users)[0])
        if game_name in self._games:
            del self._games[game_name]

    def _handle_join_game(self, packet: Packet) -> Response:
        """Handle a request to join the game specified in the payload."""
        connection = self._connections[packet.username]
        current_name: Optional[str] = connection.game
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
        fail = game.add_user(packet.username, password)
        if fail:
            return Response(f"Failed to join: {fail}", status=STATUS_UNEXPECTED)
        connection.game = new_name
        return Response("Joined game.", dict(heartbeat_rate=game.heartbeat_rate))

    def _handle_leave_game(self, packet: Packet) -> Response:
        """Handle a request to leave the game."""
        name: Optional[str] = self._connections[packet.username].game
        if not name:
            return Response("Not in game.", status=STATUS_UNEXPECTED)
        self._remove_user_from_game(packet.username)
        return Response("Left game.")

    def _handle_create_game(self, packet: Packet) -> Response:
        """Handle request to create a new game specified in the payload."""
        connection = self._connections[packet.username]
        current_game = connection.game
        if current_game:
            return Response("Must leave game first.", status=STATUS_UNEXPECTED)
        game_name = packet.payload.get("name")
        if not self._name_allowed(game_name):
            return Response("Name not allowed.", status=STATUS_UNEXPECTED)
        if game_name in self._games:
            return Response("Name already exists.", status=STATUS_UNEXPECTED)
        password = packet.payload.get("password")
        game = self._create_game(game_name, password)
        fail = game.add_user(packet.username, password)
        assert not fail
        connection.game = game_name
        return Response("Created new game.", dict(heartbeat_rate=game.heartbeat_rate))

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

    def _admin_destroy(self, packet: Packet) -> Response:
        """Destroy the game specified in payload."""
        game_name = packet.payload.get("name", "")
        if game_name not in self._games:
            return Response(f"No such game: {game_name}", status=STATUS_UNEXPECTED)
        self._destroy_game(game_name)
        return Response(f"Destroyed game: {game_name}")

    def _admin_save(self, packet: Packet) -> Response:
        """Save all server data to file."""
        self._save_to_disk()
        return Response(f"Saved server data to disk: {self._save_file}")

    def _admin_verbose(self, packet: Packet) -> Response:
        """Toggle verbose logging.

        Pass nothing to toggle, or "set" parameter in payload to enable/disable.
        """
        set_as = bool(packet.payload.get("set", not self.verbose_logging))
        self.verbose_logging = set_as
        return Response(f"Verbose logging enabled: {set_as}")

    def _admin_debug(self, packet: Packet) -> Response:
        """Return debugging info."""
        non_kicked = set(self._users.keys()) - self._kicked_users
        debug = "\n".join([
            packet.debug_repr,
            "Kicked users:",
            *(f" -- {u}" for u in sorted(self._kicked_users)),
            "All users:",
            *(f" -- {u}" for u in sorted(non_kicked)),
            "Connected users:",
            *(f"  {conn}" for u, conn in sorted(self._connections.items())),
            "Games:",
            *(f"  {game}" for name, game in sorted(self._games.items())),
            f"Pubkey: {self.pubkey}",
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

    def _save_to_disk(self):
        """Save all data to disk."""
        game_data = []
        for game in self._games.values():
            save_string = game.get_save_string()
            if not save_string:
                continue
            game_data.append(dict(
                name=game.name,
                password=game.password,
                data=save_string,
            ))
        users = [
            dict(name=u.name, salt=u.salt, password=u.hashed_password)
            for u in self._users.values() if u.name != ADMIN_USERNAME
        ]
        data = dict(
            users=users,
            kicked_users=list(self._kicked_users),
            games=game_data,
            registration=self.registration_enabled,
        )
        dumped = json.dumps(data, indent=4)
        self._save_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self._save_file, "w") as f:
            f.write(dumped)
        logger.debug(
            f"Saved server data to {self._save_file}"
            f" ({len(users)} users and {len(game_data)} games)"
        )

    def _load_from_disk(self):
        if not self._save_file.is_file():
            return
        logger.info(f"Loading server data from {self._save_file}")
        with open(self._save_file) as f:
            data = f.read()
        data = json.loads(data)
        for user in data["users"]:
            username = user["name"]
            if username == ADMIN_USERNAME:
                continue
            assert self._name_allowed(username)
            self._users[username] = u = User(username, user["salt"], user["password"])
            logger.debug(f"Loaded: {u}")
        for game in data["games"]:
            game_name = game["name"]
            assert self._name_allowed(game_name)
            self._create_game(game_name, game["password"], game["data"])
            logger.debug(f"Loaded: {self._games[game_name]}")
        self._kicked_users |= set(data["kicked_users"])
        self.registration_enabled = data["registration"]
        logger.debug("Loading disk data complete.")

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
            f"address={self._address!r} port={self._port!r} "
            f"{id(self)}>"
        )


__all__ = (
    "Server",
)
