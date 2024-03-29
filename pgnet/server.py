"""Home of the `Server` class."""

from loguru import logger
from typing import Optional, Callable, Type, Any
import arrow
import asyncio
import functools
import json
from pathlib import Path
import inspect
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
    Request,
    DEFAULT_ADMIN_PASSWORD,
    ADMIN_USERNAME,
    Status,
)


GAME_UPDATE_INTERVAL = 0.1
AUTOSAVE_INTERVAL = 300  # 5 minutes
SALT_SIZE = 20

_re_whitespace = re.compile(r"\W")
_re_non_alnum = re.compile(r"[^a-zA-Z\d\s]")
_re_start_whitespace = re.compile(r"^\W")
_re_end_whitespace = re.compile(r"\W$")


def _get_packet_handler_params(f: Callable) -> set[str]:
    return {
        name: param
        for name, param in inspect.signature(f).parameters.items()
        if name not in {"self", "packet"}
    }


def _user_packet_handler(*, admin: bool = False):
    """Decorator that unpacks a packet payload into keyword arguments.

    Checks that payload keys exist in arguments and values match the annotations. If
    *admin* is True, will check that the packet is from the admin user.
    """
    def wrapper(f: Callable):
        params = _get_packet_handler_params(f)
        for name, param in params.items():
            if param.annotation not in {int, str, bool, float}:
                raise AssertionError(
                    f"{name!r} of {f} must be of JSON-able type,"
                    f" instead got: {param.annotation}"
                )

        @functools.wraps(f)
        def inner(server: "Server", packet: Packet):
            # Check admin
            if admin and packet.username != ADMIN_USERNAME:
                return Response(
                    f"{packet.message!r} requires admin privileges.",
                    status=Status.UNEXPECTED,
                )
            # Compare payload to signature
            for arg, value in packet.payload.items():
                if arg not in params:
                    return Response(
                        f"Unexpected argument {arg!r} for request {packet.message!r}",
                        status=Status.UNEXPECTED,
                    )
                expected_type = params[arg].annotation
                if type(value) is not expected_type:
                    m = (
                        f"Expected argument type {expected_type} for argument {arg!r}."
                        f" Instead got: {type(value)} {value!r}"
                    )
                    return Response(m, status=Status.UNEXPECTED)
            # Finally call wrapped function
            return f(server, packet, **packet.payload)
        return inner
    return wrapper


def _check_name(
    name: str,
    /,
    *,
    min_len: int = 3,
    max_len: int = 20,
    allow_whitespace: bool = False,
    alnum_only: bool = True,
    allow_lead_trail_whitespace: bool = False,
) -> bool:
    """If a string matches criteria of arguments."""
    if ADMIN_USERNAME.lower() in name.lower():
        return False
    if len(name) > max_len:
        return False
    if len(name) < min_len:
        return False
    if not allow_whitespace and bool(_re_whitespace.search(name)):
        return False
    if alnum_only and bool(_re_non_alnum.search(name)):
        return False
    if not allow_lead_trail_whitespace:
        if bool(_re_start_whitespace.search(name)):
            return False
        if bool(_re_end_whitespace.search(name)):
            return False
    return True


def is_username_allowed(name: str, /) -> bool:
    """If a username is allowed."""
    return _check_name(
        name,
        max_len=20,
        allow_whitespace=False,
        alnum_only=True,
    )


def is_gamename_allowed(name: str, /) -> bool:
    """If a game name is allowed."""
    return _check_name(
        name,
        max_len=50,
        allow_whitespace=True,
        alnum_only=True,
    )


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
    """Thin wrapper for `pgnet.util.Connection`.

    Provides serialization and deserialization.
    """

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
    """`pgnet.Game` instance wrapper for management by server."""

    game: Game = field(repr=False)
    name: str
    password: str
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

    def get_lobby_info(self) -> str:
        """Called by the server to get game info."""
        return self.game.get_lobby_info()

    @property
    def expired(self) -> bool:
        """If the game is empty and not persistent."""
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

    Subclass from `pgnet.Game` and pass it as the *`game`* argument for the server.
    Then, use the `Server.async_run` coroutine to start the server.

    By default, the server is configured to listen on localhost. To listen
    globally, set *`listen_globally`* and *`admin_password`*.

    For games to save and load, *`save_file`* must be set (see also:
    `pgnet.Game.get_save_string`).

    .. note:: Most home networks require port forwarding to be discoverable by remote
        clients.
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
        require_user_password: bool = False,
        on_connection: Optional[Callable[[str, bool], Any]] = None,
        verbose_logging: bool = False,
        save_file: Optional[str | Path] = None,
    ):
        """Initialize the server.

        Args:
            listen_globally: Listen globally instead of localhost only.
                Requires that *`admin_password`* must be set.
            port: Port number to listen on.
            admin_password: Password for admin user with elevated priviliges.
            registration_enabled: Allow new users to register.
            require_user_password: Require that users have non-empty passwords.
            on_connection: Callback for when a username connects or disconnects.
            verbose_logging: Log *all* packets and responses.
            save_file: Location of file to save and load server sessions.
        """
        if listen_globally and not admin_password:
            logger.warning(
                "Created server that listens globally without admin password."
            )
        admin_password = admin_password or DEFAULT_ADMIN_PASSWORD
        self._key: Key = Key()
        self._stop: Optional[asyncio.Future] = None
        self._require_user_password = require_user_password
        self._users: dict[str, User] = dict()
        self._register_user(ADMIN_USERNAME, admin_password)
        self._games: dict[str, LobbyGame] = {}
        self._connections: dict[str, Optional[UserConnection]] = {}
        self._deleted_users: set[str] = set()
        self._invite_codes: dict[str, str] = {}
        self._game_cls: Type[Game] = game
        self._save_file: Optional[Path] = None if save_file is None else Path(save_file)
        self._address: str = "" if listen_globally else "localhost"
        self._port: int = port
        self.registration_enabled: bool = registration_enabled
        self.on_connection: Optional[Callable[[str, bool], Any]] = on_connection
        self.verbose_logging: bool = verbose_logging
        self._load_from_disk()
        logger.debug(f"{self._save_file=}")
        logger.debug(f"{self._game_cls=}")
        logger.debug(f"{self._key=}")
        print(f"{admin_password=}")  # Use print instead of logger for password

    async def async_run(self, *, on_start: Optional[Callable] = None) -> int:
        """Start the server.

        The server will listen for connections and pass them off to the
        connection handler.

        Args:
            on_start: Callback for when the server is online and handling messages.

        Returns:
            Exit code as given by the `shutdown` command. A value of -1 indicates a
                request to reboot.
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
        """Stop the server.

        The *result* is passed as the return value (exit code) for `Server.async_run`.
        """
        if self._stop and not self._stop.done():
            self._stop.set_result(result)

    def delete_user(self, username: str):
        """Disconnect and delete a given username from the server."""
        if username == ADMIN_USERNAME:
            logger.warning("Cannot delete admin.")
            return
        if username in self._connections:
            self._deleted_users.add(username)
        else:
            self._delete_user(username)

    @property
    def pubkey(self) -> str:
        """Public key used for end to end encryption."""
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
            username = connection.username
            if username in self._users and username in self._deleted_users:
                self._delete_user(connection.username)

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
                status=Status.BAD,
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
        password = packet.payload.get("password", "")
        invite_code = packet.payload.get("invite_code", "")
        fail = self._check_auth(username, password, invite_code)
        if fail:
            # Respond with problem and disconnect
            response = Response(fail, status=Status.BAD, disconnecting=True)
            await connection.send(response)
            raise DisconnectedError("Failed to authenticate.")
        connection.username = username
        logger.debug(f"Assigned username: {connection}")
        if username == ADMIN_USERNAME:
            logger.warning(f"Authenticated as admin: {connection}")
        await connection.send(Response("Authenticated."))

    def _check_auth(
        self,
        username: str,
        password: str,
        invite_code: str,
    ) -> Optional[str]:
        """Return failure reason or None."""
        if not username:
            return "Missing non-empty username."
        if username in self._deleted_users:
            return "User deleted."
        if username in self._connections:
            return "Username already connected."
        if username not in self._users:
            return self._try_register_user(username, password, invite_code)
        user = self._users[username]
        if not user.compare_password(password):
            return "Incorrect password."
        return None

    def _try_register_user(
        self,
        username: str,
        password: str,
        invite_code: str,
    ) -> Optional[str]:
        """Return failure reason or None."""
        if invite_code:
            invite_username = self._invite_codes.get(invite_code)
            wrong_code = invite_username is None
            invite_valid = username == invite_username or invite_username == ""
            if wrong_code or not invite_valid:
                return "Incorrect username or invite code."
        if not (self.registration_enabled or invite_code):
            return "Registration blocked."
        if self._require_user_password and not password:
            return "User password required."
        if not is_username_allowed(username):
            return "Username not allowed."
        self._register_user(username, password)
        if invite_code:
            del self._invite_codes[invite_code]
        return None

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
            if username in self._deleted_users:
                response = Response("User deleted.", disconnecting=True)
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
        # Find builtin handler
        request_handler = self._request_handlers.get(packet.message)
        if request_handler:
            return request_handler(self, packet)
        # Find game handler
        game_name: Optional[str] = self._connections[packet.username].game
        if game_name:
            return self._handle_game_packet(packet, game_name)
        # No handler found - not in game and not a builtin request
        return Response(
            "Please create/join a game.",
            self._canned_response_payload | dict(packet=packet.debug_repr),
            status=Status.UNEXPECTED,
        )

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
        logger.debug(f"User {username!r} removed from {game}")

    def _delete_user(self, username: str):
        assert username in self._users and username not in self._connections
        del self._users[username]
        if username in self._deleted_users:
            self._deleted_users.remove(username)
        logger.info(f"Deleted {username=}")

    @_user_packet_handler()
    def _handle_game_dir(self, packet: Packet) -> Response:
        """Create a Response with dictionary of games details."""
        games_dict = {}
        for name, game in self._games.items():
            games_dict[game.name] = dict(
                name=game.name,
                users=len(game.connected_users),
                password_protected=game.password_protected,
                info=game.get_lobby_info(),
            )
        return Response("See payload for games directory.", dict(games=games_dict))

    def _create_game(
        self,
        name: str,
        password: str = "",
        game_data: Optional[str] = None,
    ) -> LobbyGame:
        """Create a new game."""
        assert name not in self._games
        game = self._game_cls(name, save_string=game_data)
        lobbygame = LobbyGame(game, name, password)
        self._games[name] = lobbygame
        logger.debug(f"Created game: {lobbygame}")
        return lobbygame

    def _destroy_game(self, game_name: str):
        """Destroy an existing game."""
        game = self._games[game_name]
        while game.connected_users:
            self._remove_user_from_game(list(game.connected_users)[0])
        if game_name in self._games:
            del self._games[game_name]
        logger.debug(f"Destroyed game: {game_name!r}")

    @_user_packet_handler()
    def _handle_join_game(
        self,
        packet: Packet,
        /,
        *,
        name: str = "",
    ) -> Response:
        """Handle a request to join a game."""
        game_name = name
        connection = self._connections[packet.username]
        current_name: Optional[str] = connection.game
        if current_name:
            return Response("Must leave game first.", status=Status.UNEXPECTED)
        if not game_name:
            return Response("Please specify a game name.", status=Status.UNEXPECTED)
        if game_name == current_name:
            return Response("Already in game.", status=Status.UNEXPECTED)
        game = self._games.get(game_name)
        if not game:
            return self._handle_create_game(packet)
        password = packet.payload.get("password", "")
        fail = game.add_user(packet.username, password)
        if fail:
            return Response(f"Failed to join game: {fail}", status=Status.UNEXPECTED)
        connection.game = game_name
        logger.debug(f"User {packet.username!r} joined: {game}")
        return Response(
            f"Joined game: {game_name!r}.",
            dict(heartbeat_rate=game.heartbeat_rate),
        )

    @_user_packet_handler()
    def _handle_leave_game(self, packet: Packet) -> Response:
        """Handle a request to leave the game."""
        game_name: Optional[str] = self._connections[packet.username].game
        if not game_name:
            return Response("Not in game.", status=Status.UNEXPECTED)
        self._remove_user_from_game(packet.username)
        logger.debug(f"User {packet.username!r} left game: {game_name!r}")
        return Response(f"Left game: {game_name!r}.")

    @_user_packet_handler()
    def _handle_create_game(
        self,
        packet: Packet,
        /,
        *,
        name: str = "",
        password: str = "",
    ) -> Response:
        """Handle request to create a new game specified in the payload."""
        game_name = name
        connection = self._connections[packet.username]
        current_game = connection.game
        if current_game:
            return Response("Must leave game first.", status=Status.UNEXPECTED)
        if not is_gamename_allowed(game_name):
            return Response("Game name not allowed.", status=Status.UNEXPECTED)
        if game_name in self._games:
            return Response("Game name already exists.", status=Status.UNEXPECTED)
        game = self._create_game(game_name, password)
        fail = game.add_user(packet.username, password)
        assert not fail
        connection.game = game_name
        logger.debug(f"User {packet.username!r} created game: {game}")
        return Response(
            f"Created new game: {game_name!r}.",
            dict(heartbeat_rate=game.heartbeat_rate),
        )

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

    @_user_packet_handler()
    def _handle_help(self, packet: Packet) -> Response:
        requests = dict()
        for name, f in self._request_handlers.items():
            requests[name] = {
                name: param.annotation.__name__
                for name, param in _get_packet_handler_params(f).items()
            }
        return Response("See payload for requests.", requests)

    # Admin commands
    @_user_packet_handler(admin=True)
    def _admin_shutdown(self, packet: Packet) -> Response:
        """Shutdown the server."""
        self.shutdown()
        return Response("Shutting down...")

    @_user_packet_handler(admin=True)
    def _admin_create_invite(
        self,
        packet: Packet,
        /,
        *,
        username: str = "",
    ) -> Response:
        """Create an invite code. Can optionally by for a specific username."""
        code = os.urandom(2).hex()
        self._invite_codes[code] = username
        return Response(f"Created invite code: {code}")

    @_user_packet_handler(admin=True)
    def _admin_register(
        self,
        packet: Packet,
        /,
        *,
        set_as: bool = False,
    ) -> Response:
        """Set user registration."""
        self.registration_enabled = set_as
        return Response(f"Registration enabled: {set_as}")

    @_user_packet_handler(admin=True)
    def _admin_delete_user(
        self,
        packet: Packet,
        /,
        *,
        username: str = ""
    ) -> Response:
        """Delete a user by name."""
        if username not in self._users:
            return Response(f"No such username {username!r}")
        self.delete_user(username)
        return Response(f"Requested delete user {username!r}")

    @_user_packet_handler(admin=True)
    def _admin_destroy_game(
        self,
        packet: Packet,
        /,
        *,
        name: str = "",
    ) -> Response:
        """Destroy a game by name."""
        game_name = name
        if game_name not in self._games:
            return Response(f"No such game: {game_name!r}", status=Status.UNEXPECTED)
        self._destroy_game(game_name)
        return Response(f"Destroyed game: {game_name!r}")

    @_user_packet_handler(admin=True)
    def _admin_save(self, packet: Packet) -> Response:
        """Save all server data to file."""
        success = self._save_to_disk()
        return Response(f"Saved {success=} server data to disk: {self._save_file}")

    @_user_packet_handler(admin=True)
    def _admin_verbose(
        self,
        packet: Packet,
        /,
        *,
        set_as: bool = False,
    ) -> Response:
        """Set verbose logging."""
        self.verbose_logging = set_as
        return Response(f"Verbose logging enabled: {set_as}")

    @_user_packet_handler(admin=True)
    def _admin_debug(self, packet: Packet) -> Response:
        """Return debugging info."""
        games = [str(game) for name, game in sorted(self._games.items())]
        connected_users = [str(conn) for u, conn in sorted(self._connections.items())]
        all_users = sorted(self._users.keys())
        payload = dict(
            packet=packet.debug_repr,
            pubkey=self.pubkey,
            games=games,
            connected_users=connected_users,
            all_users=all_users,
            registration=self.registration_enabled,
            invite_codes=self._invite_codes,
            deleted_users=list(self._deleted_users),
            verbose=self.verbose_logging,
        )
        return Response("Debug", payload)

    @_user_packet_handler(admin=True)
    def _admin_sleep(self, packet: Packet, /, *, seconds: float = 1) -> Response:
        """Simulate slow response by blocking for the time specified in payload.

        Warning: this actually blocks the entire server. Time is capped at 5 seconds.
        """
        max_sleep = 5
        seconds = min(max_sleep, seconds)
        time.sleep(seconds)
        return Response(f"Slept for {seconds} seconds")

    def _save_to_disk(self) -> bool:
        """Save all data to disk."""
        if not self._save_file:
            return False
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
            games=game_data,
            registration=self.registration_enabled,
            invite_codes=self._invite_codes,
        )
        dumped = json.dumps(data, indent=4)
        self._save_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self._save_file, "w") as f:
            f.write(dumped)
        logger.debug(
            f"Saved server data to {self._save_file}"
            f" ({len(users)} users and {len(game_data)} games)"
        )
        return True

    def _load_from_disk(self):
        if not self._save_file or not self._save_file.is_file():
            return
        logger.info(f"Loading server data from {self._save_file}")
        with open(self._save_file) as f:
            data = f.read()
        data = json.loads(data)
        for user in data["users"]:
            username = user["name"]
            if username == ADMIN_USERNAME:
                continue
            if not is_username_allowed(username):
                logger.warning(f"Loaded disallowed {username=}")
            self._users[username] = u = User(username, user["salt"], user["password"])
            logger.debug(f"Loaded username: {u!r}")
        for game in data["games"]:
            game_name = game["name"]
            if not is_gamename_allowed(game_name):
                logger.warning(f"Loaded disallowed {game_name=}")
            self._create_game(game_name, game["password"], game["data"])
            logger.debug(f"Loaded game: {self._games[game_name]!r}")
        self._invite_codes |= data["invite_codes"]
        self.registration_enabled = data["registration"]
        logger.debug("Loading disk data complete.")

    def __repr__(self):
        """Object repr."""
        address = self._address or "public"
        return (
            f"<{self.__class__.__qualname__}"
            f" serving {address}:{self._port}"
            f" @ {id(self):x}>"
        )

    _request_handlers = {
        Request.HELP: _handle_help,
        Request.GAME_DIR: _handle_game_dir,
        Request.CREATE_GAME: _handle_create_game,
        Request.JOIN_GAME: _handle_join_game,
        Request.LEAVE_GAME: _handle_leave_game,
        Request.DEBUG: _admin_debug,
        Request.SAVE: _admin_save,
        Request.CREATE_INVITE: _admin_create_invite,
        Request.DESTROY_GAME: _admin_destroy_game,
        Request.DELETE_USER: _admin_delete_user,
        Request.REGISTRATION: _admin_register,
        Request.VERBOSE: _admin_verbose,
        Request.SLEEP: _admin_sleep,
        Request.SHUTDOWN: _admin_shutdown,
    }
    _canned_response_payload = dict(commands=list(_request_handlers.keys()))


__all__ = (
    "Server",
    "LobbyGame",
    "User",
    "UserConnection",
    "is_username_allowed",
    "is_gamename_allowed",
)
