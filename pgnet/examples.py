"""A simple example implementation of a game and client."""

import functools
from typing import Optional
from .client import Client
from .util import Game, Packet, Response


class ExampleGame(Game):
    """A subclass of `pgnet.Game` as a simple example.

    Maintains a log of strings, that users can get and add to.
    """

    persistent = True

    def __init__(self, *args, save_string: Optional[str] = None, **kwargs):
        """On initialization, import log from *save_string*."""
        super().__init__(*args, **kwargs)
        self.log = list(save_string.splitlines()) if save_string else ["Game started"]

    def user_joined(self, username: str):
        """Add log message on user join."""
        self.log.append(f"Joined: {username}")

    def user_left(self, username: str):
        """Add log message on user leave."""
        self.log.append(f"Left: {username}")

    def handle_game_packet(self, packet: Packet) -> Response:
        """Add log message and return full log."""
        self.log.append(f"{packet.username} says: {packet.message!r}")
        return Response("Message added.")

    def handle_heartbeat(self, packet: Packet) -> Response:
        """Return latest log messages."""
        return Response("Latest log entries.", payload=dict(log=self.log[-10:]))

    def get_save_string(self) -> str:
        """Export the log."""
        return "\n".join(self.log)


class ExampleClient(Client):
    """Client subclass to implement heartbeat for `ExampleGame`."""

    log = []
    on_status = functools.partial(print, ">> STATUS:")
    on_game = functools.partial(print, ">> GAME:")

    def on_heartbeat(self, heartbeat: Response):
        """Save and print the log if changed."""
        game_log = heartbeat.payload.get("log", ["Empty log"])
        if self.log != game_log:
            self.log = game_log
            print("New log:")
            print("\n".join(f"-- {_}" for _ in game_log))

    def on_connection(self, connected: bool):
        """Automatically create and join a game when connected."""
        print(">> CONNECTION:", connected)
        if connected:
            self.create_game("test")  # Will auto join if created
            # self.join_game("test")  # Use this in case game already exists


__all__ = (
    "ExampleGame",
    "ExampleClient",
)
