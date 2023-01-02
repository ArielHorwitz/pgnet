""".. include:: ../README.md

# Getting started

A general overview of communications:
> `<Packet> GUI -> Client -> Server -> Game`

> `<Response> GUI <- Client <- Server <- Game`


PGNet aims to enable an easy-to-use implementation of the communication between clients
and a game object, requiring minimal or no code to connect via a server. The GUI is not
in the scope of this library (for a GUI solution consider [mousefox](
https://github.com/ArielHorwitz/mousefox)).


## Game logic
The purpose of the `BaseGame` class is to:
* Receive notifications when users join or leave
* Handle a `Packet` from a user and return a `Response` (see:
    `BaseGame.handle_game_packet`)
* Implement the `BaseGame.handle_heartbeat` method (for automatic game updates)
* Export and load (save game state)

The purpose of the `BaseClient` class is to:
* Connect and login to a server
* Browse, create, join, and leave games
* Send a `Packet` to the game object and receive a `Response` (see: `BaseClient.send`)
* Implement the `BaseClient.on_heartbeat` method (for automatic game updates)

Once you have a client and game class, there are two ways to run a server and allow them
to connect and communicate: localhost or remote.

## Running a localhost server
To run a localhost server, use `BaseClient.async_connect_localhost` and pass the game
class. This option is good for testing or for playing the game as a single player
without modifying anything in the client or game.

## Running the server directly
To run a server directly, use `BaseServer.async_run` and pass the game class. Clients
can then connect remotely using `BaseClient.async_connect`.

.. warning:: For remote clients to find the server, proper configuration is required.
    See `BaseServer`.

<br><br><br><hr><br><br><br>
"""

# flake8: noqa  - Errors due to imports we do for the pgnet API.


from .util import (
    Packet,
    Response,
    BaseGame,
    enable_logging,
    STATUS_OK,
    STATUS_BAD,
    STATUS_UNEXPECTED,
    DEFAULT_PORT,
)
from . import util, client, server, devclient
from .server import BaseServer
from .client import BaseClient

__all__ = (
    "BaseGame",
    "BaseClient",
    "BaseServer",
    "Packet",
    "Response",
    "STATUS_OK",
    "STATUS_BAD",
    "STATUS_UNEXPECTED",
    "enable_logging",
    "DEFAULT_PORT",
    "util",
    "client",
    "server",
    "devclient",
)
