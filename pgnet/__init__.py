"""PGNet - an asynchronous server-client framework for games written in Python.


# Getting started
PGNet provides a `BaseClient` for the front end, enabling communication with the server.
Implementing game logic is done by subclassing `BaseGame`. This class is
passed to the back end (server or localhost client).

There are two ways to run a server: by using the `BaseServer` class, or by using a
localhost client. A localhost client will automatically create a server to connect to,
and use it as if it were a normal server. Both of these require the `BaseGame` subclass.

Once connected the client can list, create, join, and leave games. When in game, the
client and game class can communicate directly using `BaseClient.send` and
`BaseGame.handle_game_packet`.

When joining a game, it will automatically let the client know how often to
*"heartbeat"* (check for updates) which the client will do automatically. To customize
this, see `BaseGame.handle_heartbeat` and `BaseClient.on_heartbeat`.

The following are minimal code examples to get started with the basics.

## Game
Subclassing `BaseGame` to implement game logic:

```python3
import pgnet


class MyGame(pgnet.BaseGame):
    def handle_game_packet(self, packet: pgnet.Packet) -> pgnet.Response:
        # Game logic goes here
        username = packet.username
        message = packet.message
        return pgnet.Response(f"Received {message!r} from {username!r}.")
```

## Client
Our UI must be event-driven and yield to the asyncio event loop.

In this example, we will not create a UI but instead use the client's event
callbacks `BaseClient.on_connection`, `BaseClient.on_status`, and
`BaseClient.on_game` to simulate the user reacting to the server:

```python3
import asyncio
import pgnet
import time

# Disable pgnet logging so that we can more clearly see this example working
pgnet.enable_logging(False)


# Create a client
local_client = pgnet.LocalhostClient(game=MyGame)
remote_client = pgnet.BaseClient(
    address="11.22.33.44",
    username="thelegend27",
    password="1234",
)
client = local_client or remote_client  # Same API


# Defining event callbacks instead of using a UI
def _response_callback(response: pgnet.Response):
    # Print the response and disconnect.
    print(f"Disconnecting after response: {response}")
    client.close()


def on_connection(connected: bool):
    # Create a new game after connecting.
    if connected:
        client.create_game("my_game", password="abcd")


def on_status(status: str):
    # Print the client status
    print(f"Client status: {status}")
    time.sleep(1)  # Helps to better understand what is happening


def on_game(game_name: str):
    # Send a packet after joining a game.
    if game_name is not None:
        print("Sending 'Hello world' packet.")
        time.sleep(1)  # Helps to better understand what is happening
        client.send(pgnet.Packet("Hello world"), _response_callback)


# Bind client events
client.on_connection = on_connection
client.on_status = on_status
client.on_game = on_game

# Connect and login to server
asyncio.run(client.async_connect())
```

This will connect, create (and join) a game, send "Hello world", print the
response, and disconnect.

## Server
To run a server independently:

```python3
import asyncio

server = pgnet.BaseServer(MyGame)
asyncio.run(server.async_run())
```

To serve globally, the server must be configured properly (see `BaseServer`).
If running the server behind a router, ensure that port forwarding is properly
configured as well (see your router's manual).

.. note:: For regular testing, it is usually enough to use a localhost client.

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
from . import server, client, localhost, devclient, util
from .server import BaseServer
from .client import BaseClient
from .localhost import LocalhostClient

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
    "localhost",
    "devclient",
)
