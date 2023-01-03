""".. include:: ../README.md

# Getting started
Starting "locally" is recommended since the client will create its own server. It
behaves the same, but faster and with no configuration required. This is enough for
local testing and single player mode.

To get started, prepare a `Game` class and a `Client` class. Consider
`pgnet.examples.ExampleGame` and `pgnet.examples.ExampleClient`. The UI is expected to
be event-driven and yield to the asyncio event loop. For a GUI solution, consider
*[mousefox](https://github.com/ArielHorwitz/mousefox)*.

## Local server
Create a local client:
```python3
client = Client.local(game=Game, username="player")
```

When the UI is ready, run `Client.async_connect`. For example:
```python3
import asyncio

asyncio.create_task(client.async_connect())
```
The connection task should run in the background, and from here on everything should be
event-driven.

When connected (or disconnected), the `Client.on_connection` event will trigger. The
ExampleClient will automatically create and join a game on the server. Otherwise you can
use:
```python3
client.create_game("SomeGameName")
```

When joining (or leaving) a game, the `Client.on_game` event will trigger. You can use
`Client.send` to send packets to the game object and set callbacks for the responses:

```python3
def response_callback(response: pgnet.Response):
    print(response)

client.send(pgnet.Packet("Hello world"), response_callback)
```

## Local server example script
This example is simply a minimal code example, and avoids using events. Normally you
should use an asynchronous and event-drive UI.
```python3
# main.py - use classes from `pgnet.examples` for demonstration

import asyncio
import pgnet

Game = pgnet.examples.ExampleGame
Client = pgnet.examples.ExampleClient

async def main():
    # Create a local client
    client = Client.local(game=Game, username="player")
    # Connect
    asyncio.create_task(client.async_connect())
    await asyncio.sleep(1)  # wait instead of using client events
    # Send a packet
    client.send(pgnet.Packet("Hello world!"), response_callback)
    await asyncio.sleep(1)  # wait instead of using client events
    # Send another packet
    client.send(pgnet.Packet("Goodbye."), response_callback)
    await asyncio.sleep(1)  # wait instead of using client events
    # Disconnect
    client.disconnect()
    await asyncio.sleep(1)  # wait instead of using client events

def response_callback(response: pgnet.Response):
    # Callback for responses. Simply print them.
    print(f"SERVER RESPONSE: {response}")

if __name__ == "__main__":
    asyncio.run(main())
```

## Game
Subclassing `Game` enables you to:
* Receive notifications when users join or leave
* Handle a `Packet` from a user and return a `Response` (see: `Game.handle_game_packet`)
* Implement the `Game.handle_heartbeat` method (for automatic game updates)
* Export and load to save game state (see `Game.get_save_string`)

## Client
Subclassing `Client` enables you to:
* Connect and login to a server (or create its own local server)
* Browse, create, join, and leave games
* Send a `Packet` to the game object and receive a `Response` (see: `Client.send`)
* Implement the `Client.on_heartbeat` method (for automatic game updates)
* Implement other client events (`Client.on_connection`, `Client.on_status`, and
    `Client.on_game`)

## Remote Server
If you wish to run the `Server` directly, e.g. to host games online for multiple users,
create a server with the game class and use `Server.async_run`:
```python3
import asyncio

server = Server(MyGame)
asyncio.run(server.async_run())
```

Users can create clients using `Client.remote` and then connect using
`Client.async_connect`:
```python3
import asyncio

client = Client.remote(address="1.2.3.4", username="player")
asyncio.create_task(client.async_connect())
```

.. warning:: For remote clients to find the server, proper configuration is required.
    See `Server`.

<br><br><br><hr><br><br><br>
"""

# flake8: noqa  - Errors due to imports we do for the pgnet API.


from .util import (
    Packet,
    Response,
    Game,
    enable_logging,
    STATUS,
    DEFAULT_PORT,
)
from . import util, client, server, examples, devclient
from .server import Server
from .client import Client
from .examples import ExampleGame, ExampleClient


__all__ = (
    "Game",
    "Client",
    "Server",
    "Packet",
    "Response",
    "STATUS",
    "enable_logging",
    "DEFAULT_PORT",
    "util",
    "client",
    "server",
    "examples",
    "devclient",
)
