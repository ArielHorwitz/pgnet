# PGNet

PGNet is a server-client framework for games written in Python.


### Features
* Minimum effot to connect game to server, and client to UI
* A single server can host many games in a lobby automagically
* Localhost client that saves you from writing separate interfaces for local and online
    play
* CLI client for developers and server admins
* Network I/O (using [websockets](https://github.com/aaugustin/websockets))
* End-to-end encryption (using [PyNaCl](https://github.com/pyca/pynacl))
* Hopefully a concise API

### Notably lacking features
* Any sort of concurrency beyond async on a single thread (bad for real-time or
    CPU-intensive games)
* Documentation
* Tests


## Install and run
Install using pip:

```pip install git+ssh://git@github.com/ArielHorwitz/pgnet.git```


### Server

```python3
import asyncio
import pgnet


class Game(pgnet.BaseGame):
    def handle_packet(self, packet: pgnet.Packet) -> pgnet.Response:
        # Game logic goes here
        username = packet.username
        message = packet.message
        payload = packet.payload
        return pgnet.Response(f"Received {message!r} from {username!r}.")


def run_server():
    server = pgnet.BaseServer(Game)
    asyncio.run(server.async_run())


if __name__ == "__main__":
    run_server()
```

### Client

```python3
# These two clients have exactly the same API, but the localhost client uses
# it's own local server instead of connecting to a remote.
local_client = pgnet.LocalhostClient(Game)
remote_client = pgnet.BaseClient(
    address="1.23.23.1",
    username="thelegend27",
    password="1234",
)
client = local_client or remote_client

# Connect and login to the server
asyncio.create_task(client.async_connect())

# ... When connected (client.on_connected):
client.create_game("My game", password="abcd")

# ... When joined (client.on_game):
client.send(pgnet.Packet("Hello world."), response_callback)
```

For a simple working example, see [`example.py`](/example.py).
