"""Simple example for demonstration."""

import asyncio
import pgnet
import sys


class MyGame(pgnet.BaseGame):
    """Example class for game logic."""

    def handle_packet(self, packet: pgnet.Packet) -> pgnet.Response:
        """Game logic goes here."""
        username = packet.username
        message = packet.message
        return pgnet.Response(f"Received {message!r} from {username!r}.")


class MockUI:
    """Mock UI as if a user is using a GUI."""

    def __init__(self, client: pgnet.BaseClient):
        """Bind to client events to simulate user doing things."""
        self.client = client
        self.client.on_status = self.on_status
        self.client.on_connection = self.on_connection
        self.client.on_game = self.on_game

    def on_status(self, status: str):
        """When the client status changes, print to console."""
        print(f"Client status: {status}")

    def on_connection(self, connected: bool):
        """When we connect to the server, create and join a game."""
        if connected:
            self.client.create_game("My game", password="abcd")

    def on_game(self, game_name: str):
        """When we join a game, send a packet and disconnect when response returns."""
        self.client.send(pgnet.Packet("Hello world."), self.disconnect)

    def disconnect(self, response: pgnet.Response):
        """Close the client."""
        print(f"Got response from server: {response.message}")
        print("Closing the client.")
        self.client.close()


async def run_client():
    """Create a client, pass it to the mock UI and connect."""
    local_client = pgnet.LocalhostClient(MyGame, username="thelegend27")
    remote_client = pgnet.BaseClient(
        address="1.23.23.1",
        username="thelegend27",
        password="1234",
    )
    client = local_client or remote_client
    # These two clients use exactly the same API, but the localhost client uses
    # it's own local server instead of connecting to a remote.
    MockUI(client)
    await client.async_connect()


async def run_server():
    """Run the server to host the `MyGame` class."""
    server = pgnet.BaseServer(MyGame)
    asyncio.create_task(server.async_run())
    print("Shutting down the server in 3 seconds...")
    await asyncio.sleep(3)
    server.shutdown()


if __name__ == "__main__":
    if len(sys.argv) == 1:
        asyncio.run(run_client())
    else:
        asyncio.run(run_server())
