"""LocalhostClient for local single player mode.

The LocalhostClient class is a subclass of BaseClient that runs its own
server when connecting, emulating a real server and maintaining the same
client interface.
"""

from typing import Type
import asyncio
from . import common
from . import client
from . import server


class LocalhostClient(client.BaseClient):
    """See module documentation for details."""

    def __init__(self, game: Type[common.BaseGame], **client_kwargs):
        """See module documentation for details.

        Args:
            game: The game class for the server.
            client_kwargs: Keyword arguments for the client.
        """
        client_kwargs.setdefault("username", "Player")
        client_kwargs.setdefault("password", "")
        client_kwargs["address"] = "localhost"
        client_kwargs["port"] = common.DEFAULT_PORT
        super().__init__(**client_kwargs)
        self._server = server.BaseServer(game)

    async def async_connect(self, *args, **kwargs):
        """Start a server and connect."""
        server_task = asyncio.create_task(self._server.async_run())
        server_task.add_done_callback(lambda *a: self.close())
        await super().async_connect(*args, **kwargs)
        self.close()

    def close(self):
        """Close the connection and server."""
        super().close()
        self._server.shutdown()
