"""LocalhostClient for local single player mode.

The LocalhostClient class is a subclass of BaseClient that runs its own
server when connecting, emulating a real server and maintaining the same
client interface.
"""

from typing import Type, Optional
import asyncio
from . import client
from . import server
from .util import BaseGame, DEFAULT_PORT


class LocalhostClientMixin:
    """See module documentation for details."""

    def __init__(
        self,
        *,
        game: Type[BaseGame],
        server_kwargs: Optional[dict] = None,
        **client_kwargs,
    ):
        """See module documentation for details.

        Args:
            game: The game class for the server.
            server_kwargs: Keyword arguments for the server.
            client_kwargs: Keyword arguments for the client.
        """
        if server_kwargs is None:
            server_kwargs = dict()
        server_kwargs["address"] = "localhost"
        server_kwargs["port"] = DEFAULT_PORT
        self._server = server.BaseServer(game, **server_kwargs)
        client_kwargs.setdefault("username", "Player")
        client_kwargs.setdefault("password", "")
        client_kwargs["address"] = "localhost"
        client_kwargs["port"] = DEFAULT_PORT
        client_kwargs["verify_server_pubkey"] = self._server.pubkey
        super().__init__(**client_kwargs)

    async def async_connect(self, *args, **kwargs):
        """Start a server, then connect."""
        started = asyncio.Future()
        server_coro = self._server.async_run(on_start=lambda *a: started.set_result(1))
        server_task = asyncio.create_task(server_coro)
        server_task.add_done_callback(lambda *a: self.close())
        await asyncio.wait((server_task, started), return_when=asyncio.FIRST_COMPLETED)
        await super().async_connect(*args, **kwargs)
        self.close()

    def close(self):
        """Close both client and server."""
        super().close()
        self._server.shutdown()


class LocalhostClient(LocalhostClientMixin, client.BaseClient):
    """See module documentation for details."""
