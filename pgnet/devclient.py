"""Developer client - command line tool to interface with a server."""

from typing import Optional, Type
import sys
import functools
import arrow
import asyncio
import aioconsole
from .client import BaseClient
from .localhost import LocalhostClient
from .util import (
    Packet,
    Response,
    BaseGame,
    DEFAULT_PORT,
    ADMIN_USERNAME,
    DEFAULT_ADMIN_PASSWORD,
)


class DevGame(BaseGame):
    """A subclass of BaseGame for simple testing purposes."""

    persistent = True

    def __init__(self, *args, save_string: Optional[str] = None, **kwargs):
        """Initialization."""
        super().__init__(*args, **kwargs)
        self.log = list(save_string.splitlines()) if save_string else ["Game started"]

    def user_joined(self, username: str):
        """Overridden callback."""
        print(f"Joined: {username=}")
        self.log.append(f"Joined: {username}")

    def user_left(self, username: str):
        """Overridden callback."""
        print(f"Left: {username=}")
        self.log.append(f"Left: {username}")

    def get_save_string(self) -> str:
        """Overriden base method."""
        return "\n".join(self.log)


class DevClient:
    """A CLI client."""

    def __init__(self, client: BaseClient):
        """A CLI client."""
        self.client = client

    async def run(self) -> int:
        """Run the client."""
        conn_task = asyncio.create_task(self.client.async_connect())
        cli_task = asyncio.create_task(self._async_cli())
        combined_task = asyncio.wait(
            (conn_task, cli_task),
            return_when=asyncio.FIRST_COMPLETED,
        )
        await combined_task
        if not conn_task.done():
            self.client.close()
            await asyncio.wait_for(conn_task, timeout=1)

    def _close(self, *args):
        self.client.close()

    async def _async_cli(self):
        while not self.client.connected:
            await asyncio.sleep(0.1)
        while True:
            uinput = await aioconsole.ainput(">> ")
            if uinput == "quit":
                return
            packet = _parse_cli_packet(uinput)
            if packet:
                await self._relay_packet(packet)

    async def _relay_packet(self, packet):
        print(packet.debug_repr)
        print(f"    SENT: {arrow.now().for_json()}")
        response = asyncio.Future()
        self.client.send(packet, lambda sr, r=response: r.set_result(sr))
        await response
        _log_response(response.result())


def _parse_cli_packet(s: str, /) -> Optional[Packet]:
    try:
        parts = s.split(";")
        message = parts.pop(0)
        payload = {}
        for p in parts:
            key, value = p.split("=", 1)
            if value.isnumeric():
                i, f = int(value), float(value)
                value = i if i == f else f
            payload[key] = value
    except ValueError as e:
        print(
            "Bad CLI request format, expected: "
            f"'message_str;key1=value1;key2=value2'\n{e}"
        )
        return None
    return Packet(message, payload)


def _log_response(response: Response):
    strs = [
        f"RECEIVED: {arrow.now().for_json()}",
        response.debug_repr,
        "-" * 20,
        f"MESSAGE:  {response.message}",
    ]
    if len(tuple(response.payload.keys())):
        strs.extend([
            "PAYLOAD:",
            *(f"{k:>20} : {v}" for k, v in response.payload.items()),
        ])
    print("\n".join(strs))
    print("=" * 20)


async def async_run(
    *,
    remote: bool = False,
    game: Type[BaseGame] = DevGame,
    server_kwargs: Optional[dict] = None,
) -> int:
    """Run the CLI client for admins and developers."""
    username = ADMIN_USERNAME
    password = DEFAULT_ADMIN_PASSWORD
    kw = dict(
        on_connection=functools.partial(print, ">> CONN:"),
        on_status=functools.partial(print, ">> STATUS:"),
        on_game=functools.partial(print, ">> GAME:"),
    )
    if remote:
        address = input("Enter address (leave blank for localhost): ") or "localhost"
        port = int(input("Enter port (leave blank for default): ") or DEFAULT_PORT)
        username = input("Enter username (leave blank for admin): ") or username
        password = input("Enter password (leave blank for default): ") or password
        pubkey = input("Enter pubkey to verify (leave blank to ignore): ") or None
        client = BaseClient(
            address=address,
            port=port,
            username=username,
            password=password,
            verify_server_pubkey=pubkey,
            **kw,
        )
    else:
        client = LocalhostClient(
            username=ADMIN_USERNAME,
            password=DEFAULT_ADMIN_PASSWORD,
            game=game,
            server_kwargs=server_kwargs,
            **kw,
        )
    await DevClient(client).run()


def run():
    """Main script entry point for the devclient."""
    remote = len(sys.argv) > 1 and sys.argv[1] == "-r"
    asyncio.run(async_run(remote=remote))
