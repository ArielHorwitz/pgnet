"""Developer client - command line tool to interface with a server."""

from typing import Optional
import sys
import functools
import arrow
import asyncio
import aioconsole
from .client import BaseClient
from .localhost import LocalhostClient
from .common import (
    Packet,
    Response,
    BaseGame,
    DEFAULT_PORT,
    ADMIN_USERNAME,
    DEFAULT_ADMIN_PASSWORD,
)


def run() -> int:
    """Run a CLI client for developers."""
    username = ADMIN_USERNAME
    password = DEFAULT_ADMIN_PASSWORD
    kw = dict(
        on_connection=functools.partial(print, "conn"),
        on_status=functools.partial(print, "status"),
        on_game=functools.partial(print, "game"),
        on_games_dir=functools.partial(print, "games dir"),
    )
    if len(sys.argv) > 1 and sys.argv[1] == "-r":
        address = input("Enter address (leave blank for localhost): ") or "localhost"
        port = int(input("Enter port (leave blank for default): ") or DEFAULT_PORT)
        username = input("Enter username (leave blank for admin): ") or username
        password = input("Enter password (leave blank for default): ") or password
        client = BaseClient(
            username=username,
            password=password,
            address=address,
            port=port,
            **kw,
        )
    else:
        client = LocalhostClient(
            game=DevGame,
            username=ADMIN_USERNAME,
            password=DEFAULT_ADMIN_PASSWORD,
            **kw,
        )
    return asyncio.run(DevClient(client).run())


class DevGame(BaseGame):
    """A subclass of BaseGame for simple testing purposes."""

    def add_user(self, username: str):
        """Overridden callback."""
        print(f"Add: {username=}")

    def remove_user(self, username: str):
        """Overridden callback."""
        print(f"Remove: {username=}")


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
        if cli_task.done():
            return_code = cli_task.result()
        else:
            return_code = 0
        return return_code

    def _close(self, *args):
        self.client.close()

    async def _async_cli(self):
        while True:
            uinput = await aioconsole.ainput(">> ")
            if uinput == "quit":
                return 0
            if uinput == "restart":
                return -1
            if uinput == "games":
                await self.client._async_update_games_dir()
                continue
            packet = _parse_cli_packet(uinput)
            await self._relay_packet(packet)

    async def _relay_packet(self, packet):
        print(packet.debug_repr)
        print(f"    SENT: {arrow.now().for_json()}")
        if self.client.game:
            response = asyncio.Future()
            self.client.queue(packet, lambda sr, r=response: r.set_result(sr))
            await response
            _log_response(response.result())
        elif self.client._websocket:
            response = await self.client._async_send(self.client._websocket, packet)
            _log_response(response)
        else:
            print("NO CONNECTION.")


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
