"""Developer client - command line tool to interface with a server."""

from typing import Optional
import sys
import arrow
import asyncio
import aioconsole
from .server import Server
from .util import (
    Packet,
    Response,
    DEFAULT_PORT,
    ADMIN_USERNAME,
    DEFAULT_ADMIN_PASSWORD,
)
from .examples import ExampleGame, ExampleClient


class DevCLI:
    """A CLI for the pgnet client."""

    async def async_run(self, remote: bool):
        """Run the command-line devclient.

        Args:
            remote: Connect to a remote server, otherwise run a local server using
                `DevGame`.
        """
        self.client = self._get_client(remote)
        conn_coro = self.client.async_connect()
        conn_task = asyncio.create_task(conn_coro)
        cli_task = asyncio.create_task(self._cli())
        combined_task = asyncio.wait(
            (conn_task, cli_task),
            return_when=asyncio.FIRST_COMPLETED,
        )
        await combined_task
        if not conn_task.done():
            self.client.disconnect()
            await asyncio.wait_for(conn_task, timeout=1)

    def _get_client(self, remote: bool):
        username = ADMIN_USERNAME
        password = DEFAULT_ADMIN_PASSWORD
        username = input("Enter username (leave blank for admin): ") or username
        password = input("Enter password (leave blank for admin default): ") or password
        if not remote:
            return ExampleClient.local(
                game=ExampleGame,
                username=username,
                password=password,
            )
        address = input("Enter address (leave blank for localhost): ") or "localhost"
        port = int(input("Enter port (leave blank for default): ") or DEFAULT_PORT)
        pubkey = input("Enter pubkey to verify (leave blank to ignore): ") or ""
        return ExampleClient.remote(
            username=username,
            password=password,
            address=address,
            port=port,
            verify_server_pubkey=pubkey,
        )

    async def _cli(self):
        while not self.client.connected:
            await asyncio.sleep(0.1)
        while True:
            uinput = await aioconsole.ainput(">> ")
            if uinput == "quit":
                return
            packet = self._parse_cli_packet(uinput)
            if packet:
                await self._send_packet(packet)

    async def _send_packet(self, packet):
        print(packet.debug_repr)
        print(f"    SENT: {arrow.now().for_json()}")
        response = asyncio.Future()
        self.client.send(packet, lambda sr, r=response: r.set_result(sr))
        await response
        self._log_response(response.result())

    @staticmethod
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

    @staticmethod
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


def run():
    """Main script entry point for the devclient.

    Will parse the first argument from `sys.argv`:
    * `no argument`: run locally using `pgnet.ExampleClient` and `pgnet.ExampleGame`
    * `"-s"` or `"--server"`: run a server using `pgnet.ExampleGame`
    * `"-r"` or `"--remote"`: connect to a remote server
    """
    arg = None
    if len(sys.argv) > 1:
        arg = sys.argv[1]
    if arg in {"-s", "--server"}:
        asyncio.run(Server(ExampleGame).async_run())
    elif arg in {"-r", "--remote"}:
        asyncio.run(DevCLI().async_run(remote=True))
    else:
        asyncio.run(DevCLI().async_run(remote=False))


__all__ = (
    "run",
)
