"""Developer client - command line tool to interface with a server."""

from typing import Optional
import sys
import functools
import arrow
import asyncio
import aioconsole
from .client import Client
from .util import (
    Packet,
    Response,
    Game,
    DEFAULT_PORT,
    ADMIN_USERNAME,
    DEFAULT_ADMIN_PASSWORD,
)


class DevGame(Game):
    """A subclass of `Game` for simple testing purposes.

    Maintains a log of strings, that users can get and add to.
    """

    persistent = True

    def __init__(self, *args, save_string: Optional[str] = None, **kwargs):
        """On initialization, import log from *save_string*."""
        super().__init__(*args, **kwargs)
        self.log = list(save_string.splitlines()) if save_string else ["Game started"]

    def user_joined(self, username: str):
        """Add log message on user join."""
        self.log.append(f"Joined: {username}")

    def user_left(self, username: str):
        """Add log message on user leave."""
        self.log.append(f"Left: {username}")

    def handle_game_packet(self, packet: Packet) -> Response:
        """Add log message and return full log."""
        self.log.append(f"{packet.username} says: {packet.message!r}")
        return Response("Message added.")

    def handle_heartbeat(self, packet: Packet) -> Response:
        """Return latest log messages."""
        return Response("Latest log entries.", dict(log=self.log[-10:]))

    def get_save_string(self) -> str:
        """Export the log."""
        return "\n".join(self.log)


class DevClient(Client):
    """Client subclass to implement heartbeat for `DevGame`."""

    on_connection = functools.partial(print, ">> CONNECTION:")
    on_status = functools.partial(print, ">> STATUS:")
    on_game = functools.partial(print, ">> GAME:")
    log = []

    def on_heartbeat(self, heartbeat: Response):
        """Save and print the log if changed."""
        game_log = heartbeat.payload.get("log", ["Empty log"])
        if self.log != game_log:
            self.log = game_log
            print("New log:")
            print("\n".join(game_log))


class DevCLI:
    """A CLI for the PGNet client."""
    client = DevClient()

    async def async_run(self, remote: bool):
        """Run the command-line devclient.

        Args:
            remote: Connect to a remote server, prompting the user for connection
                details, otherwise run a localhost server using `DevGame`.
        """
        conn_coro = self._connect(remote)
        conn_task = asyncio.create_task(conn_coro)
        cli_task = asyncio.create_task(self._cli())
        combined_task = asyncio.wait(
            (conn_task, cli_task),
            return_when=asyncio.FIRST_COMPLETED,
        )
        await combined_task
        if not conn_task.done():
            self.client.close()
            await asyncio.wait_for(conn_task, timeout=1)

    async def _connect(self, remote: bool):
        username = ADMIN_USERNAME
        password = DEFAULT_ADMIN_PASSWORD
        username = input("Enter username (leave blank for admin): ") or username
        password = input("Enter password (leave blank for admin default): ") or password
        if not remote:
            await self.client.async_connect_localhost(
                DevGame,
                username=username,
                password=password,
            )
            return
        address = input("Enter address (leave blank for localhost): ") or "localhost"
        port = int(input("Enter port (leave blank for default): ") or DEFAULT_PORT)
        pubkey = input("Enter pubkey to verify (leave blank to ignore): ") or None
        await self.client.async_connect(
            address=address,
            port=port,
            username=username,
            password=password,
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

    If any arguments are found in `sys.argv` then it will connect to a remote server,
    otherwise will run a localhost server with `DevGame`.
    """
    remote = len(sys.argv) > 1 and sys.argv[1] == "-r"
    asyncio.run(DevCLI().async_run(remote=remote))
