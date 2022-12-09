"""Common constants and classes."""

from typing import Optional
import arrow
import json
from dataclasses import dataclass, field
import nacl.public
from nacl.encoding import Base64Encoder


DEFAULT_PORT = 38929
ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "localhostadmin"
REQUEST_GAME_DIR = "server.game_dir"
REQUEST_JOIN_GAME = "server.join_game"
REQUEST_LEAVE_GAME = "server.leave_game"
REQUEST_CREATE_GAME = "server.create_game"
STATUS_OK = 0
STATUS_BAD = 1
STATUS_UNEXPECTED = 2


class DisconnectedError(Exception):
    """Raised when a connection should no longer be open.

    It is expected that the cause of the error is passed as the first
    argument as a string.
    """
    pass


class CipherError(Exception):
    """Raised when failing to encrypt plaintext or decrypt ciphertext."""
    pass


@dataclass
class Packet:
    """The dataclass used to send messages from client to server.

    Payload must be JSON-able.
    """

    message: str
    payload: dict = field(default_factory=dict, repr=False)
    created_on: Optional[str] = None
    username: Optional[str] = None
    disconnecting: bool = False

    def __post_init__(self):  # noqa: D105
        self.created_on = self.created_on or arrow.now().for_json()

    def serialize(self) -> dict:
        """Convert into a string."""
        return json.dumps({
            k: getattr(self, k) for k in self.__dataclass_fields__.keys()
        })

    @classmethod
    def deserialize(cls, raw_data: str, /) -> "Packet":
        """Convert a string into a Packet."""
        return cls(**json.loads(raw_data))

    @property
    def debug_repr(self) -> str:
        """Repr with more data."""
        return f"{self!r}+{self.payload}"


@dataclass
class Response:
    """The dataclass used to respond from server to client."""

    message: str
    payload: dict = field(default_factory=dict, repr=False)
    status: int = STATUS_OK
    created_on: Optional[str] = None
    disconnecting: bool = False
    game: Optional[str] = None

    def __post_init__(self):  # noqa: D105
        self.created_on = self.created_on or arrow.now().for_json()

    def serialize(self) -> dict:
        """Convert into a string."""
        return json.dumps({
            k: getattr(self, k) for k in self.__dataclass_fields__.keys()
        })

    @classmethod
    def deserialize(cls, raw_data: str, /) -> "Response":
        """Convert a string into a Response."""
        return cls(**json.loads(raw_data))

    @property
    def debug_repr(self) -> str:
        """Repr with more data."""
        return f"{self!r}+{self.payload}"


class CryptoKey:
    """A key manager for end to end encryption.

    By generating a pair of CryptoKey instances and each sharing their public
    key with the other, they can encrypt and decrypt messages for each other.
    """

    def __init__(self):
        """See class documentation for details."""
        self._private_key = nacl.public.PrivateKey.generate()
        self._public_key = self._private_key.public_key
        self._boxes: dict[str, nacl.public.Box] = {}

    @property
    def pubkey(self) -> str:
        """The public key in string format."""
        return self._public_key.encode(encoder=Base64Encoder).decode()

    def _get_box(self, pubkey: str) -> nacl.public.Box:
        box = self._boxes.get(pubkey)
        if not box:
            pub = nacl.public.PublicKey(pubkey.encode(), encoder=Base64Encoder)
            box = self._boxes[pubkey] = nacl.public.Box(self._private_key, pub)
        return box

    def encrypt(self, pubkey: str, plaintext: str) -> str:
        """Encrypt a message for the given public key."""
        box = self._get_box(pubkey)
        try:
            encrypted_message = box.encrypt(plaintext.encode(), encoder=Base64Encoder)
            ciphertext = encrypted_message.decode()
        except Exception as e:
            raise CipherError("Failed to encrypt the plaintext.") from e
        return ciphertext

    def decrypt(self, pubkey: str, ciphertext: str) -> str:
        """Decrypt a message from the given public key."""
        box = self._get_box(pubkey)
        try:
            ciphertext = ciphertext.encode()
            plaintext = box.decrypt(ciphertext, encoder=Base64Encoder).decode()
        except Exception as e:
            raise CipherError("Failed to decrypt the ciphertext.") from e
        return plaintext


class BaseGame:
    """Subclass this to implement the back end and pass to server as the game."""

    def __init__(self, name: str):
        """Initialized with the name given by the user that created the game."""
        self.name = name

    def add_user(self, username: str):
        """Called when a user joins the game."""
        pass

    def remove_user(self, username: str):
        """Called when a user leaves the game."""
        pass

    def handle_packet(self, packet: Packet) -> Response:
        """Override this method to implement packet handling."""
        return Response(
            f"No packet handling configured for {self.__class__.__qualname__}",
        )
