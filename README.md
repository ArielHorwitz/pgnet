# PGNet

PGNet is a server-client framework for games written in Python.

It provides an easy way to run a server hosting one or many instances of a game
concurrently using asyncio. All games run on the same thread, hence for
performance reasons this is best used for turn-based games.

It is based on the [websockets](https://github.com/aaugustin/websockets) library
and uses [PyNaCl](https://github.com/pyca/pynacl) for end to end encryption.


## How it works
A game class must implement at least one python method to work with the server.
This class is passed to the server which initializes one for each game
opened on the server. The server will manage connections and users joining
and leaving games. Once a user joins a game, the server waits for packets
from the client, relays them to the game and returns the responses.

The client class provides a queue for sending packets to the game, along with
an optional callback for each response.

Also provided is a localhost mixin class for clients that will run its own
local server. This allows you to use the same client interface for both local
single player and online multiplayer.


## Try it out
Install using pip:

```pip install git+ssh://git@github.com/ArielHorwitz/pgnet.git```


Then use the command to run the CLI client:

```pgnet```

This will open the CLI client, a command line tool for developers and admins.
Without arguments, it will run a localhost client and use an empty game class.
This should allow you to test that the server is operating correctly.
