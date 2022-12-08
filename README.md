# PGNet

PGNet is a server-client framework for games written in Python. It is based on
the (websockets)[https://github.com/aaugustin/websockets] library.

It provides an easy way to run a server hosting one or many instances of a game
concurrently using asyncio. All games run on the same thread, hence for
performance reasons this is best used for turn-based games.


## How it works
A game class must only implement 3 python methods to work with the server.
This class is passed to the server which initializes one for each game
opened on the server. The server will manage connections and users joining
and leaving games. Once a user joins a game, the server waits for packets
from the client, relays them to the game and returns the responses.

The client class provides a queue for sending packets to the game, along with
an optional callback for the response. The client must run asyncronously.

Also provided is a localhost client subclass which will run its own local
server. This allows you to use the same client interface for both local single
player and online multiplayer.


## Try it out
Install `pgnet` using pip, then use the command:
```pgnet```

This will open the dev client, a command line tool for communicating with a
server. Without arguments, it will run a localhost client and use the default
game class. This should allow you to test the server.
