# PGNet

PGNet is a server-client framework for games written in Python.


## Features
* Minimum boilerplate
* A single server can host many games in a lobby automagically
* Local client that saves you from writing separate interfaces for local and online play
* End-to-end encryption (between client and server)
* CLI client for developers and server admins


## Limitation
* No concurrency beyond async on a single thread (bad for CPU-intensive games)
* Client initiated communication (server responds to client, best for turn-based games)
* No tests


## Documentation
Documentation is available via the [MouseFox project](https://ariel.ninja/mousefox).
