# PGNet

PGNet is a server-client framework for games written in Python.


## Features
* Minimum effort to connect game to server, and client to UI
* A single server can host many games in a lobby automagically
* Localhost option that saves you from writing separate interfaces for local and online
    play
* CLI client for developers and server admins
* End-to-end encryption
* Hopefully a concise API

## Limitation
* No concurrency beyond async on a single thread (bad for CPU-intensive games)
* Client initiated communication (server responds to client)
* No tests


## Install

```bash
pip install git+ssh://git@github.com/ArielHorwitz/pgnet.git
```

See documentation for examples and API reference.
