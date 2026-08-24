#!/usr/bin/env python3
"""Container healthcheck: all four lab services must accept TCP connections."""

import socket
import sys

PORTS = (21, 22, 8080, 31337)


def reachable(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(2)
        return sock.connect_ex(("127.0.0.1", port)) == 0


sys.exit(0 if all(reachable(p) for p in PORTS) else 1)
