#!/usr/bin/env python3
"""LAVOISIER VAULT-SYNC decoy service on tcp/31337.

Intentional dead end: password authentication is disabled and harvested
database credentials are rejected with an account-locked error, so this
service cannot be turned into a foothold. It exists to reward thorough
enumeration (banner + auth probe) and punish tunnel vision.
"""

import socketserver

PORT = 31337
BANNER = "LAVOISIER VAULT-SYNC v0.9 ready. Send AUTH <token>. Password auth is DISABLED."

# Ordered: named principals are matched before the generic AUTH prefix so
# harvested credentials get the documented account-locked rejection.
RESPONSES = (
    ("developer", "ERR account locked: developer is not a vault principal."),
    ("svc_archive", "ERR account locked: svc_archive is not a vault principal."),
    ("AUTH", "ERR token required: request one from archive-admin."),
)


def reply(line: str) -> str:
    for needle, response in RESPONSES:
        if needle in line:
            return response
    return "ERR unknown command. Syntax: AUTH <token> | LIST | PING"


class Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.wfile.write((BANNER + "\n").encode())
        try:
            for _ in range(2):
                line = self.rfile.readline().decode(errors="replace").strip()
                if not line:
                    break
                self.wfile.write((reply(line) + "\n").encode())
        except ConnectionError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


if __name__ == "__main__":
    Server(("0.0.0.0", PORT), Handler).serve_forever()
