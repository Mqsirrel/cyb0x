#!/usr/bin/env python3
"""Lavoisier Archive Portal - deterministic intentionally-misconfigured web app.

Serves on 0.0.0.0:8080. All content is static and time-independent so scans
and screenshots are reproducible across resets.

Intentional weaknesses (AUTHORIZED LAB ONLY):
  1. /backups/ has directory listing enabled and ships a world-readable
     site-backup.tar.gz containing plaintext credentials (the intended vuln).
  2. /robots.txt discloses the hidden paths (recon breadcrumb / branch seed).
  3. /admin/ accepts mock default creds admin:LavoisierAdmin2024! but then
     dead-ends behind "MFA enrollment" - a credential trap, not a foothold.
"""

import tarfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

PORT = 8080
BACKUP_TGZ = Path("/opt/lavoisier/backups/site-backup.tar.gz")
ADMIN_USER = "admin"
ADMIN_PASS = "LavoisierAdmin2024!"

INDEX = """<!doctype html>
<html><head><title>Lavoisier Archive Portal</title></head>
<body>
<h1>Lavoisier Archive Portal</h1>
<p>Internal archive and vault synchronization service.</p>
<ul>
  <li><a href="/admin/">Staff administration</a></li>
  <li><a href="/backups/">Maintenance area</a> (staff only)</li>
</ul>
<p>VAULT-SYNC clients: point your agent at tcp/31337. Password auth is
disabled; request a token from the archive-admin.</p>
<!-- TODO: retire the legacy backup job, it still ships credentials -->
</body></html>
"""

ROBOTS = """User-agent: *
Disallow: /admin/
Disallow: /backups/
"""

ADMIN_FORM = """<!doctype html>
<html><head><title>Portal Administration</title></head>
<body>
<h1>Portal Administration</h1>
<form method="post" action="/admin/login">
  <label>User: <input name="user"></label><br>
  <label>Pass: <input name="pass" type="password"></label><br>
  <input type="submit" value="Sign in">
</form>
</body></html>
"""

ADMIN_MFA_WALL = """<!doctype html>
<html><head><title>Portal Administration</title></head>
<body>
<h1>MFA enrollment required</h1>
<p>Credentials accepted. This account has no registered second factor, so
portal access is temporarily disabled. Contact archive-admin to enroll.</p>
</body></html>
"""

ADMIN_RETRY = """<!doctype html>
<html><head><title>Portal Administration</title></head>
<body>
<h1>Authentication failed</h1>
<p><a href="/admin/">Try again</a></p>
</body></html>
"""

BACKUP_LISTING = """<!doctype html>
<html><head><title>Index of /backups</title></head>
<body>
<h1>Index of /backups</h1>
<table>
  <tr><td><a href="../">../</a></td></tr>
  <tr><td><a href="site-backup.tar.gz">site-backup.tar.gz</a></td></tr>
</table>
</body></html>
"""


class Handler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    def _send(self, body: str, code: int = 200, ctype: str = "text/html") -> None:
        payload = body.encode()
        self.send_response(code)
        self.send_header("Server", "nginx/1.24.0")
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0].rstrip("/") or "/"
        if path == "/":
            self._send(INDEX)
        elif path == "/robots.txt":
            self._send(ROBOTS, ctype="text/plain")
        elif path == "/admin":
            self._send(ADMIN_FORM)
        elif path == "/backups":
            # Misconfiguration: autoindex left enabled on a sensitive path.
            self._send(BACKUP_LISTING)
        elif path == "/backups/site-backup.tar.gz":
            if BACKUP_TGZ.exists():
                data = BACKUP_TGZ.read_bytes()
                self.send_response(200)
                self.send_header("Server", "nginx/1.24.0")
                self.send_header("Content-Type", "application/gzip")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self._send("backup missing", code=404)
        else:
            self._send("<h1>404 Not Found</h1>", code=404)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        if path != "/admin/login":
            self._send("<h1>404 Not Found</h1>", code=404)
            return
        length = int(self.headers.get("Content-Length", 0))
        fields = parse_qs(self.rfile.read(length).decode())
        user = (fields.get("user") or [""])[0]
        password = (fields.get("pass") or [""])[0]
        if user == ADMIN_USER and password == ADMIN_PASS:
            self._send(ADMIN_MFA_WALL)
        else:
            self._send(ADMIN_RETRY)

    def log_message(self, fmt: str, *args) -> None:
        pass  # keep container logs quiet and deterministic


def ensure_backup() -> None:
    BACKUP_TGZ.parent.mkdir(parents=True, exist_ok=True)
    source = Path("/opt/lavoisier/backup_source")
    if not BACKUP_TGZ.exists():
        with tarfile.open(BACKUP_TGZ, "w:gz") as tar:
            for item in sorted(source.rglob("*")):
                tar.add(item, arcname=item.relative_to(source))


if __name__ == "__main__":
    ensure_backup()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
