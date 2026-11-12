#!/usr/bin/env python3

import argparse
import base64
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import socketserver
import sqlite3
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit


ROOT = Path(os.environ.get("ENCAP_DATA_DIR", "/data"))
SOCKET = Path(os.environ.get("ENCAP_SOCKET", "/run/encap/control.sock"))
NETWORK = ipaddress.IPv4Network("10.77.77.0/24")
FIRST_PEER = 3
DIFFICULTY = 22
MAX_PEERS = int(os.environ.get("ENCAP_MAX_PEERS", "40"))
MONTHLY_BYTES = int(os.environ.get("ENCAP_MONTHLY_BYTES", "10000000000"))
GLOBAL_MONTHLY_BYTES = int(os.environ.get("ENCAP_GLOBAL_MONTHLY_BYTES", "500000000000"))
PER_IP_DAILY = int(os.environ.get("ENCAP_PER_IP_DAILY", "3"))
PER_IP_MONTHLY = int(os.environ.get("ENCAP_PER_IP_MONTHLY", "10"))
IDLE_SECONDS = int(os.environ.get("ENCAP_IDLE_MINUTES", "10")) * 60
CHALLENGE_SECONDS = 120
SYNC_SECONDS = 15


class ControlError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status


def valid_public_key(value):
    if not isinstance(value, str):
        raise ControlError(400, "Invalid public key")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise ControlError(400, "Invalid public key") from error
    if len(raw) != 32 or base64.b64encode(raw).decode() != value:
        raise ControlError(400, "Invalid public key")
    return value


def current_month():
    return time.strftime("%Y-%m", time.gmtime())


def run_wg(*args):
    try:
        result = subprocess.run(["wg", *args], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ControlError(503, "WireGuard unavailable") from error
    if result.returncode:
        raise ControlError(503, "WireGuard unavailable")
    return result.stdout.strip()


def run_iptables(*args, check=True):
    try:
        result = subprocess.run(["iptables", "-w", *args], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ControlError(503, "Firewall unavailable") from error
    if check and result.returncode:
        raise ControlError(503, "Firewall unavailable")
    return result.returncode


def run_ip(*args, check=True):
    try:
        result = subprocess.run(["ip", *args], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ControlError(503, "Route unavailable") from error
    if check and result.returncode:
        raise ControlError(503, "Route unavailable")
    return result.stdout.strip()


def ensure_guest_firewall():
    if run_iptables("-S", "ENCAP_GUEST", check=False):
        run_iptables("-N", "ENCAP_GUEST")
    run_iptables("-F", "ENCAP_GUEST")
    for destination in (
        "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
        "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16",
        "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
    ):
        run_iptables("-A", "ENCAP_GUEST", "-d", destination, "-j", "REJECT")
    for port in (25, 465, 587):
        run_iptables("-A", "ENCAP_GUEST", "-p", "tcp", "--dport", str(port), "-j", "REJECT")
    if run_iptables("-C", "FORWARD", "-i", "wg0", "!", "-s", "10.77.77.2/32", "-j", "ENCAP_GUEST", check=False):
        run_iptables("-I", "FORWARD", "1", "-i", "wg0", "!", "-s", "10.77.77.2/32", "-j", "ENCAP_GUEST")


class WireGuard:
    def public_key(self):
        return valid_public_key(run_wg("show", "wg0", "public-key"))

    def peers(self):
        return set(run_wg("show", "wg0", "peers").splitlines())

    def routes(self):
        return {line.split()[0].split("/")[0] for line in run_ip("-4", "route", "show", "dev", "wg0").splitlines() if line}

    def transfers(self):
        result = {}
        for line in run_wg("show", "wg0", "transfer").splitlines():
            columns = line.split()
            if len(columns) == 3:
                result[columns[0]] = (int(columns[1]), int(columns[2]))
        return result

    def handshakes(self):
        result = {}
        for line in run_wg("show", "wg0", "latest-handshakes").splitlines():
            columns = line.split()
            if len(columns) == 2:
                result[columns[0]] = int(columns[1])
        return result

    def add(self, public_key, address):
        run_wg("set", "wg0", "peer", public_key, "allowed-ips", f"{address}/32")

        run_ip("-4", "route", "replace", f"{address}/32", "dev", "wg0")

    def remove(self, public_key, address):
        run_wg("set", "wg0", "peer", public_key, "remove")
        run_ip("-4", "route", "del", f"{address}/32", "dev", "wg0", check=False)


class Controller:
    def __init__(self, backend=None, root=ROOT):
        if not 1 <= MAX_PEERS <= 252 or not 1 <= PER_IP_DAILY <= 100 or not 1 <= PER_IP_MONTHLY <= 100 or MONTHLY_BYTES < 1000000 or GLOBAL_MONTHLY_BYTES < MONTHLY_BYTES or IDLE_SECONDS < 300:
            raise ValueError("Invalid service limits")
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        self.key_path = self.root / "issuer.key"
        if not self.key_path.exists():
            fd = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as file:
                file.write(secrets.token_bytes(32))
        self.secret = self.key_path.read_bytes()
        if len(self.secret) != 32 or self.key_path.stat().st_mode & 0o077:
            raise ValueError("Invalid issuer key")
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.root / "peers.db", timeout=5, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS peers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                public_key TEXT NOT NULL UNIQUE,
                address TEXT NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                ip_hash TEXT NOT NULL,
                created INTEGER NOT NULL,
                month TEXT NOT NULL,
                used_bytes INTEGER NOT NULL DEFAULT 0,
                last_rx INTEGER NOT NULL DEFAULT 0,
                last_tx INTEGER NOT NULL DEFAULT 0,
                last_seen INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS enroll_events (
                ip_hash TEXT NOT NULL,
                created INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS enroll_events_lookup ON enroll_events(ip_hash, created);
            CREATE UNIQUE INDEX IF NOT EXISTS active_address ON peers(address) WHERE revoked=0;
        """)
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(peers)")}
        if "last_seen" not in columns:
            self.db.execute("ALTER TABLE peers ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0")
        self.db.commit()
        os.chmod(self.root / "peers.db", 0o600)
        self.backend = backend or WireGuard()
        self.last_sync = 0.0

    def ip_hash(self, address):
        try:
            canonical = str(ipaddress.ip_address(address))
        except ValueError as error:
            raise ControlError(400, "Invalid client address") from error
        return hmac.new(self.secret, canonical.encode(), hashlib.sha256).hexdigest()

    def challenge(self, address):
        ip_hash = self.ip_hash(address)
        nonce = secrets.token_hex(16)
        expiry = int(time.time()) + CHALLENGE_SECONDS
        value = f"{nonce}.{expiry}"
        signature = hmac.new(self.secret, f"{value}.{ip_hash}".encode(), hashlib.sha256).hexdigest()
        return {"challenge": f"{value}.{signature}", "difficulty": DIFFICULTY}

    def verify_challenge(self, address, challenge, public_key, counter):
        if not isinstance(challenge, str) or type(counter) is not int or not 0 <= counter <= 1000000000:
            raise ControlError(400, "Invalid challenge")
        match = re.fullmatch(r"([0-9a-f]{32})\.([0-9]{10})\.([0-9a-f]{64})", challenge)
        if not match or not int(time.time()) <= int(match.group(2)) <= int(time.time()) + CHALLENGE_SECONDS:
            raise ControlError(400, "Challenge expired")
        value = f"{match.group(1)}.{match.group(2)}"
        expected = hmac.new(self.secret, f"{value}.{self.ip_hash(address)}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, match.group(3)):
            raise ControlError(400, "Invalid challenge")
        digest = hashlib.sha256(f"{challenge}:{public_key}:{counter}".encode()).digest()
        if int.from_bytes(digest, "big") >> (256 - DIFFICULTY):
            raise ControlError(400, "Invalid proof")

    def sync(self, force=False):
        now = time.monotonic()
        if not force and now - self.last_sync < SYNC_SECONDS:
            return
        transfers = self.backend.transfers()
        handshakes = self.backend.handshakes()
        active = self.backend.peers()
        routes = self.backend.routes()
        month = current_month()
        wall = int(time.time())
        try:
            for row in self.db.execute("SELECT * FROM peers").fetchall():
                rx, tx = transfers.get(row["public_key"], (0, 0))
                used = 0 if row["month"] != month else row["used_bytes"]
                if row["month"] == month:
                    used += (rx - row["last_rx"] if rx >= row["last_rx"] else rx)
                    used += (tx - row["last_tx"] if tx >= row["last_tx"] else tx)
                last_seen = max(row["last_seen"], row["created"], handshakes.get(row["public_key"], 0))
                revoked = 2 if row["revoked"] == 0 and wall - last_seen > IDLE_SECONDS else row["revoked"]
                self.db.execute(
                    "UPDATE peers SET used_bytes=?, last_rx=?, last_tx=?, month=?, last_seen=?, revoked=? WHERE id=?",
                    (used, rx, tx, month, last_seen, int(revoked), row["id"]),
                )
            total = self.db.execute("SELECT COALESCE(SUM(used_bytes),0) FROM peers WHERE month=?", (month,)).fetchone()[0]
            for row in self.db.execute("SELECT public_key,address,used_bytes,revoked FROM peers").fetchall():
                allowed = not row["revoked"] and row["used_bytes"] < MONTHLY_BYTES and total < GLOBAL_MONTHLY_BYTES
                if allowed and (row["public_key"] not in active or row["address"] not in routes):
                    self.backend.add(row["public_key"], row["address"])
                elif not allowed and row["public_key"] in active:
                    self.backend.remove(row["public_key"], row["address"])
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        self.last_sync = now

    def enroll(self, address, public_key, challenge, counter):
        public_key = valid_public_key(public_key)
        self.verify_challenge(address, challenge, public_key, counter)
        self.sync(force=True)
        ip_hash = self.ip_hash(address)
        now = int(time.time())
        self.db.execute("DELETE FROM enroll_events WHERE created < ?", (now - 30 * 86400,))
        if self.db.execute("SELECT 1 FROM peers WHERE public_key=?", (public_key,)).fetchone():
            raise ControlError(409, "Key already enrolled")
        count = self.db.execute("SELECT COUNT(*) FROM enroll_events WHERE ip_hash=? AND created>=?", (ip_hash, now - 86400)).fetchone()[0]
        if count >= PER_IP_DAILY:
            raise ControlError(429, "Daily signup limit reached")
        month_count = self.db.execute("SELECT COUNT(*) FROM enroll_events WHERE ip_hash=?", (ip_hash,)).fetchone()[0]
        if month_count >= PER_IP_MONTHLY:
            raise ControlError(429, "Monthly signup limit reached")
        total = self.db.execute("SELECT COALESCE(SUM(used_bytes),0) FROM peers WHERE month=?", (current_month(),)).fetchone()[0]
        if total >= GLOBAL_MONTHLY_BYTES:
            raise ControlError(503, "Server traffic limit reached")
        active_count = self.db.execute("SELECT COUNT(*) FROM peers WHERE revoked=0", ()).fetchone()[0]
        if active_count >= MAX_PEERS:
            raise ControlError(503, "Server full")
        used = {row[0] for row in self.db.execute("SELECT address FROM peers WHERE revoked=0")}
        address_vpn = next((str(NETWORK.network_address + i) for i in range(FIRST_PEER, 255)
                            if str(NETWORK.network_address + i) not in used), None)
        if address_vpn is None:
            raise ControlError(503, "Server full")
        server_key = self.backend.public_key()
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        try:
            self.backend.add(public_key, address_vpn)
            self.db.execute(
                "INSERT INTO peers(public_key,address,token_hash,ip_hash,created,month,last_seen) VALUES(?,?,?,?,?,?,?)",
                (public_key, address_vpn, token_hash, ip_hash, now, current_month(), now),
            )
            self.db.execute("INSERT INTO enroll_events(ip_hash,created) VALUES(?,?)", (ip_hash, now))
            self.db.commit()
        except Exception:
            self.db.rollback()
            try:
                self.backend.remove(public_key, address_vpn)
            except ControlError:
                pass
            raise
        return {
            "client_ip": address_vpn,
            "server_public_key": server_key,
            "access_token": token,
            "monthly_bytes": MONTHLY_BYTES,
            "relay_path": "ws",
        }

    def authorize(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            return False
        self.sync()
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        row = self.db.execute("SELECT revoked,used_bytes FROM peers WHERE token_hash=?", (token_hash,)).fetchone()
        total = self.db.execute("SELECT COALESCE(SUM(used_bytes),0) FROM peers WHERE month=?", (current_month(),)).fetchone()[0]
        return bool(row and not row["revoked"] and row["used_bytes"] < MONTHLY_BYTES and total < GLOBAL_MONTHLY_BYTES)

    def resume(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            raise ControlError(401, "Access denied")
        self.sync(force=True)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        row = self.db.execute("SELECT * FROM peers WHERE token_hash=?", (token_hash,)).fetchone()
        if not row or row["revoked"] == 1:
            raise ControlError(401, "Access denied")
        if row["used_bytes"] >= MONTHLY_BYTES:
            raise ControlError(429, "Monthly traffic limit reached")
        total = self.db.execute("SELECT COALESCE(SUM(used_bytes),0) FROM peers WHERE month=?", (current_month(),)).fetchone()[0]
        if total >= GLOBAL_MONTHLY_BYTES:
            raise ControlError(503, "Server traffic limit reached")
        address = row["address"]
        if row["revoked"] == 2:
            count = self.db.execute("SELECT COUNT(*) FROM peers WHERE revoked=0").fetchone()[0]
            if count >= MAX_PEERS:
                raise ControlError(503, "Server full")
            used = {item[0] for item in self.db.execute("SELECT address FROM peers WHERE revoked=0")}
            if address in used:
                address = next((str(NETWORK.network_address + i) for i in range(FIRST_PEER, 255)
                                if str(NETWORK.network_address + i) not in used), None)
            if address is None:
                raise ControlError(503, "Server full")
            self.backend.add(row["public_key"], address)
            try:
                self.db.execute("UPDATE peers SET address=?,revoked=0,last_seen=?,last_rx=0,last_tx=0 WHERE id=?",
                                (address, int(time.time()), row["id"]))
                self.db.commit()
            except Exception:
                self.db.rollback()
                self.backend.remove(row["public_key"], address)
                raise
        return {"client_ip": address}

    def release(self, token):
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            raise ControlError(401, "Access denied")
        self.sync(force=True)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        row = self.db.execute("SELECT public_key,address,revoked FROM peers WHERE token_hash=?", (token_hash,)).fetchone()
        if not row or row["revoked"] == 1:
            raise ControlError(401, "Access denied")
        if row["revoked"] == 0:
            self.db.execute("UPDATE peers SET revoked=2 WHERE token_hash=?", (token_hash,))
            self.db.commit()
            self.backend.remove(row["public_key"], row["address"])
        return {"ok": True}

    def revoke(self, peer_id):
        row = self.db.execute("SELECT public_key,address FROM peers WHERE id=?", (peer_id,)).fetchone()
        if not row:
            raise ControlError(404, "Peer not found")
        self.db.execute("UPDATE peers SET revoked=1 WHERE id=?", (peer_id,))
        self.db.commit()
        self.backend.remove(row["public_key"], row["address"])


class Handler(BaseHTTPRequestHandler):
    server_version = "ENCAP"
    sys_version = ""

    def log_message(self, *_args):
        return

    def respond(self, status, body):
        payload = json.dumps(body, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def client_ip(self):
        value = self.headers.get("X-Client-IP", "")
        ipaddress.ip_address(value)
        return value

    def do_GET(self):
        try:
            path = urlsplit(self.path).path
            if path == "/v1/health":
                with self.server.controller.lock:
                    self.server.controller.sync()
                return self.respond(200, {"ok": True})
            if path == "/v1/challenge":
                with self.server.controller.lock:
                    challenge = self.server.controller.challenge(self.client_ip())
                return self.respond(200, challenge)
            if path == "/v1/auth":
                header = self.headers.get("Authorization", "")
                token = header[7:] if header.startswith("Bearer ") else ""
                with self.server.controller.lock:
                    authorized = self.server.controller.authorize(token)
                if authorized:
                    return self.respond(200, {"ok": True})
                return self.respond(401, {"error": "Access denied"})
            return self.respond(404, {"error": "Not found"})
        except ControlError as error:
            return self.respond(error.status, {"error": str(error)})
        except ValueError:
            return self.respond(400, {"error": "Invalid client address"})

    def do_POST(self):
        try:
            path = urlsplit(self.path).path
            if path in ("/v1/resume", "/v1/release"):
                length = self.headers.get("Content-Length", "0")
                if length not in ("0", "2") or length == "2" and self.rfile.read(2) != b"{}":
                    return self.respond(400, {"error": "Invalid request"})
                header = self.headers.get("Authorization", "")
                token = header[7:] if header.startswith("Bearer ") else ""
                with self.server.controller.lock:
                    result = (self.server.controller.resume(token) if path == "/v1/resume"
                              else self.server.controller.release(token))
                return self.respond(200, result)
            if path != "/v1/enroll":
                return self.respond(404, {"error": "Not found"})
            if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/json":
                return self.respond(415, {"error": "JSON required"})
            length = int(self.headers.get("Content-Length", "0"))
            if not 1 <= length <= 512:
                return self.respond(413, {"error": "Request too large"})
            self.connection.settimeout(10)
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise ControlError(400, "Invalid request")
            with self.server.controller.lock:
                result = self.server.controller.enroll(
                    self.client_ip(), data.get("public_key"), data.get("challenge"), data.get("counter")
                )
            return self.respond(201, result)
        except (ValueError, UnicodeDecodeError):
            return self.respond(400, {"error": "Invalid request"})
        except TimeoutError:
            return self.respond(408, {"error": "Request timed out"})
        except ControlError as error:
            return self.respond(error.status, {"error": str(error)})


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 32
    timeout = 1

    def __init__(self, path, controller):
        self.controller = controller
        self.slots = threading.BoundedSemaphore(16)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).unlink(missing_ok=True)
        super().__init__(str(path), Handler)
        os.chmod(path, 0o600)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def main():
    parser = argparse.ArgumentParser(prog="encap-server")
    parser.add_argument("command", choices=("serve", "list", "revoke", "sync", "stats"))
    parser.add_argument("peer_id", nargs="?", type=int)
    args = parser.parse_args()
    os.umask(0o077)
    controller = Controller()
    if args.command == "serve":
        ensure_guest_firewall()
        with UnixServer(SOCKET, controller) as server:
            while True:
                server.handle_request()
                try:
                    with controller.lock:
                        controller.sync()
                except ControlError:
                    pass
    elif args.command == "list":
        for row in controller.db.execute("SELECT id,address,used_bytes,revoked FROM peers ORDER BY id"):
            print(row["id"], row["address"], row["used_bytes"], {0: "active", 1: "revoked", 2: "idle"}[row["revoked"]])
    elif args.command == "revoke":
        if args.peer_id is None:
            parser.error("peer_id required")
        controller.revoke(args.peer_id)
    elif args.command == "stats":
        controller.sync(force=True)
        active = controller.db.execute("SELECT COUNT(*) FROM peers WHERE revoked=0").fetchone()[0]
        used = controller.db.execute("SELECT COALESCE(SUM(used_bytes),0) FROM peers WHERE month=?", (current_month(),)).fetchone()[0]
        print(f"active={active}/{MAX_PEERS} guest_bytes={used}/{GLOBAL_MONTHLY_BYTES} month={current_month()}")
    else:
        controller.sync(force=True)


if __name__ == "__main__":
    sys.exit(main())
