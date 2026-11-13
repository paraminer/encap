#!/usr/bin/env python3

import argparse
import base64
from collections import deque
import fcntl
import hashlib
import ipaddress
import json
import os
import pathlib
import platform
import plistlib
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import termios
import threading
import time
import traceback
import urllib.error
import urllib.request
from urllib.parse import urlparse


STATE_DIR = pathlib.Path.home() / ".local" / "state" / "encap"
STATE_FILE = STATE_DIR / "session.plist"
LOCK_FILE = STATE_DIR / "lock"
PREFIXES = (("0.0.0.0/1", "0/1"), ("128.0.0.0/1", "128.0/1"))
DEBUG = False
PUBLIC_SERVER = "https://167.104.110.55"


class EncapError(Exception):
    pass


LOGO = (
    "   ___ _ __   ___ __ _ _ __",
    "  / _ \\ '_ \\ / __/ _` | '_ \\",
    " |  __/ | | | (_| (_| | |_) |",
    "  \\___|_| |_|\\___\\__,_| .__/",
    "                      | |",
    "                      |_|",
)
TAGLINE = "private tunnel over https"


def color_on(stream=sys.stdout):
    return stream.isatty() and not os.environ.get("NO_COLOR")


def paint(code, text, stream=sys.stdout):
    return f"\033[{code}m{text}\033[0m" if color_on(stream) else text


def dim(text, stream=sys.stdout):
    return paint("2", text, stream)


def interactive():
    return sys.stdout.isatty() and not DEBUG


def banner():
    if not interactive():
        return
    lines = list(LOGO)
    lines[4] = f"{lines[4]:<29}{dim(TAGLINE)}"
    print("\n" + "\n".join("  " + line for line in lines) + "\n", flush=True)


def clock(seconds):
    seconds = max(0, int(seconds))
    hours, rest = divmod(seconds, 3600)
    return f"{hours}:{rest // 60:02}:{rest % 60:02}" if hours else f"{rest // 60:02}:{rest % 60:02}"


def log(level, message):
    if level in ("debug", "info") and not DEBUG:
        return
    labels = {"info": "•", "ok": "✓", "warn": "!", "error": "✗", "debug": "·"}
    colors = {"info": "36", "ok": "32", "warn": "33", "error": "31", "debug": "90"}
    stream = sys.stderr if level in ("warn", "error") else sys.stdout
    print(f"  {paint(colors[level], labels[level], stream)} {message}", file=stream, flush=True)


def hint(message):
    print(f"    {dim(message, sys.stderr)}", file=sys.stderr, flush=True)


def tunnel_line(opened, server_ip, started, live=False):
    """One status line: '● Tunnel open  1.2.3.4  02:14' or '○ Tunnel closed  02:14'."""
    if opened:
        text = f"  {paint('32', '●')} Tunnel open   {server_ip}   {clock(time.time() - started)}"
        return text + (f"   {dim('ctrl+c to close')}" if live else "")
    return f"  {dim('○')} Tunnel closed   {dim(clock(time.time() - started))}"


class TerminalGuard:
    """While connected, hide the cursor and keep ^C and keystrokes from breaking the status line."""

    def __init__(self):
        self.saved = None
        self.active = interactive() and sys.stdin.isatty()

    def __enter__(self):
        if self.active:
            try:
                fd = sys.stdin.fileno()
                self.saved = termios.tcgetattr(fd)
                quiet = termios.tcgetattr(fd)
                quiet[3] &= ~(termios.ECHO | termios.ECHOCTL)
                termios.tcsetattr(fd, termios.TCSANOW, quiet)
            except (termios.error, OSError):
                self.saved = None
            sys.stdout.write("\033[?25l")
            sys.stdout.flush()
        return self

    def __exit__(self, *_error):
        if self.active:
            if self.saved is not None:
                try:
                    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, self.saved)
                except (termios.error, OSError):
                    pass
            sys.stdout.write("\033[?25h")
            sys.stdout.flush()
        return False


class ConnectionProgress:
    """Spinner with a step counter, or a live status line once connected."""

    FRAMES = ("◐", "◓", "◑", "◒")

    def __init__(self):
        self.animated = interactive()
        self.message = ""
        self.step = ""
        self.render = None
        self.stopped = threading.Event()
        self.thread = None
        self.printed = False

    def start(self, message, step=""):
        self.message, self.step, self.render = message, step, None
        if not self.animated:
            if not DEBUG and not self.printed:
                print("Connecting", flush=True)
                self.printed = True
            return
        self._run(0.12)

    def live(self, render):
        """Redraw render() in place every half second until pause()."""
        if not self.animated:
            return
        self.render = render
        self._run(0.5)

    def update(self, message, step=""):
        self.message, self.step = message, step

    def pause(self):
        if not self.animated or self.thread is None:
            return
        self.stopped.set()
        self.thread.join()
        sys.stdout.write("\r\033[2K")
        sys.stdout.flush()
        self.thread = None

    def _run(self, interval):
        self.pause()
        self.stopped.clear()
        self.thread = threading.Thread(target=self._animate, args=(interval,), daemon=True)
        self.thread.start()

    def _animate(self, interval):
        index = 0
        while not self.stopped.is_set():
            if self.render:
                line = self.render()
            else:
                marker = paint("36", self.FRAMES[index % len(self.FRAMES)])
                step = f"  {dim(self.step)}" if self.step else ""
                line = f"  {marker} {self.message}{step}"
            sys.stdout.write(f"\r\033[2K{line}")
            sys.stdout.flush()
            index += 1
            self.stopped.wait(interval)


def run(args, timeout=30, check=True):
    started = time.monotonic()
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EncapError(f"{args[0]}: {error}") from error
    log("debug", f"{pathlib.Path(args[0]).name}: exit {result.returncode}, {time.monotonic() - started:.2f}s")
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()[-350:]
        raise EncapError(f"{pathlib.Path(args[0]).name} failed ({result.returncode}): {detail}")
    return result


def field(output, name):
    match = re.search(rf"^\s*{re.escape(name)}:\s*(\S+)", output, re.MULTILINE)
    return match.group(1) if match else None


def private_file(path):
    path = pathlib.Path(path).expanduser().resolve()
    if not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise EncapError(f"Missing or insecure file: {path} (mode 600 required)")
    return path


def ensure_state_dir():
    STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(STATE_DIR, 0o700)


def save_state(state):
    ensure_state_dir()
    temporary = STATE_FILE.with_suffix(".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as output:
        plistlib.dump(state, output, fmt=plistlib.FMT_BINARY)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, STATE_FILE)
    os.chmod(STATE_FILE, 0o600)


def load_state():
    if not STATE_FILE.exists():
        return None
    with private_file(STATE_FILE).open("rb") as source:
        return plistlib.load(source)


def lock(nonblocking=False):
    ensure_state_dir()
    fd = os.open(LOCK_FILE, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | (fcntl.LOCK_NB if nonblocking else 0))
    except BlockingIOError as error:
        os.close(fd)
        raise EncapError("Another encap operation is running") from error
    return fd


def resolve_binary(value):
    path = pathlib.Path(value).expanduser()
    found = str(path) if path.is_absolute() else shutil.which(value)
    if not found or not os.access(found, os.X_OK):
        raise EncapError(f"Executable not found: {value}")
    return found


def config_path(argument):
    value = argument or os.environ.get("ENCAP_CONFIG") or "~/.config/encap/config.json"
    return pathlib.Path(value).expanduser().resolve()


def repair_profile_name(config_file, data):
    value = data.get("wireguard_profile")
    if not isinstance(value, str):
        return
    old = pathlib.Path(value).expanduser().resolve()
    match = re.fullmatch(r"peer-([0-9a-f]{12})\.conf", old.name)
    if not match:
        return
    new = old.with_name(f"e-{match.group(1)}.conf")
    if old.is_file():
        private_file(old)
        if new.exists():
            if new.is_symlink() or not os.path.samefile(old, new):
                raise EncapError("Profile name collision")
        else:
            os.link(old, new)
    else:
        private_file(new)
    data["wireguard_profile"] = str(new)
    temporary = config_file.with_name(config_file.name + ".new-" + secrets.token_hex(4))
    try:
        write_private(temporary, json.dumps(data, indent=2) + "\n")
        os.replace(temporary, config_file)
    finally:
        temporary.unlink(missing_ok=True)
    old.unlink(missing_ok=True)
    log("ok", "Profile name repaired")


def load_config(path):
    path = private_file(path)
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise EncapError("Config must be a JSON object")
    required = ("server_ip", "tls_host", "relay_target", "wireguard_profile")
    missing = [name for name in required if not data.get(name)]
    if missing:
        raise EncapError("Missing config fields: " + ", ".join(missing))
    dns_servers = data.get("dns_servers", ["1.1.1.1"])
    if not isinstance(dns_servers, list) or not dns_servers:
        raise EncapError("dns_servers must be a nonempty list")
    try:
        ipaddress.IPv4Address(data["server_ip"])
        if data.get("expected_exit_ip"):
            ipaddress.IPv4Address(data["expected_exit_ip"])
        for address in dns_servers:
            ipaddress.IPv4Address(address)
    except (ValueError, ipaddress.AddressValueError) as error:
        raise EncapError(f"Invalid IPv4 address: {error}") from error
    if not isinstance(data["tls_host"], str) or not re.fullmatch(r"[A-Za-z0-9.-]+", data["tls_host"]):
        raise EncapError("Invalid tls_host")
    target = data["relay_target"]
    if (
        not isinstance(target, str)
        or not re.fullmatch(r"[A-Za-z0-9.-]+:[0-9]{1,5}", target)
        or not 1 <= int(target.rsplit(":", 1)[1]) <= 65535
    ):
        raise EncapError("Invalid relay_target")
    data["local_port"] = int(data.get("local_port", 51820))
    if not 1 <= data["local_port"] <= 65535:
        raise EncapError("Invalid local_port")
    data["dns_servers"] = dns_servers
    data["health_url"] = data.get("health_url", "https://example.org/")
    if urlparse(data["health_url"]).scheme != "https" or not urlparse(data["health_url"]).hostname:
        raise EncapError("health_url must use HTTPS")
    repair_profile_name(path, data)
    profile_path = private_file(data["wireguard_profile"])
    if not re.fullmatch(r"[A-Za-z0-9_=+.-]{1,15}", profile_path.stem):
        raise EncapError("Invalid WireGuard profile name (max 15 characters)")
    data["profile"] = str(profile_path)
    if bool(data.get("relay_secret_file")) == bool(data.get("access_token_file")):
        raise EncapError("Set one access credential file")
    data["wstunnel"] = resolve_binary(data.get("wstunnel", "wstunnel"))
    data["wg_quick"] = resolve_binary(data.get("wg_quick", "wg-quick"))
    data["wg"] = resolve_binary(data.get("wg", "wg"))
    data["wireguard_go"] = resolve_binary(data.get("wireguard_go", "wireguard-go"))
    profile = pathlib.Path(data["profile"]).read_text()
    options = dict(
        (key.strip(), value.strip())
        for key, value in re.findall(r"^\s*([^#;\[\]=]+)\s*=\s*(.*?)\s*$", profile, re.MULTILINE)
    )
    allowed_ips = [value.strip() for value in options.get("AllowedIPs", "").split(",")]
    if options.get("Table", "").lower() != "off" or "0.0.0.0/0" not in allowed_ips:
        raise EncapError("WireGuard profile needs Table = off and AllowedIPs = 0.0.0.0/0")
    if "DNS" in options or options.get("Endpoint") != f"127.0.0.1:{data['local_port']}":
        raise EncapError("WireGuard profile needs a local Endpoint and no DNS")
    if not options.get("PrivateKey") or not options.get("PublicKey"):
        raise EncapError("WireGuard key missing")
    if data.get("access_token_file"):
        data["access_header_file"] = str(private_file(data["access_token_file"]))
        header = pathlib.Path(data["access_header_file"]).read_text().strip()
        match = re.fullmatch(r"Authorization: Bearer ([A-Za-z0-9_-]{43})", header)
        if not match:
            raise EncapError("Invalid access token")
        data["access_token"] = match.group(1)
        data["relay_path"] = data.get("relay_path", "ws")
        if not re.fullmatch(r"[a-z0-9_-]{1,32}", data["relay_path"]):
            raise EncapError("Invalid relay path")
    else:
        data["secret_file"] = str(private_file(data["relay_secret_file"]))
        text = pathlib.Path(data["secret_file"]).read_text().strip()
        named = [line.split("=", 1)[1].strip() for line in text.splitlines() if line.startswith("WG_PATH_SECRET=")]
        data["relay_secret"] = named[0] if named else text
        if not re.fullmatch(r"[0-9a-f]{48}", data["relay_secret"]):
            raise EncapError("Invalid relay secret")
    return data


def ssid(interface):
    result = run(["system_profiler", "SPAirPortDataType", "-json"], timeout=25)
    data = json.loads(result.stdout)
    for item in data["SPAirPortDataType"][0]["spairport_airport_interfaces"]:
        if item.get("_name") == interface:
            return item.get("spairport_current_network_information", {}).get("_name", "").strip()
    return ""


def network_service(interface):
    output = run(["networksetup", "-listnetworkserviceorder"]).stdout
    service = None
    for line in output.splitlines():
        heading = re.match(r"^\(\d+\)\s+(.+)$", line.strip())
        if heading:
            service = heading.group(1).lstrip("*").strip()
        device = re.search(r"Device:\s*([^),\s]+)", line)
        if service and device and device.group(1) == interface:
            return service
    return None


def route(destination):
    result = run(["route", "-n", "get", destination], check=False)
    return result.stdout if result.returncode == 0 else ""


def dns(service):
    return run(["networksetup", "-getdnsservers", service]).stdout.strip()


def dns_values(output):
    return ["Empty"] if output.startswith("There aren't any") else output.splitlines()


def touch_id_sudo():
    for name in ("/etc/pam.d/sudo", "/etc/pam.d/sudo_local"):
        try:
            if re.search(r"^\s*auth\s+\S+\s+pam_tid\.so", pathlib.Path(name).read_text(), re.MULTILINE):
                return True
        except OSError:
            pass
    return False


def sudo_ready(prompt):
    if not prompt:
        run(["sudo", "-n", "-v"], timeout=10)
        return
    if run(["sudo", "-n", "-v"], check=False, timeout=10).returncode == 0:
        return
    run(["sudo", "-v", "-p", "  Your device password: "], timeout=120)
    if interactive() and not touch_id_sudo():
        sys.stdout.write("\033[1A\r\033[2K")
        sys.stdout.flush()


def server_route_status(server_ip):
    default = route("default")
    gateway = field(default, "gateway")
    interface = field(default, "interface")
    if not gateway or not interface or interface.startswith("utun"):
        return "offline"
    current = route(server_ip)
    destination = field(current, "destination")
    if destination == "default":
        return "ready"
    if destination != server_ip:
        return "custom"
    old_gateway = field(current, "gateway")
    if old_gateway == gateway and field(current, "interface") == interface:
        return "ready"
    if field(current, "interface") != interface or "STATIC" not in current:
        return "custom"
    try:
        ipaddress.IPv4Address(old_gateway)
    except ValueError:
        return "custom"
    gateway_route = route(old_gateway)
    if (
        field(gateway_route, "destination") == "default"
        and field(gateway_route, "gateway") == gateway
        and field(gateway_route, "interface") == interface
    ):
        return "stale"
    return "custom"


def prepare_server_route(server_ip):
    status = server_route_status(server_ip)
    if status == "ready":
        return
    if status == "offline":
        raise EncapError("No physical default route")
    if status != "stale":
        raise EncapError("Server has a custom route")
    old_gateway = field(route(server_ip), "gateway")
    log("warn", "Removing stale server route")
    sudo_ready(True)
    if server_route_status(server_ip) != "stale" or field(route(server_ip), "gateway") != old_gateway:
        raise EncapError("Server route changed; retry connection")
    removed = run(["sudo", "-n", "route", "-n", "delete", "-host", server_ip], check=False)
    if removed.returncode or server_route_status(server_ip) != "ready":
        raise EncapError("Could not remove stale server route")


def profile_active(profile):
    return pathlib.Path("/var/run/wireguard", pathlib.Path(profile).stem + ".name").exists()


def interface_exists(interface):
    return bool(interface and re.fullmatch(r"utun[0-9]+", interface) and run(["ifconfig", interface], check=False).returncode == 0)


def prefix_owner(prefix):
    output = run(["netstat", "-rn", "-f", "inet"]).stdout
    alias = dict(PREFIXES)[prefix]
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == alias:
            return parts[-1]
    return None


def prefix_on_interface(prefix, interface):
    return prefix_owner(prefix) == interface


def process_alive(pid):
    if not isinstance(pid, int) or pid < 2:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def relay_alive(pid):
    if not process_alive(pid):
        return False
    result = run(["ps", "-p", str(pid), "-o", "comm="], check=False)
    return pathlib.Path(result.stdout.strip()).name == "wstunnel"


def check_https(url, pinned=None):
    args = ["curl", "--noproxy", "*", "-4", "-sS", "--connect-timeout", "6", "--max-time", "15"]
    if pinned:
        host = urlparse(url).hostname
        args += ["--resolve", f"{host}:443:{pinned}"]
    result = run(args + ["-o", "/dev/null", "-w", "%{http_code}|%{ssl_verify_result}", url], timeout=18)
    code, tls = result.stdout.strip().split("|", 1)
    if not code.startswith(("2", "3")) or tls != "0":
        raise EncapError(f"HTTPS check failed: {urlparse(url).hostname} (HTTP {code}, TLS {tls})")


def recover(state, prompt=True):
    if state.get("schema") != 2:
        raise EncapError("Unknown session state format")
    ipaddress.IPv4Address(state["server_ip"])
    ipaddress.IPv4Address(state["gateway"])
    profile = pathlib.Path(state["profile"]).expanduser().resolve()
    if profile.suffix != ".conf":
        raise EncapError("Invalid profile path in state")
    interface = state.get("tunnel_interface")
    if interface and not re.fullmatch(r"utun[0-9]+", interface):
        raise EncapError("Invalid interface in state")
    service = state["network_service"]
    if not isinstance(service, str) or not service or any(char in service for char in ("\x00", "\r", "\n")):
        raise EncapError("Invalid network service in session state")
    if not re.fullmatch(r"[A-Za-z0-9]+", state["network_interface"]):
        raise EncapError("Invalid network interface in session state")
    needs_admin = (
        profile_active(profile)
        or any(interface and prefix_on_interface(prefix, interface) for prefix, _alias in PREFIXES)
        or dns(service) == "\n".join(state["dns_servers"])
        or (
            state.get("host_route_owned")
            and field(route(state["server_ip"]), "destination") == state["server_ip"]
            and "STATIC" in route(state["server_ip"])
        )
    )
    if needs_admin:
        sudo_ready(prompt)
    errors = []
    def attempt(args, label, timeout=30):
        try:
            return run(args, timeout=timeout, check=False)
        except EncapError as error:
            errors.append(f"{label}: {error}")
            return None

    try:
        current_dns = dns(state["network_service"])
    except EncapError as error:
        errors.append(f"DNS read failed: {error}")
        current_dns = ""
    applied = "\n".join(state["dns_servers"])
    original = state["original_dns"]
    if current_dns == applied:
        result = attempt(
            ["sudo", "-n", "/usr/sbin/networksetup", "-setdnsservers", state["network_service"]] + original,
            "DNS restore",
        )
        if result is not None and result.returncode:
            errors.append("DNS restore failed")
    elif current_dns != state["original_dns_text"]:
        errors.append("DNS changed externally; left unchanged")
    for prefix, _alias in reversed(PREFIXES):
        if interface and prefix_on_interface(prefix, interface):
            result = attempt(["sudo", "-n", "route", "-n", "delete", "-inet", prefix], f"Route {prefix}")
            if result is not None and result.returncode and prefix_on_interface(prefix, interface):
                errors.append(f"Route {prefix} remains")
    if profile_active(profile):
        if profile.is_file():
            result = attempt(["sudo", "-n", state["wg_quick"], "down", str(profile)], "WireGuard down", timeout=50)
            if result is not None and result.returncode and profile_active(profile):
                detail = (result.stderr or result.stdout).strip()[-250:]
                if interface_exists(interface):
                    errors.append(f"WireGuard down failed: {detail}")
                else:
                    marker = pathlib.Path("/var/run/wireguard", profile.stem + ".name")
                    removed = attempt(["sudo", "-n", "rm", "-f", str(marker)], "Stale WireGuard marker")
                    if removed is None or removed.returncode:
                        errors.append(f"Stale WireGuard marker remains: {detail}")
        else:
            errors.append("WireGuard profile was removed")
    pid = state.get("relay_pid")
    if relay_alive(pid):
        os.kill(pid, signal.SIGTERM)
        for _ in range(30):
            if not relay_alive(pid):
                break
            time.sleep(0.1)
        if relay_alive(pid):
            errors.append("WebSocket relay remains active")
    server_route = route(state["server_ip"])
    owns_server_route = (
        state.get("host_route_owned")
        and field(server_route, "destination") == state["server_ip"]
        and field(server_route, "gateway") == state["gateway"]
        and field(server_route, "interface") == state["network_interface"]
        and "STATIC" in server_route
    )
    if owns_server_route:
        attempt(["sudo", "-n", "route", "-n", "delete", "-host", state["server_ip"]], "Server route")
        remaining = route(state["server_ip"])
        if field(remaining, "destination") == state["server_ip"] and "STATIC" in remaining:
            errors.append("Server route remains")
    try:
        if dns(state["network_service"]) != state["original_dns_text"]:
            errors.append("DNS differs from baseline")
    except EncapError as error:
        errors.append(f"DNS verification failed: {error}")
    if profile_active(profile):
        errors.append("WireGuard profile remains active")
    if interface and any(prefix_on_interface(prefix, interface) for prefix, _alias in PREFIXES):
        errors.append("Tunnel routes remain active")
    if errors:
        raise EncapError("; ".join(dict.fromkeys(errors)))
    release_public(state)
    STATE_FILE.unlink(missing_ok=True)


def stop_signal(number, _frame):
    if number == signal.SIGINT and not interactive():
        print(flush=True)
    raise KeyboardInterrupt()


def follow_relay(stream, secret, messages):
    for line in stream:
        clean = line.strip().replace(secret, "[redacted]")
        if clean:
            messages.append(clean)
            log("debug", f"wstunnel: {clean}")


def connect(config):
    if platform.system() != "Darwin":
        raise EncapError("This client currently supports macOS only")
    guard = lock(nonblocking=True)
    terminal = TerminalGuard().__enter__()
    progress = ConnectionProgress()
    progress.start("Checking network", "1/4")
    try:
        log("info", "Checking network")
        if load_state():
            raise EncapError("Session state exists. Run: encap stop")
        if profile_active(config["profile"]):
            raise EncapError("WireGuard profile is already active")
        if any(prefix_owner(prefix) for prefix, _alias in PREFIXES):
            raise EncapError("Another full-route tunnel is active")
        default = route("default")
        gateway = field(default, "gateway")
        network_interface = field(default, "interface")
        if not gateway or not network_interface or network_interface.startswith("utun"):
            raise EncapError("No physical default route")
        service = network_service(network_interface)
        if not service:
            raise EncapError(f"No network service for {network_interface}")
        network_name = ssid(network_interface)
        log("info", f"Network: {network_name or service} ({network_interface})")
        log("debug", f"Service: {service}; gateway: {gateway}; server: {config['server_ip']}")
        server_route = route(config["server_ip"])
        same_physical_route = (
            field(server_route, "destination") == config["server_ip"]
            and field(server_route, "gateway") == gateway
            and field(server_route, "interface") == network_interface
        )
        cloned = (
            same_physical_route
            and "WASCLONED" in server_route
            and "STATIC" not in server_route
        )
        redundant_route = same_physical_route and "STATIC" in server_route
        if field(server_route, "destination") != "default" and not (cloned or redundant_route):
            raise EncapError("Server has a custom route")
        original_dns_text = dns(service)
        original_dns = dns_values(original_dns_text)
        if not original_dns:
            raise EncapError("Could not save network DNS")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(("127.0.0.1", config["local_port"]))
        ipify_ip = socket.getaddrinfo("api.ipify.org", 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        log("info", "Authorizing network changes")
        progress.pause()
        if not DEBUG and not progress.animated:
            print("Authorizing network changes", flush=True)
        sudo_ready(True)
        progress.start("Connecting to server", "2/4")
        state = {
            "schema": 2,
            "owner_pid": os.getpid(),
            "started_at": time.time(),
            "server_ip": config["server_ip"],
            "gateway": gateway,
            "network_interface": network_interface,
            "network_service": service,
            "network_name": network_name,
            "original_dns": original_dns,
            "original_dns_text": original_dns_text,
            "dns_servers": config["dns_servers"],
            "profile": config["profile"],
            "wg_quick": config["wg_quick"],
            "host_route_owned": not redundant_route,
        }
        if config.get("access_header_file"):
            state["access_header_file"] = config["access_header_file"]
            state["tls_host"] = config["tls_host"]
        save_state(state)
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, stop_signal)
        relay = None
        opened = None
        relay_messages = deque(maxlen=30)
        failure = None
        try:
            if redundant_route:
                current = route(config["server_ip"])
                if (
                    field(current, "destination") != config["server_ip"]
                    or field(current, "gateway") != gateway
                    or field(current, "interface") != network_interface
                    or "STATIC" not in current
                ):
                    raise EncapError("Server route changed; retry connection")
                log("debug", "Using existing server route")
            else:
                log("info", "Adding server route")
                added = run(["sudo", "-n", "route", "-n", "add", "-host", config["server_ip"], gateway], check=False)
                if added.returncode and cloned:
                    log("debug", "Removing cached server route")
                    run(["sudo", "-n", "route", "-n", "delete", "-host", config["server_ip"]], check=False)
                    added = run(["sudo", "-n", "route", "-n", "add", "-host", config["server_ip"], gateway], check=False)
                if added.returncode:
                    raise EncapError("Server route failed")
            environment = os.environ.copy()
            environment.pop("NO_COLOR", None)
            log("info", "Starting WebSocket relay")
            relay_command = [config["wstunnel"], "client", "--tls-verify-certificate"]
            try:
                ipaddress.ip_address(config["tls_host"])
            except ValueError:
                relay_command += ["--tls-sni-override", config["tls_host"]]
            credential = config.get("access_token") or config["relay_secret"]
            if config.get("access_token"):
                relay_command += ["--http-headers-file", config["access_header_file"]]
            relay_command += [
                "-H", f"Host: {config['tls_host']}",
                "--http-upgrade-path-prefix", config.get("relay_path", credential),
                "-L", f"udp://127.0.0.1:{config['local_port']}:{config['relay_target']}?timeout_sec=0",
                f"wss://{config['server_ip']}",
            ]
            relay = subprocess.Popen(
                relay_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=environment,
                text=True,
                bufsize=1,
            )
            threading.Thread(
                target=follow_relay,
                args=(relay.stdout, credential, relay_messages),
                daemon=True,
            ).start()
            state["relay_pid"] = relay.pid
            save_state(state)
            time.sleep(0.7)
            if relay.poll() is not None:
                raise EncapError("WebSocket relay exited; check server HTTPS/443")
            log("info", "Starting WireGuard")
            progress.update("Starting tunnel", "3/4")
            up = run(["sudo", "-n", config["wg_quick"], "up", config["profile"]], timeout=50)
            match = re.search(r"Interface for [^\s]+ is (utun\d+)", up.stderr)
            if not match:
                raise EncapError("WireGuard interface not found")
            interface = match.group(1)
            log("debug", f"Tunnel interface: {interface}")
            state["tunnel_interface"] = interface
            save_state(state)
            log("info", "Adding IPv4 routes")
            for prefix, _alias in PREFIXES:
                run(["sudo", "-n", "route", "-n", "add", "-inet", prefix, "-interface", interface])
            time.sleep(2)
            if field(route(config["server_ip"]), "interface") != network_interface:
                raise EncapError("Server route changed")
            log("info", "Checking exit IP and HTTPS")
            progress.update("Verifying connection", "4/4")
            check_https("https://api.ipify.org/", pinned=ipify_ip)
            if config.get("expected_exit_ip"):
                result = run(
                    ["curl", "--noproxy", "*", "-4", "-sS", "--connect-timeout", "6",
                     "--max-time", "15", "--resolve", f"api.ipify.org:443:{ipify_ip}",
                     "https://api.ipify.org/"],
                    timeout=18,
                )
                if result.stdout.strip() != config["expected_exit_ip"]:
                    raise EncapError("Exit IP mismatch")
            run(["sudo", "-n", "/usr/sbin/networksetup", "-setdnsservers", service] + config["dns_servers"])
            check_https(config["health_url"])
            progress.pause()
            opened = time.time()
            if progress.animated:
                progress.live(lambda: tunnel_line(True, config["server_ip"], opened, live=True))
            else:
                log("ok", f"Tunnel open: {config['server_ip']}")
                print("Keep this window open. Press Ctrl+C to close the tunnel.", flush=True)
            last_refresh = time.monotonic()
            while True:
                time.sleep(5)
                current_default = route("default")
                if relay.poll() is not None:
                    raise EncapError("WebSocket relay stopped")
                if field(current_default, "interface") != network_interface or field(current_default, "gateway") != gateway:
                    raise EncapError("Default network changed")
                if network_name and ssid(network_interface) != network_name:
                    raise EncapError("Wi-Fi changed")
                if field(route(config["server_ip"]), "interface") != network_interface:
                    raise EncapError("Server route changed")
                if not all(prefix_on_interface(prefix, interface) for prefix, _alias in PREFIXES):
                    raise EncapError("Tunnel route changed")
                if time.monotonic() - last_refresh >= 60:
                    sudo_ready(False)
                    log("debug", "sudo refreshed")
                    last_refresh = time.monotonic()
        except KeyboardInterrupt:
            progress.pause()
            log("info", "Closing tunnel")
        except BaseException as error:
            progress.pause()
            failure = error
            log("debug", f"Connection stopped: {error}")
            relay_errors = [line for line in relay_messages if any(word in line.lower() for word in ("error", "fail", "timeout", "denied"))]
            if relay_errors:
                log("warn", f"wstunnel: {relay_errors[-1]}")
        finally:
            for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                signal.signal(sig, signal.SIG_IGN)
            log("info", "Restoring network")
            progress.start("Closing tunnel")
            try:
                recover(state, prompt=True)
            except BaseException as error:
                progress.pause()
                raise EncapError(f"Restore incomplete: {error}. Run: encap stop") from error
            progress.pause()
            if opened:
                print(tunnel_line(False, None, opened), flush=True)
        if failure:
            raise EncapError(str(failure))
    finally:
        progress.pause()
        terminal.__exit__(None, None, None)
        os.close(guard)


def status():
    state = load_state()
    if not state:
        external = {prefix: owner for prefix, _alias in PREFIXES if (owner := prefix_owner(prefix))}
        if external:
            routes = ", ".join(f"{prefix} → {owner}" for prefix, owner in external.items())
            log("warn", f"Another tunnel owns the routes: {routes}")
        else:
            print(f"  {dim('○')} Tunnel closed", flush=True)
        return
    interface = state.get("tunnel_interface")
    active = (
        process_alive(state.get("owner_pid"))
        and interface
        and all(prefix_on_interface(prefix, interface) for prefix, _alias in PREFIXES)
    )
    if active:
        print(tunnel_line(True, state["server_ip"], state["started_at"]), flush=True)
    else:
        log("warn", "Session ended unexpectedly")
        hint("run encap to clean up")


def disconnect():
    state = load_state()
    if not state:
        print(f"  {dim('○')} Tunnel already closed", flush=True)
        return
    progress = ConnectionProgress()
    pid = state.get("owner_pid")
    if process_alive(pid):
        command = run(["ps", "-p", str(pid), "-o", "command="], check=False).stdout
        if "encap.py" in command or "/encap" in command:
            log("info", "Closing tunnel")
            progress.start("Closing tunnel")
            os.kill(pid, signal.SIGTERM)
            for _ in range(300):
                if not STATE_FILE.exists():
                    progress.pause()
                    print(tunnel_line(False, None, state["started_at"]), flush=True)
                    return
                if not process_alive(pid):
                    break
                time.sleep(0.1)
            progress.pause()
            if process_alive(pid):
                raise EncapError("Tunnel is still closing. Run: encap stop")
    guard = lock(nonblocking=True)
    try:
        current = load_state()
        if current:
            log("info", "Restoring network")
            progress.start("Restoring network")
            try:
                recover(current, prompt=True)
            finally:
                progress.pause()
        print(f"  {dim('○')} Tunnel closed", flush=True)
    finally:
        os.close(guard)


def remove_encap_path(path):
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def uninstall(home=None, public_paths=None):
    home = pathlib.Path(home) if home is not None else pathlib.Path.home()
    if public_paths is None:
        public_paths = (pathlib.Path("/usr/local/bin/encap"), pathlib.Path("/opt/homebrew/bin/encap"))
    if load_state():
        disconnect()
    guard = lock(nonblocking=True)
    try:
        if load_state():
            raise EncapError("Tunnel is still active. Run: encap stop")
        config_dir = home / ".config" / "encap"
        for profile in config_dir.glob("*.conf"):
            if profile_active(profile):
                raise EncapError("WireGuard is still active. Run: encap stop")
        local_bin = home / ".local" / "bin"
        if (local_bin / "encap").is_dir() and not (local_bin / "encap").is_symlink():
            raise EncapError("Cannot remove a directory at ~/.local/bin/encap")
        config_file = config_dir / "config.json"
        if config_file.is_file() and not config_file.is_symlink():
            try:
                saved = json.loads(config_file.read_text())
                release_public({"access_header_file": saved.get("access_token_file"), "tls_host": saved.get("tls_host")})
            except (ValueError, OSError, AttributeError):
                pass
        for path in map(pathlib.Path, public_paths):
            if path.is_symlink():
                recognized = any(marker in os.readlink(path) for marker in ("encap", "Application Support"))
            elif path.is_file():
                with path.open("rb") as file:
                    content = file.read(4096)
                recognized = content.startswith(b"#!") and any(marker in content for marker in (
                    b'.local/bin/encap', b'.local/share/encap', b'Application Support/encap',
                ))
            else:
                recognized = False
            if not recognized:
                continue
            if os.access(path.parent, os.W_OK):
                path.unlink()
            else:
                sudo_ready(True)
                run(["sudo", "-n", "rm", "-f", str(path)])
        relay_link = local_bin / "wstunnel"
        if relay_link.is_symlink() and os.readlink(relay_link) == str(home / ".local" / "share" / "encap" / "bin" / "wstunnel"):
            relay_link.unlink()
        remove_encap_path(local_bin / "encap")
        remove_encap_path(home / ".local" / "share" / "encap")
        remove_encap_path(config_dir)
        remove_encap_path(home / ".local" / "state" / "encap")
    finally:
        os.close(guard)
    log("ok", "Encap removed")


def doctor(config):
    if platform.system() != "Darwin":
        raise EncapError("macOS only")
    default = route("default")
    interface = field(default, "interface")
    gateway = field(default, "gateway")
    service = network_service(interface) if interface else None
    current_ssid = ssid(interface) if interface and service else ""
    log("ok", "Config and tools ready")
    if service and gateway:
        log("ok", f"Network: {current_ssid or service} ({interface})")
    else:
        log("warn", "No active network")
    log("ok", f"Server: {config['tls_host']} ({config['server_ip']})")
    server_status = server_route_status(config["server_ip"])
    if server_status == "stale":
        log("warn", "Stale server route; encap will remove it")
    elif server_status == "custom":
        log("warn", "Server has a custom route")
    if any(prefix_owner(prefix) for prefix, _alias in PREFIXES):
        log("warn", "Another tunnel owns the routes")
    if load_state():
        log("warn", "Session needs cleanup")
        hint("run encap stop")


def enrollment_request(server, path, payload=None, extra_headers=None, timeout=12):
    body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(
        server + path,
        data=body,
        headers={"Accept": "application/json", "Content-Type": "application/json", **(extra_headers or {})},
        method="GET" if body is None else "POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as response:
            if response.status not in (200, 201):
                raise EncapError("Enrollment unavailable")
            result = json.loads(response.read(4097))
    except urllib.error.HTTPError as error:
        try:
            detail = json.loads(error.read(1024)).get("error", "Enrollment failed")
        except (ValueError, AttributeError):
            detail = "Enrollment failed"
        raise EncapError(f"Server: {detail}") from error
    except (urllib.error.URLError, TimeoutError, ValueError) as error:
        raise EncapError(f"Enrollment unavailable: {error}") from error
    if not isinstance(result, dict):
        raise EncapError("Invalid server response")
    return result


def release_public(state):
    header_file = state.get("access_header_file")
    host = state.get("tls_host")
    if not header_file or not host:
        return
    try:
        header = private_file(header_file).read_text().strip()
        match = re.fullmatch(r"Authorization: Bearer ([A-Za-z0-9_-]{43})", header)
        if not match or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
            raise EncapError("Invalid public access credential")
        enrollment_request(f"https://{host}", "/v1/release", {},
                           {"Authorization": f"Bearer {match.group(1)}"}, timeout=3)
        log("debug", "Server slot released")
    except (EncapError, OSError) as error:
        log("debug", f"Server slot release deferred: {error}")


def validated_key(value):
    if not isinstance(value, str):
        raise EncapError("Invalid WireGuard key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise EncapError("Invalid WireGuard key") from error
    if len(decoded) != 32 or base64.b64encode(decoded).decode() != value:
        raise EncapError("Invalid WireGuard key")
    return value


def solve_challenge(challenge, public_key, difficulty):
    if not isinstance(challenge, str) or not re.fullmatch(r"[0-9a-f]{32}\.[0-9]{10}\.[0-9a-f]{64}", challenge):
        raise EncapError("Invalid server challenge")
    if type(difficulty) is not int or not 12 <= difficulty <= 22:
        raise EncapError("Invalid server challenge")
    prefix = f"{challenge}:{public_key}:".encode()
    for counter in range(1000000001):
        digest = hashlib.sha256(prefix + str(counter).encode()).digest()
        if int.from_bytes(digest, "big") >> (256 - difficulty) == 0:
            return counter
    raise EncapError("Enrollment proof failed")


def write_private(path, content):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as file:
        file.write(content)
        file.flush()
        os.fsync(file.fileno())


def resume_public(config):
    if not config.get("access_token"):
        return
    result = enrollment_request(
        f"https://{config['tls_host']}", "/v1/resume", {},
        {"Authorization": f"Bearer {config['access_token']}"},
    )
    try:
        address = str(ipaddress.IPv4Address(result.get("client_ip")))
    except (TypeError, ValueError) as error:
        raise EncapError("Invalid server address") from error
    profile = pathlib.Path(config["profile"])
    original = profile.read_text()
    updated, count = re.subn(r"(?m)^Address = [0-9.]+/32$", f"Address = {address}/32", original)
    if count != 1:
        raise EncapError("Invalid WireGuard address")
    if updated != original:
        temporary = profile.with_name(profile.name + ".new-" + secrets.token_hex(4))
        try:
            write_private(temporary, updated)
            os.replace(temporary, profile)
        finally:
            temporary.unlink(missing_ok=True)
        log("info", "Server address updated")


def enroll_public(server, path):
    target = pathlib.Path(path).expanduser().resolve()
    parsed = urlparse(server)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.port not in (None, 443) or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise EncapError("Use a direct HTTPS server address")
    server = f"https://{parsed.hostname}"
    guard = lock(nonblocking=True)
    progress = ConnectionProgress()
    try:
        if target.exists():
            raise EncapError("Already enrolled")
        wg = resolve_binary("wg")
        resolve_binary("wg-quick")
        resolve_binary("wireguard-go")
        wstunnel = resolve_binary("wstunnel")
        private_key = validated_key(run([wg, "genkey"]).stdout.strip())
        try:
            public_result = subprocess.run([wg, "pubkey"], input=private_key + "\n", capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise EncapError("Could not create WireGuard key") from error
        if public_result.returncode:
            raise EncapError("Could not create WireGuard key")
        public_key = validated_key(public_result.stdout.strip())
        host = parsed.hostname
        server_ip = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]
        prepare_server_route(server_ip)
        progress.start("Registering this Mac")
        challenge = enrollment_request(server, "/v1/challenge")
        counter = solve_challenge(challenge.get("challenge"), public_key, challenge.get("difficulty"))
        response = enrollment_request(server, "/v1/enroll", {
            "public_key": public_key,
            "challenge": challenge["challenge"],
            "counter": counter,
        })
        address = str(ipaddress.IPv4Address(response.get("client_ip")))
        server_key = validated_key(response.get("server_public_key"))
        token = response.get("access_token")
        relay_path = response.get("relay_path")
        if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", token):
            raise EncapError("Invalid access token from server")
        if not isinstance(relay_path, str) or not re.fullmatch(r"[a-z0-9_-]{1,32}", relay_path):
            raise EncapError("Invalid relay path from server")
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(target.parent, 0o700)
        suffix = hashlib.sha256(public_key.encode()).hexdigest()[:12]
        profile = target.parent / f"e-{suffix}.conf"
        token_file = target.parent / f"e-{suffix}.token"
        profile_text = (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {address}/32\n"
            "MTU = 1280\n"
            "Table = off\n\n"
            "[Peer]\n"
            f"PublicKey = {server_key}\n"
            "AllowedIPs = 0.0.0.0/0\n"
            "Endpoint = 127.0.0.1:51820\n"
            "PersistentKeepalive = 20\n"
        )
        config = {
            "server_ip": server_ip,
            "tls_host": host,
            "access_token_file": str(token_file),
            "relay_path": relay_path,
            "relay_target": "wireguard:51820",
            "wireguard_profile": str(profile),
            "local_port": 51820,
            "dns_servers": ["1.1.1.1"],
            "expected_exit_ip": server_ip,
            "health_url": "https://example.org/",
            "wstunnel": wstunnel,
            "wg_quick": resolve_binary("wg-quick"),
            "wg": wg,
            "wireguard_go": resolve_binary("wireguard-go"),
        }
        try:
            write_private(profile, profile_text)
            write_private(token_file, f"Authorization: Bearer {token}\n")
            write_private(target, json.dumps(config, indent=2) + "\n")
        except Exception:
            profile.unlink(missing_ok=True)
            token_file.unlink(missing_ok=True)
            target.unlink(missing_ok=True)
            raise
        progress.pause()
        log("ok", "Registered this Mac")
    finally:
        progress.pause()
        os.close(guard)


def main():
    global DEBUG
    parser = argparse.ArgumentParser(
        prog="encap",
        description="Private tunnel over HTTPS for macOS",
        epilog="Run encap to open or close the tunnel. Use encap status to check.",
    )
    parser.add_argument("--config", help="Config file path")
    parser.add_argument("--server", help="HTTPS server for first setup")
    parser.add_argument("--debug", action="store_true", help="Show details")
    parser.add_argument("command", nargs="?", default="toggle", choices=("doctor", "connect", "status", "stop", "disconnect", "enroll", "uninstall"))
    args = parser.parse_args()
    DEBUG = args.debug
    try:
        if args.command == "uninstall":
            if args.config or args.server:
                raise EncapError("Uninstall does not accept --config or --server")
            uninstall()
            return 0
        if args.server and args.command != "enroll" and config_path(args.config).is_file():
            raise EncapError("Already enrolled. Use encap --config PATH --server URL to add another server")
        if args.command == "enroll":
            enroll_public(args.server or PUBLIC_SERVER, config_path(args.config))
        elif args.command == "toggle":
            if load_state():
                disconnect()
            else:
                banner()
                path = config_path(args.config)
                if not path.is_file():
                    enroll_public(args.server or PUBLIC_SERVER, path)
                config = load_config(path)
                prepare_server_route(config["server_ip"])
                resume_public(config)
                connect(config)
        elif args.command == "status":
            status()
        elif args.command in ("stop", "disconnect"):
            disconnect()
        else:
            path = config_path(args.config)
            if args.command == "connect":
                banner()
            if args.command == "connect" and not path.is_file():
                enroll_public(args.server or PUBLIC_SERVER, path)
            config = load_config(path)
            if args.command == "doctor":
                doctor(config)
            else:
                prepare_server_route(config["server_ip"])
                resume_public(config)
                connect(config)
    except KeyboardInterrupt:
        print(flush=True)
        return 130
    except (EncapError, KeyError, ValueError, OSError, plistlib.InvalidFileException) as error:
        log("error", str(error))
        if DEBUG:
            traceback.print_exc()
        else:
            hint("run encap --debug for details")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
