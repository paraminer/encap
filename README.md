# Encap

Encap connects a Mac to a WireGuard VPN through HTTPS WebSocket. The client creates its own key and registers over verified HTTPS. The default public server is `167.104.110.55`.

## Install on macOS

On a new Mac, install and connect with one Terminal command:

```sh
curl -fsSL https://raw.githubusercontent.com/paraminer/encap/main/bootstrap.sh | sh
```

The bootstrap script downloads and checks `encap.py`, adds Homebrew if needed, installs Python and WireGuard tools, verifies wstunnel, installs `encap`, and starts the connection. Homebrew and the VPN may ask for the Mac administrator password. Keep Terminal open while connected; press Ctrl+C to disconnect. In a new Terminal window, run `encap` to connect or disconnect again. `encap status`, `encap stop`, and `encap doctor` are also available. To install from a local checkout without connecting, run `ENCAP_INSTALL_ONLY=1 sh bootstrap.sh`.

To use your own server, run `encap --server https://YOUR_PUBLIC_IP` on first launch. Use `--config PATH` for a separate registration. Private keys and tokens stay in `~/.config/encap` with file mode `0600`.

The free server allows 40 active guest devices. A normal disconnect frees a slot immediately; after an abrupt loss, the server releases it about ten minutes after the last WireGuard handshake. The registration remains valid for a later connection. Each device has a 10 GB monthly limit; the server has a 500 GB monthly guest traffic limit. IPv4 is routed through the VPN. IPv6 traffic stays on the current network.

## Run your own server

Clone the full repository to use the server code:

```sh
git clone https://github.com/paraminer/encap.git
cd encap
```

Use a dedicated Linux VPS with Docker Engine, Docker Compose, Python 3 with `venv`, `curl`, systemd, and inbound TCP 80 and 443. On that VPS, run:

```sh
sudo ./server/setup.sh YOUR_PUBLIC_IP you@example.com
```

The setup script creates `/opt/encap`, requests an IP certificate, starts the containers, and enables daily certificate renewal. It refuses to overwrite an existing installation. Check the server with:

```sh
cd /opt/encap
docker compose -f compose.public.yaml ps
docker compose -f compose.public.yaml exec control python3 /app/control.py stats
systemctl status encap-certbot.timer
```

Use `list` and `revoke PEER_ID` in the same administration command to inspect or disable an individual guest. Limits can be set in `/opt/encap/.env` using `ENCAP_MAX_PEERS`, `ENCAP_MONTHLY_BYTES`, `ENCAP_GLOBAL_MONTHLY_BYTES`, `ENCAP_PER_IP_DAILY`, `ENCAP_PER_IP_MONTHLY`, and `ENCAP_IDLE_MINUTES`; then run `docker compose -f compose.public.yaml up -d`.

The public stack authenticates WebSocket upgrades before forwarding them to the relay. Tokens are hashed in SQLite; client private keys are never stored on the server. Guest forwarding to private and reserved IPv4 ranges and SMTP ports 25, 465, and 587 is blocked. Back up `/opt/encap/data`, `/opt/encap/wg-config`, and `/etc/letsencrypt` privately. Monitor bandwidth and certificate renewal on a public exit server.

The current server keeps a separate secret path for the owner's existing connection. Its `Caddyfile.open` accepts registration; `Caddyfile.closed` pauses it. These files are operational variants of `Caddyfile.public`. Do not use the clean-server setup script on this existing server.

If `encap.py` changes, update its pinned SHA-256 in `bootstrap.sh`.

License: MIT.
