#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ] || [ "$(uname -s)" != Linux ] || [ "$#" -ne 2 ]; then
    printf 'Usage: sudo ./setup.sh PUBLIC_IP EMAIL\n' >&2
    exit 1
fi

encap_ip=$1
encap_email=$2
python3 - "$encap_ip" "$encap_email" <<'PY'
import ipaddress
import sys
ip = ipaddress.ip_address(sys.argv[1])
if ip.version != 4 or not ip.is_global:
    raise SystemExit("A public IPv4 address is required")
if "@" not in sys.argv[2] or any(char.isspace() for char in sys.argv[2]):
    raise SystemExit("A valid email address is required")
PY

if [ -e /opt/encap ]; then
    printf '/opt/encap already exists. Setup stopped.\n' >&2
    exit 1
fi
for encap_command in docker python3 curl systemctl; do
    if ! command -v "$encap_command" >/dev/null 2>&1; then
        printf '%s is required.\n' "$encap_command" >&2
        exit 1
    fi
done
if ! docker compose version >/dev/null 2>&1; then
    printf 'Docker Compose plugin is required.\n' >&2
    exit 1
fi
if ! python3 -m venv --help >/dev/null 2>&1; then
    printf 'python3-venv is required.\n' >&2
    exit 1
fi

encap_source=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
umask 077
install -d -m 700 /opt/encap /opt/encap/acme /opt/encap/data /opt/encap/run /opt/encap/wg-config
install -m 644 "$encap_source/compose.public.yaml" /opt/encap/compose.public.yaml
install -m 644 "$encap_source/Caddyfile.public" /opt/encap/Caddyfile.public
install -m 644 "$encap_source/Dockerfile.control" /opt/encap/Dockerfile.control
install -m 644 "$encap_source/control.py" /opt/encap/control.py
install -m 700 "$encap_source/reload-cert.sh" /opt/encap/reload-cert.sh
printf 'PUBLIC_HOST=%s\n' "$encap_ip" > /opt/encap/.env
python3 -m venv /opt/encap/certbot
/opt/encap/certbot/bin/pip install --disable-pip-version-check 'certbot>=5.4,<6'

python3 -m http.server 80 --bind 0.0.0.0 --directory /opt/encap/acme >/dev/null 2>&1 &
encap_http_pid=$!
trap 'kill "$encap_http_pid" 2>/dev/null || true' EXIT HUP INT TERM
sleep 1
if ! kill -0 "$encap_http_pid" 2>/dev/null; then
    printf 'Port 80 is unavailable.\n' >&2
    exit 1
fi
/opt/encap/certbot/bin/certbot certonly --non-interactive --agree-tos --email "$encap_email" \
    --preferred-profile shortlived --webroot --webroot-path /opt/encap/acme \
    --ip-address "$encap_ip" --deploy-hook /opt/encap/reload-cert.sh
kill "$encap_http_pid" 2>/dev/null || true
wait "$encap_http_pid" 2>/dev/null || true
trap - EXIT HUP INT TERM

cat > /etc/systemd/system/encap-certbot.service <<'UNIT'
[Unit]
Description=Renew ENCAP IP certificate

[Service]
Type=oneshot
EnvironmentFile=/opt/encap/.env
ExecStart=/opt/encap/certbot/bin/certbot renew --quiet --no-random-sleep-on-renew --cert-name ${PUBLIC_HOST}
UNIT
cat > /etc/systemd/system/encap-certbot.timer <<'UNIT'
[Unit]
Description=Check ENCAP IP certificate daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
UNIT
chmod 644 /etc/systemd/system/encap-certbot.service /etc/systemd/system/encap-certbot.timer
systemctl daemon-reload
systemctl enable --now encap-certbot.timer
cd /opt/encap
docker compose -f compose.public.yaml up -d --build
printf 'Server ready: https://%s\n' "$encap_ip"
