#!/bin/sh
set -eu
cd /opt/encap
if [ -f compose.public.yaml ]; then
    if docker compose -f compose.public.yaml ps --status running --services | grep -qx https; then
        docker compose -f compose.public.yaml --progress quiet restart https
    fi
else
    docker compose --progress quiet restart https
fi
