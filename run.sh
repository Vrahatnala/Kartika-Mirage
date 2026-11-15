#!/usr/bin/env bash
# Jalankan KARTIKA-MIRAGE (engine :8000 + VIP gateway :8001). Ctrl+C menghentikan keduanya.
cd "$(dirname "$0")"
python3 mirage-engine/main.py &
ENGINE=$!
(cd vip-gateway && python3 vip_server.py) &
GATEWAY=$!
trap 'kill $ENGINE $GATEWAY 2>/dev/null' INT TERM EXIT
wait
