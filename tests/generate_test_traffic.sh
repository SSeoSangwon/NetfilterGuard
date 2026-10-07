#!/usr/bin/env bash
set -u

usage() {
    echo "Usage: $0 <TARGET_IP> <normal|syn|tcp|udp> [PORT]" >&2
    echo "This script intentionally refuses public destination IP addresses." >&2
}

if [[ $# -lt 2 || $# -gt 3 ]]; then
    usage
    exit 1
fi

TARGET_IP="$1"
MODE="$2"
PORT="${3:-8080}"

python3 - "$TARGET_IP" <<'PY'
import ipaddress
import sys

try:
    ip = ipaddress.ip_address(sys.argv[1])
except ValueError:
    raise SystemExit("TARGET_IP must be a valid IPv4/IPv6 address")

if not (ip.is_private or ip.is_loopback or ip.is_link_local):
    raise SystemExit("Refusing to generate test traffic toward a public IP address")
PY

run_root() {
    if [[ ${EUID} -eq 0 ]]; then
        "$@"
    else
        sudo "$@"
    fi
}

case "$MODE" in
    normal)
        echo "Opening five ordinary TCP connection attempts to ${TARGET_IP}:${PORT}."
        python3 - "$TARGET_IP" "$PORT" <<'PY'
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
for _ in range(5):
    try:
        with socket.create_connection((host, port), timeout=1.0):
            pass
    except OSError:
        pass
    time.sleep(0.2)
PY
        ;;
    syn)
        command -v hping3 >/dev/null 2>&1 || {
            echo "hping3 is required for SYN validation." >&2
            exit 1
        }
        echo "Sending 60 finite SYN probes to ${TARGET_IP}:${PORT}."
        run_root hping3 -S -p "$PORT" -c 60 -i u20000 "$TARGET_IP"
        ;;
    tcp)
        command -v hping3 >/dev/null 2>&1 || {
            echo "hping3 is required for TCP-rate validation." >&2
            exit 1
        }
        echo "Sending 120 finite TCP ACK probes to ${TARGET_IP}:${PORT}."
        run_root hping3 -A -p "$PORT" -c 120 -i u10000 "$TARGET_IP"
        ;;
    udp)
        command -v hping3 >/dev/null 2>&1 || {
            echo "hping3 is required for UDP-rate validation." >&2
            exit 1
        }
        echo "Sending 120 finite UDP probes to ${TARGET_IP}:${PORT}."
        run_root hping3 --udp -p "$PORT" -c 120 -i u10000 "$TARGET_IP"
        ;;
    *)
        usage
        exit 1
        ;;
esac
