#!/usr/bin/env bash
set -u

NS="nfgtest"
HOST_IF="nfg-host"
NS_IF="nfg-ns"
HOST_IP="10.200.0.1"
NS_IP="10.200.0.2"
PORT="18080"
RESULT_FILE="results/runtime_validation.txt"
SERVER_PID=""

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root: sudo ./scripts/run_isolated_validation.sh" >&2
    exit 1
fi

for cmd in ip python3 hping3; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Missing required command: $cmd" >&2
        exit 1
    fi
done

if [[ ! -f ./netfilter_guard.ko ]]; then
    echo "netfilter_guard.ko not found. Run 'make' first." >&2
    exit 1
fi

cleanup() {
    if [[ -n "$SERVER_PID" ]]; then
        kill "$SERVER_PID" >/dev/null 2>&1 || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if lsmod | grep -q '^netfilter_guard'; then
        rmmod netfilter_guard >/dev/null 2>&1 || true
    fi
    ip netns del "$NS" >/dev/null 2>&1 || true
    ip link del "$HOST_IF" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

cleanup

mkdir -p results
: > "$RESULT_FILE"

log() {
    echo "$*" | tee -a "$RESULT_FILE"
}

status_snapshot() {
    local label="$1"
    {
        echo
        echo "===== ${label} ====="
        cat /proc/netfilter_guard
    } | tee -a "$RESULT_FILE"
}

log "NetfilterGuard isolated validation"
log "kernel: $(uname -r)"
log "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

ip netns add "$NS"
ip link add "$HOST_IF" type veth peer name "$NS_IF"
ip link set "$NS_IF" netns "$NS"
ip addr add "${HOST_IP}/24" dev "$HOST_IF"
ip link set "$HOST_IF" up
ip netns exec "$NS" ip addr add "${NS_IP}/24" dev "$NS_IF"
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip link set "$NS_IF" up

insmod ./netfilter_guard.ko \
    interface="$HOST_IF" \
    window_seconds=5 \
    ban_seconds=8 \
    syn_threshold=40 \
    tcp_threshold=100 \
    udp_threshold=100 \
    min_completion_pct=25 \
    idle_timeout_seconds=60 \
    max_entries=128

python3 -m http.server "$PORT" --bind "$HOST_IP" >/tmp/netfilter_guard_http.log 2>&1 &
SERVER_PID=$!
sleep 1

status_snapshot "baseline"

log "[1/4] ordinary TCP connections"
for _ in 1 2 3 4 5; do
    ip netns exec "$NS" python3 - "$HOST_IP" "$PORT" <<'PY'
import socket
import sys
host = sys.argv[1]
port = int(sys.argv[2])
try:
    with socket.create_connection((host, port), timeout=1.0):
        pass
except OSError:
    pass
PY
    sleep 0.2
done
status_snapshot "after_normal_tcp"

log "Waiting for a fresh observation window..."
sleep 6

log "[2/4] finite SYN-heavy probe"
ip netns exec "$NS" hping3 -S -p "$PORT" -c 60 -i u20000 "$HOST_IP" >/dev/null 2>&1 || true
status_snapshot "after_syn_probe"

log "Waiting for temporary SYN block to expire..."
sleep 9

log "[3/4] finite TCP-rate probe"
ip netns exec "$NS" hping3 -A -p "$PORT" -c 120 -i u10000 "$HOST_IP" >/dev/null 2>&1 || true
status_snapshot "after_tcp_rate_probe"

log "Waiting for temporary TCP block to expire..."
sleep 9

log "[4/4] finite UDP-rate probe"
ip netns exec "$NS" hping3 --udp -p "$PORT" -c 120 -i u10000 "$HOST_IP" >/dev/null 2>&1 || true
status_snapshot "after_udp_rate_probe"

{
    echo
    echo "===== kernel_log_tail ====="
    dmesg | grep 'netfilter_guard:' | tail -n 30
} | tee -a "$RESULT_FILE"

log "Validation finished. Result: $RESULT_FILE"
