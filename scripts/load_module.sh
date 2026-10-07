#!/usr/bin/env bash
set -u

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root: sudo $0 [module parameters...]" >&2
    exit 1
fi

if [[ ! -f ./netfilter_guard.ko ]]; then
    echo "netfilter_guard.ko not found. Run 'make' first." >&2
    exit 1
fi

insmod ./netfilter_guard.ko "$@"
echo "NetfilterGuard loaded."
echo "Status: cat /proc/netfilter_guard"
echo "Logs:   dmesg | tail -n 30"
