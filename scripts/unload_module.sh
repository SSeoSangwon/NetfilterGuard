#!/usr/bin/env bash
set -u

if [[ ${EUID} -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
fi

rmmod netfilter_guard
echo "NetfilterGuard unloaded."
