#!/usr/bin/env bash
set -euo pipefail
IFACE="${1:-eth1}"

echo "[Uni-Gap] One-way lab checks for interface: ${IFACE}"
if ! ip link show "${IFACE}" >/dev/null 2>&1; then
  echo "ERROR: interface ${IFACE} not found"; exit 2
fi

echo "\n[1] Interface state"
ip -br link show "${IFACE}"

echo "\n[2] Routes bound to the capture interface"
ip route show dev "${IFACE}" || true

echo "\n[3] Address assignments"
ip addr show dev "${IFACE}" || true

echo "\n[4] ARP/neighbor state (should not be used for active probing)"
ip neigh show dev "${IFACE}" || true

echo "\n[5] Passive capture smoke test (5 seconds)"
if command -v timeout >/dev/null && command -v tcpdump >/dev/null; then
  timeout 5 tcpdump -ni "${IFACE}" -c 5 || true
else
  echo "tcpdump/timeout unavailable; install tcpdump for capture verification."
fi

echo "\nRESULT: Local-state checks complete. This script cannot certify the physical data-diode hardware."
