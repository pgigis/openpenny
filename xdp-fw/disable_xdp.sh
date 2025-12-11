#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

# Disable all XDP programs from all interfaces (driver/generic/offload).

set -euo pipefail

echo "=== Disabling all XDP programs ==="

# Get all interface names
IFS=$'\n' read -r -d '' -a ifaces < <(ip -o link show | awk -F': ' '{print $2}' && printf '\0')

for IF in "${ifaces[@]}"; do
    echo "--- Processing interface: $IF ---"
    for mode in xdp xdpgeneric xdpdrv xdpoffload; do
        if sudo ip link set dev "$IF" "$mode" off 2>/dev/null; then
            echo "  ✔ Disabled mode: $mode"
        fi
    done
done

echo
echo "=== Remaining XDP attachments ==="
sudo bpftool net show 2>/dev/null | grep xdp || echo "No active XDP programs found."
echo "Done."
