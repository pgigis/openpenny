#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

# Disable all XDP programs from all interfaces (driver/generic/offload)
# and remove any pinned BPF maps (from /sys/fs/bpf).

set -euo pipefail

script_dir="$(cd -- "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Running XDP disable and cleanup ==="
"${script_dir}/disable_xdp.sh"

echo
echo "=== Cleaning pinned BPF maps ==="
sudo rm -f /sys/fs/bpf/xdp_fw_conf /sys/fs/bpf/xdp_fw_xsks 2>/dev/null || true
sudo find /sys/fs/bpf -maxdepth 1 -type f -name 'xdp_*' -exec sudo rm -f {} + 2>/dev/null || true

echo
echo "=== Verifying cleanup ==="
sudo bpftool net show 2>/dev/null | grep xdp || echo "No active XDP programs found."
sudo find /sys/fs/bpf -maxdepth 1 -type f -name 'xdp_*' | head -n 1 | grep xdp >/dev/null 2>&1 && echo "Pinned XDP maps remain under /sys/fs/bpf" || echo "No pinned XDP maps found."
echo "Done."
