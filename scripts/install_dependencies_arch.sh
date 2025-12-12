#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

# Install build dependencies for Penny on Arch Linux.
set -euo pipefail

sudo pacman -S --needed --noconfirm \
    base-devel cmake elfutils libbpf libxdp \
    openssl libpcap protobuf grpc

echo "Dependencies installed. For DPDK, install dpdk (may be in community/AUR) and configure hugepages/NIC binding separately."
