#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

# Install build dependencies for Penny on Ubuntu/Debian.
set -euo pipefail

sudo apt-get update

# Core development tools
sudo apt-get install -y \
    build-essential cmake git pkg-config \
    clang llvm llvm-dev libclang-dev \
    libelf-dev libpcap-dev libssl-dev zlib1g-dev \
    linux-headers-$(uname -r)

# eBPF / XDP dependencies (Ubuntu ≥ 22.04)
sudo apt-get install -y \
    libbpf-dev libxdp-dev

# Protobuf + gRPC
sudo apt-get install -y \
    libprotobuf-dev protobuf-compiler \
    libgrpc++-dev libgrpc++1 grpc-proto grpc-compiler

echo "Dependencies installed successfully on Ubuntu/Debian."
echo "For DPDK: install libdpdk-dev and configure hugepages / NIC binding separately."
