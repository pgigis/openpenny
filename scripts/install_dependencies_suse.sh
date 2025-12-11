#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

# Install build dependencies for Penny on openSUSE Leap / Tumbleweed.
set -euo pipefail

# Refresh repositories
sudo zypper refresh

# Core development tools
sudo zypper install -y \
    gcc gcc-c++ make cmake git pkgconfig \
    kernel-devel clang llvm llvm-devel

# Libraries needed for XDP / BPF
sudo zypper install -y \
    libelf-devel libbpf-devel libxdp-devel \
    libopenssl-devel libpcap-devel zlib-devel

# Protobuf + gRPC
sudo zypper install -y \
    protobuf-devel protobuf-compiler \
    grpc-devel grpc-compiler grpc-plugins \
    libgrpc++-devel

echo "Dependencies installed successfully on openSUSE."
echo "For DPDK: install dpdk-devel and configure hugepages / NIC binding separately."
