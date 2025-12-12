#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause

# Install build dependencies for Penny on Rocky Linux / RHEL / CentOS.
set -euo pipefail

# Detect package manager (Rocky uses dnf)
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR=dnf
else
    PKG_MGR=yum
fi

# Enable EPEL for some development packages (common on Rocky)
sudo "$PKG_MGR" install -y epel-release

# Install core development tools
sudo "$PKG_MGR" groupinstall -y "Development Tools"

# Install Penny build dependencies
sudo "$PKG_MGR" install -y \
    gcc gcc-c++ make cmake pkgconfig \
    elfutils-libelf-devel libbpf libbpf-devel libxdp libxdp-devel \
    openssl-devel libpcap-devel \
    kernel-devel-$(uname -r) \
    bison flex \
    protobuf-devel protobuf-compiler \
    grpc-devel grpc-plugins grpc-plugins 

echo "Dependencies installed successfully on Rocky Linux."
echo "For DPDK, install dpdk-devel and configure hugepages/NIC binding separately."
