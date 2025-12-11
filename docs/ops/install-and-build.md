# Install & Build Guide

This guide explains how to install the required dependencies, build the OpenPenny CLI (`openpenny_cli`), and compile the gRPC daemon (`pennyd` + `penny_worker`). It includes distribution‑specific instructions, build options, and troubleshooting steps.

---

## Prerequisites (Debian / Ubuntu)

Required development packages:

- **Compiler / toolchain:** `build-essential`, `cmake`, `pkg-config`
- **XDP / BPF:** `libbpf-dev`, `libxdp-dev`, `libelf-dev`
- **Optional DPDK:** `libdpdk-dev` (requires hugepages and NIC driver binding)
- **gRPC / Protobuf:** `libprotobuf-dev`, `protobuf-compiler`, `libgrpc++-dev`, `libgrpc-dev`, `protobuf-compiler-grpc`
- **Networking libraries:** `libpcap-dev`, `libssl-dev`

To install dependencies via script (validated on Rocky; others available in `scripts/`):

```bash
./scripts/install_dependencies.sh   # RHEL / CentOS / Rocky / Fedora
```

Additional scripts:

- `scripts/install_dependencies_ubuntu.sh` – Ubuntu / Debian  
- `scripts/install_dependencies_suse.sh` – openSUSE  
- `scripts/install_dependencies_arch.sh` – Arch Linux  

---

## Other Distributions

Package names may vary per distro version.

### RHEL / CentOS / Rocky / Fedora

```bash
sudo dnf install -y gcc gcc-c++ make cmake pkgconfig elfutils-libelf-devel     libbpf-devel libxdp-devel openssl-devel libpcap-devel     protobuf-devel protobuf-compiler grpc-devel grpc-plugins grpc-compiler     grpcpp-devel
```

For DPDK support:

```bash
sudo dnf install -y dpdk-devel
```

After installation, configure hugepages and bind NICs to a suitable DPDK driver.

---

### openSUSE (zypper)

```bash
sudo zypper install -y gcc gcc-c++ make cmake pkgconfig libelf-devel     libbpf-devel libxdp-devel libopenssl-devel libpcap-devel     protobuf-devel protobuf-compiler grpc-devel grpc-plugins grpc-compiler     grpc++-devel
```

---

### Arch Linux (pacman)

```bash
sudo pacman -S --needed base-devel cmake elfutils libbpf libxdp openssl libpcap     protobuf grpc
```

For DPDK:

```bash
sudo pacman -S dpdk
```

(Some installations may require AUR packages or manual builds.)

---

## Build the CLI (XDP Only)

Enable XDP and disable DPDK:

```bash
cmake -S . -B build -DOPENPENNY_WITH_XDP=ON -DOPENPENNY_WITH_DPDK=OFF
cmake --build build
```

Generated artifact:

- **`build/openpenny_cli`**

---

## Build CLI + gRPC Daemon

Ensure gRPC / Protobuf development packages are available:

```bash
cmake -S . -B build -DOPENPENNY_WITH_XDP=ON \
  -DgRPC_DIR=/usr/lib64/cmake/grpc \
  -DProtobuf_DIR=/usr/lib64/cmake/protobuf \
  -DGRPC_CPP_PLUGIN=/usr/bin/grpc_cpp_plugin   # adjust paths for your system
cmake --build build
```

Generated artifacts:

- **CLI:** `build/openpenny_cli`  
- **gRPC server:** `build/pennyd`  
- **Worker binary:** `build/penny_worker`  

---

## Build with DPDK (optional)

Enable DPDK and disable XDP:

```bash
cmake -S . -B build -DOPENPENNY_WITH_DPDK=ON -DOPENPENNY_WITH_XDP=OFF
cmake --build build
```

Requirements:

- DPDK development packages  
- Configured hugepages  
- NIC bound to a DPDK‑compatible driver  

---

## Run Examples

- **CLI (active mode):** `docs/run/cli-guide.md`  
- **CLI (passive mode):** `docs/run/cli-readme.md`  
- **gRPC usage:** `docs/run/grpc-guide.md` and Python examples in `examples/`  

---

## Troubleshooting

### `pennyd` not built  
gRPC or Protobuf were missing at configure time. Install the necessary dev packages and rerun CMake.

### CMake cannot find gRPC / Protobuf  
Specify their locations manually:

```bash
cmake -S . -B build     -DgRPC_DIR=/path/to/lib/cmake/gRPC     -DProtobuf_DIR=/path/to/lib/cmake/protobuf
```

### Permission‑related issues  
XDP, TUN, and RAW socket forwarding require root privileges or `CAP_NET_ADMIN`.

### DPDK‑related failures  
Ensure hugepages are allocated and the NIC is correctly bound to the DPDK driver.

### XDP: no packets or attach failures  
- Rebuild the BPF object: `cmake --build build --target xdp_bpf` (or `make -C xdp-fw xdp_redirect_dstprefix.o`).  
- Detach and clean pins, then retry:  
  ```bash
  sudo python3 scripts/xdp_attach.py --iface <if> --mode drv --detach
  sudo rm -rf /sys/fs/bpf/openpenny*
  sudo ./build/openpenny_cli --config examples/configs/config_default.yaml --iface <if> --queue 0 --mode active --tun xdp-tun
  ```  
- Verify attachment and xsks map:  
  ```bash
  ip -details link show dev <if> | grep -i xdp
  bpftool map dump pinned /sys/fs/bpf/openpenny_<if>_<mask>/xsks
  ```  
- If the NIC/driver lacks zero-copy support, set `require_zerocopy: false`, `allow_skb_fallback: true`, and `allow_copy_fallback: true` in `examples/configs/config_default.yaml`.

---
