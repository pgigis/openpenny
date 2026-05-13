# OpenPenny

[![CI](https://github.com/pgigis/openpenny/actions/workflows/ci.yml/badge.svg)](https://github.com/pgigis/openpenny/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BSD%202--Clause-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.1.0-green.svg)](docs/project/CHANGELOG.md)

<p align="center">
  <img src="docs/images/openpenny_logo.png" alt="OpenPenny logo" />
</p>

OpenPenny tells you whether TCP traffic entering your network is **genuinely
non-spoofed**. It implements the Penny test
([SIGCOMM '24](https://dl.acm.org/doi/10.1145/3651890.3672259)): drop a small
number of packets in a redirected slice of traffic and watch which packets get
retransmitted. Genuine TCP senders retransmit; spoofed sources do not.

Two modes:

- **Active.** Drop a few packets in the slice; observe retransmissions.
- **Passive.** Observe only — sequence coverage, gaps, duplicates, FIN/RST,
  idle expiry. No packets are dropped.

Capture is over **AF_XDP** (default), **AF_PACKET** (copy-mode tap), or
**DPDK**. Optional forwarding to a TUN device or raw socket. Drive it from
the **CLI** (`openpenny_cli`) or the **gRPC daemon** (`pennyd` +
`penny_worker`).

<p align="center">
  <img src="docs/images/slice-traffic-figure.png" alt="Traffic slicing and analysis" />
</p>

## Quick start

```bash
# Build the CLI (XDP-only).
cmake -S . -B build -DOPENPENNY_WITH_XDP=ON -DOPENPENNY_WITH_DPDK=OFF
cmake --build build

# Run an active test on TCP/5201 traffic.
sudo ./build/openpenny_cli \
  --config examples/configs/config_minimal_active.yaml \
  --iface <ifname> --tun xdp-tun
```

For passive observation, swap to `config_minimal_passive.yaml` and add
`--mode passive`. The two minimal configs are single-file, no includes;
production-shaped equivalents that split policy and platform live at
`examples/configs/config_default.yaml` and `config_passive.yaml`.

Other entry points:

- gRPC daemon: see [`docs/run/grpc-guide.md`](docs/run/grpc-guide.md).
- Threshold reference: [`docs/run/tuning-reference.md`](docs/run/tuning-reference.md).
- More config examples: [`docs/run/configuration-examples.md`](docs/run/configuration-examples.md).

## Requirements

| Category        | Requirement                                                |
| --------------- | ---------------------------------------------------------- |
| OS / privileges | Linux with root or `CAP_NET_ADMIN`; kernel XDP for AF_XDP. |
| Toolchain       | CMake ≥ 3.16, C++17 compiler, `pkg-config`.                |
| Libraries       | `libbpf`, `libxdp`, `libelf`, `libpcap`, `openssl`.        |
| Optional (DPDK) | `libdpdk` plus hugepages and driver binding.               |
| Optional (gRPC) | `libgrpc++`, `grpc_cpp_plugin`, Protobuf headers, `protoc`.|

## Build flavours

```bash
# CLI + gRPC daemon
cmake -S . -B build \
  -DOPENPENNY_WITH_XDP=ON \
  -DgRPC_DIR=/path/to/lib/cmake/gRPC \
  -DProtobuf_DIR=/path/to/lib/cmake/protobuf \
  -DGRPC_CPP_PLUGIN=/usr/bin/grpc_cpp_plugin

# DPDK
cmake -S . -B build -DOPENPENNY_WITH_DPDK=ON -DOPENPENNY_WITH_XDP=OFF
```

The eBPF program is built automatically; rebuild with
`cmake --build build --target xdp_bpf` if you only need the BPF artifact.

## Architecture (per queue)

```text
                           NIC RX queue
                                │
                                │  (one of:)
─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─  kernel
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
   ┌─────────┐             ┌─────────┐             ┌─────────┐
   │ AF_XDP  │             │AF_PACKET│             │  DPDK   │
   │redirect │             │  copy   │             │   PMD   │
   └────┬────┘             └────┬────┘             └────┬────┘
─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─  user
        └───────────────────────┼───────────────────────┘
                                ▼
    ┌───────────────────────────────────────────────────────┐
    │            PacketSource  →  PacketParser              │
    │           (one worker thread per RX queue)            │
    └──────────────────────────┬────────────────────────────┘
                               │
                   ┌───────────┴───────────┐
                   ▼                       ▼
            ┌────────────┐          ┌────────────┐
            │   Active   │          │  Passive   │
            │  pipeline  │          │  pipeline  │
            │ ────────── │          │ ────────── │
            │ drop a few │          │ observe    │
            │ packets;   │          │ gaps and   │
            │ watch for  │          │ coverage;  │
            │ retransmit │          │ no drops   │
            └──────┬─────┘          └─────┬──────┘
                   └───────────┬──────────┘
                               ▼
             ┌─────────────────────────────────────┐
             │   PacketSink  (egress.kind):        │
             │   none, tun, raw_socket, raw_nic    │
             └────────────────┬────────────────────┘
                              ▼
                  Summary  →  CLI / gRPC reply
```

One worker per RX queue. Each worker owns its packet source; egress is a
single `PacketSink` shared across all workers.

## Repository layout

Full map: [`docs/layout.md`](docs/layout.md). High level:

- `src/`, `include/` — core library, pipelines, CLI, gRPC daemon and worker.
- `src/ingress/` — AF_XDP/eBPF, AF_PACKET mirror, DPDK backends.
- `ebpf/af_xdp/` — eBPF runtime program.
- `proto/` — gRPC service definition.
- `examples/` — configs and sample gRPC clients.
- `tools/traffic_generator/`, `tools/af_xdp/` — test traffic and AF_XDP
  diagnostics.
- `docs/` — start at [`docs/README.md`](docs/README.md).

## References

- RIPE Labs overview and stealthy-hijack case study:
  <https://labs.ripe.net/author/petros_gigis/openpenny-developing-an-open-source-tool-for-detecting-non-spoofed-traffic/>
- SIGCOMM '24 paper: <https://dl.acm.org/doi/10.1145/3651890.3672259>
- NetUK-2 talk: <https://indico.netuk.org/event/2/contributions/37/>

## Project

- Repository: <https://github.com/pgigis/openpenny>
- License: [BSD-2-Clause](LICENSE).
- Security policy: [`docs/project/SECURITY.md`](docs/project/SECURITY.md).
- Third-party licenses:
  [`docs/project/DEPENDENCIES-LICENSES.md`](docs/project/DEPENDENCIES-LICENSES.md).

Primary author: **Petros Gigis** ([`pgigis`](https://github.com/pgigis)).
Contributors: <https://github.com/pgigis/openpenny/graphs/contributors>.

The Penny mechanism was developed by **Petros Gigis, Mark Handley, and
Stefano Vissicchio**. This project was supported by the
**RIPE NCC Community Projects Fund 2024**
([details](https://www.ripe.net/community/community-initiatives/cpf/previous-funding-recipients/funding-recipients-2024/)).

Provided "as is" without warranty; the authors and funders are not liable
for any damages arising from its use.
