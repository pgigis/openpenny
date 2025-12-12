
[![CI](https://github.com/pgigis/openpenny/actions/workflows/ci.yml/badge.svg)](https://github.com/pgigis/openpenny/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-BSD%202--Clause-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-green.svg)](CHANGELOG.md)

![OpenPenny logo](docs/images/openpenny_logo.png)

# OpenPenny

OpenPenny is an open-source tool that helps operators determine whether traffic entering their network is **genuinely non-spoofed** and arriving at the **right place**.

In practice, operators often notice that traffic from certain sources starts entering their network at unexpected locations. On its own, this is hard to interpret: it might indicate a real routing problem, or it might just be spoofed background noise. Simply alerting on every change in ingress point is not useful if much of that traffic is spoofed.

With OpenPenny, the operator can **redirect a small slice of this unexpected traffic** to a commodity x86 server. There, OpenPenny implements and extends the Penny test for real networks. The core idea is simple: when new traffic appears at an unexpected router, drop a small number of TCP packets and observe how the flow reacts. Non-spoofed senders retransmit, while spoofed sources do not.

By applying this test carefully and at scale, OpenPenny helps operators distinguish genuine, non-spoofed traffic aggregates from spoofed ones with minimal impact on legitimate flows. The resulting view can be used to build accurate ingress maps and generate routing alerts that focus on real, actionable events rather than background noise.

## Why OpenPenny?

ISPs, IXPs, and large networks typically rely on NetFlow/sFlow to monitor traffic ingress points. These tools show **where** traffic appears to enter the network, but **cannot verify whether the apparent source is genuine**. This makes it hard to:
c
- Confirm whether unexpected entry points reflect real routing changes or just spoofed noise.
- Detect stealthy hijacks or misconfigurations.
- Check whether traffic obeys peering and routing policies.

OpenPenny fills this gap with a **lightweight, TCP-based mechanism** that can be deployed alongside existing monitoring systems.

---

## How it works

OpenPenny extends the Penny technique (see the SIGCOMM ’24 paper:  
<https://dl.acm.org/doi/10.1145/3651890.3672259>) into two complementary modes:

- **Active mode**  
  Redirect a traffic slice and deliberately drop a small number of TCP packets.  
  - Genuine (non-spoofed) senders retransmit.  
  - Spoofed senders do not.  
  This confirms closed-loop, non-spoofed sources on redirected traffic slices.

- **Passive mode**  
  Mirror traffic without interfering with the flows.  
  - Observe sequence coverage, gaps, duplication, FIN/RST events, and idle periods.  
  - Highlight suspect paths and irregular behaviour before deciding whether to run active checks.

Typical deployment: redirect or mirror selected traffic at PoP/edge devices to an analysis box running OpenPenny (XDP or DPDK). Use the resulting ingress map to alert on unexpected entry points, policy violations, or stealthy hijacks.

![Traffic slicing and analysis](docs/images/slice-traffic-figure.png)


---

## Table of Contents

- [Highlights](#highlights)
- [Requirements](#requirements)
- [Build](#build)
- [Quick Start (CLI)](#quick-start-cli)
- [Quick Start (gRPC)](#quick-start-grpc)
- [Common Tasks](#common-tasks)
- [Deployment in ISP/IXP environments](#deployment-in-ispixp-environments)
- [Architecture (per queue)](#architecture-per-queue)
- [Repository Layout](#repository-layout)
- [Docs](#docs)
- [Dependencies & Licenses](#dependencies--licenses)
- [Articles and Papers](#articles-and-papers)
- [Contributing](#contributing)
- [Security](#security)
- [Disclaimer](#disclaimer)
- [Authors, Credits, and Contributors](#authors-credits-and-contributors)
- [Acknowledgements](#acknowledgements)

---

## Highlights

- **Two modes, one pipeline**
  - Active mode: injects controlled drops, tracks retransmissions/duplicates, aggregates across flows.
  - Passive mode: observes coverage and gaps without interference, with idle/goal-based stop conditions.

- **High-performance capture**
  - XDP/AF_XDP (default) or DPDK packet sources, selectable at runtime.
  - Per-queue pipelines designed for multi-Gbps rates on commodity x86 servers.

- **Flexible forwarding options**
  - Optional forwarding to TUN or raw sockets.
  - Drop snapshot export for debugging and analysis.

- **Operator-friendly interfaces**
  - CLI (`openpenny_cli`) for local testing and simple automation.
  - gRPC daemon (`pennyd` + `penny_worker`) for remote control and integration into existing tooling.

---

## Requirements

- **OS / privileges**
  - Linux with root or `CAP_NET_ADMIN`.
  - Kernel XDP support for AF_XDP runs.

- **Build toolchain**
  - CMake ≥ 3.16
  - C++17 compiler
  - `pkg-config`

- **Libraries**
  - `libbpf`, `libxdp`, `libelf`, `libpcap`, `openssl`

- **Optional**
  - `libdpdk` (+ hugepages + driver binding) for DPDK runs.
  - gRPC daemon:
    - `libgrpc++`, `grpc_cpp_plugin`, Protobuf headers and `protoc`.
  - Sample gRPC clients:
    - Python 3 with `grpcio` and `grpcio-tools`.

---

## Build

XDP-only CLI:

```bash
cmake -S . -B build -DOPENPENNY_WITH_XDP=ON -DOPENPENNY_WITH_DPDK=OFF
cmake --build build
```

CLI + gRPC:

```bash
cmake -S . -B build -DOPENPENNY_WITH_XDP=ON   -DgRPC_DIR=/path/to/lib/cmake/gRPC   -DProtobuf_DIR=/path/to/lib/cmake/protobuf   -DGRPC_CPP_PLUGIN=/usr/bin/grpc_cpp_plugin
cmake --build build
```

DPDK:

```bash
cmake -S . -B build -DOPENPENNY_WITH_DPDK=ON -DOPENPENNY_WITH_XDP=OFF
cmake --build build
```

XDP BPF helper:

```bash
cmake --build build --target xdp_bpf
# or:
make -C xdp-fw xdp_redirect_dstprefix.o
```

The CLI will attempt to build the XDP program automatically on first run.

---

## Quick Start (CLI)

**Active example (XDP + TUN):**

```bash
sudo ./build/openpenny_cli   --config examples/configs/config_default.yaml   --mode active   --prefix 192.168.41.0   --mask-bits 24   --iface <ifname>   --queue 0   --tun xdp-tu
```

**Passive example:**

```bash
sudo ./build/openpenny_cli   --config examples/configs/config_default.yaml   --mode passive   --prefix 192.168.41.0   --mask-bits 24   --iface <ifname>   --queue 0   --no-forward-to-tun
```

Use `--forward-raw-socket --forward-device <if>` to forward via a raw socket instead of TUN.

---

## Quick Start (gRPC)

Start the daemon:

```bash
./build/pennyd   --config examples/configs/config_default.yaml   --listen 0.0.0.0:50051   --worker-bin ./build/penny_worker
```

Invoke from Python (active example):

```bash
python3 examples/grpc_client.py   --addr localhost:50051   --prefix 192.168.41.0   --mask-bits 24
```

See `examples/grpc_active_example.py` and `examples/grpc_passive_example.py` for tailored payloads.

---

## Common Tasks

- **Build XDP BPF**

  ```bash
  cmake --build build --target xdp_bpf
  # or let the CLI auto-build on first run
  ```

- **Detach / clean XDP pins**

  ```bash
  sudo python3 scripts/xdp_attach.py --iface <if> --mode drv --detach
  sudo rm -rf /sys/fs/bpf/openpenny*
  ```

- **Verify XDP attachment**

  ```bash
  ip -details link show dev <if> | grep -i xdp
  bpftool map dump pinned /sys/fs/bpf/openpenny_<if>_<mask>/xsks
  ```

- **DPDK build**

  Configure with:

  ```bash
  -DOPENPENNY_WITH_DPDK=ON -DOPENPENNY_WITH_XDP=OFF
  ```

- **Traffic generator dependencies**

  ```bash
  pip install -r traffic_generator/requirements.txt
  ```

  The traffic generator uses Scapy to craft spoofed and non-spoofed flows for testing.

---

## Deployment in ISP/IXP environments

- Redirect or mirror selected ingress traffic slices (per prefix or interface) to an analysis box running OpenPenny (XDP or DPDK).
- **Active mode:** apply drop-based checks on redirected flows to confirm non-spoofed traffic.
- **Passive mode:** mirror-only visibility; flag gaps, duplicates, or abrupt terminations and decide when to trigger active checks.
- Use the resulting per-prefix ingress view to detect:
  - unexpected entry points,
  - misconfigurations or policy violations,
  - potential stealthy hijacks.

---

## Architecture (per queue)

```text
NIC/XDP/DPDK -> PacketSource -> PacketParser -> worker thread
                                         |
             +---------------------------+---------------------------+
             |                                                           |
   Active pipeline (FlowManager + FlowEngine)                   Passive pipeline
   - drop heuristics & snapshots via timers                     - PassiveFlowState coverage
   - DropCollector for cross-thread aggregates                  - FIN/RST/idle/grace stopping
             |                                                           |
             +---------------------------+---------------------------+
                                         |
                        Optional forwarding (TUN/raw socket)
                                         |
                          ModeResult & summary -> CLI / gRPC reply
```

- `OpenpennyPipelineDriver` spawns one worker per queue and selects XDP or DPDK via `net::create_packet_source`.
- Active mode binds drop sinks to a shared `DropCollector`, applies duplicate/out-of-order limits, and can stop on aggregate decisions.
- Passive mode records gaps and coverage without interference and stops on FIN/RST, idle expiry, or configured flow targets.

---

## Repository Layout

Key locations (full map in `docs/layout.md`):

- `src/`, `include/`  
  Core library, active/passive pipelines, CLI, gRPC daemon, worker, and packet sources (XDP/DPDK).

- `proto/`  
  gRPC service definition (`penny.proto`) used by server and client stubs.

- `examples/`  
  Example configs under `examples/configs/` and sample gRPC clients under `examples/`.

- `docs/`  
  Split into run/ops/dev guides; start at `docs/docs-index.md` or `docs/README.md`.

- `traffic_generator/`  
  TCP generators and Scapy spoofed sender for test traffic.

- `xdp-fw/`  
  XDP program sources; build with `cmake --build build --target xdp_bpf` (the CLI can auto-build).

- `scripts/`  
  Helper installers for common distros and utility scripts.

- `traffic_generator/requirements.txt`  
  Python dependencies for the traffic generator scripts (Scapy).

---

## Docs

See [`docs/docs-index.md`](docs/docs-index.md) for an indexed list of:

- run/operations guides,  
- developer documentation,  
- traffic generation notes and examples.

---

## Dependencies & Licenses

See [`DEPENDENCIES-LICENSES.md`](DEPENDENCIES-LICENSES.md) for third-party components and their licenses.

---

## Articles and Papers

- **RIPE Labs** – OpenPenny overview and stealthy hijack case study:  
  <https://labs.ripe.net/author/petros_gigis/openpenny-developing-an-open-source-tool-for-detecting-non-spoofed-traffic/>

- **SIGCOMM ’24** (Penny algorithm paper):  
  <https://dl.acm.org/doi/10.1145/3651890.3672259>

- **NetUK-2 talk**:  
  <https://indico.netuk.org/event/2/contributions/37/>

---

## Contributing

- Use GitHub Issues for bug reports and feature requests.
- For pull requests:
  - See `.github/pull_request_template.md`.
  - Keep changes focused and include build/test notes.
- Use `clang-format` for C++ where applicable.
- Keep documentation in Markdown.

Repository: <https://github.com/pgigis/openpenny>

---

## Security

See [`SECURITY.md`](SECURITY.md) for reporting guidelines and expected response timelines.

---

## Disclaimer

This project is provided “as is”, without warranties of any kind. Use at your own risk; the authors, contributors, and funding sources are not liable for any damages arising from its use.

---

## Authors, Credits, and Contributors

- Primary author/maintainer: **Petros Gigis** (`pgigis`) – <https://github.com/pgigis>  
- Full contributor list: <https://github.com/pgigis/openpenny/graphs/contributors>

This section acknowledges contributors and does not imply legal ownership; see the [license file](LICENSE) for details.

---

## Acknowledgements

- This work was supported by the **RIPE NCC Community Projects Fund 2024**.  
  More details:  
  <https://www.ripe.net/community/community-initiatives/cpf/previous-funding-recipients/funding-recipients-2024/>

- The initial Penny algorithm was developed by **Petros Gigis, Mark Handley, and Stefano Vissicchio**, as described in the SIGCOMM ’24 paper:  
  <https://dl.acm.org/doi/10.1145/3651890.3672259>

We thank Stefano Vissicchio and Mark Handley for their early contributions, feedback, and support.
