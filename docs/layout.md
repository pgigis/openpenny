# Repository Layout

- `src/`, `include/`: core library, pipelines, packet abstractions, CLI (`openpenny_cli`), gRPC daemon (`pennyd`), and worker (`penny_worker`).
- `src/ingress/`, `include/openpenny/ingress/`: backend-specific ingress implementations (`af_xdp` redirect, `af_packet` passive mirror, `dpdk`).
- `proto/`: `penny.proto` for gRPC interfaces and client stubs.
- `examples/`:
  - `configs/`: example YAML configs and schema.
  - `grpc_*.py`: sample gRPC clients (active/passive).
- `docs/`: split into `run/`, `ops/`, `dev/`; see `docs/README.md` for a hub.
  - `project/`: changelog, contributing, security, dependency-license, and code-of-conduct docs.
- `tools/traffic_generator/`: simple TCP generators and a Scapy-based spoofed sender.
- `ebpf/af_xdp/`: OpenPenny AF_XDP eBPF runtime program; build with `cmake --build build --target xdp_bpf` or `make -C ebpf/af_xdp xdp_redirect_openpenny.o`.
- `tools/af_xdp/`: standalone AF_XDP diagnostic helper and manual cleanup scripts.
- `scripts/`: distro-specific dependency installers.
