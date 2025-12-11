# Repository Layout

- `src/`, `include/`: core library, pipelines, packet sources, CLI (`openpenny_cli`), gRPC daemon (`pennyd`), and worker (`penny_worker`).
- `proto/`: `penny.proto` for gRPC interfaces and client stubs.
- `examples/`:
  - `configs/`: example YAML configs and schema.
  - `grpc_*.py`: sample gRPC clients (active/passive).
- `docs/`: split into `run/`, `ops/`, `dev/`; see `docs/README.md` for a hub.
- `traffic_generator/`: simple TCP generators and a Scapy-based spoofed sender.
- `xdp-fw/`: lab XDP program; build with `cmake --build build --target xdp_bpf` or `make -C xdp-fw xdp_redirect_dstprefix.o`.
- `scripts/`: distro-specific dependency installers.
