# OpenPenny Examples

This guide shows how to run OpenPenny using the bundled example config, both via the CLI and the gRPC server.

## Prerequisites
- Build the project (XDP-enabled build shown):
  ```bash
  cmake -S . -B build -DOPENPENNY_WITH_XDP=ON
  cmake --build build
  ```
- Ensure the example config exists: `examples/configs/config_default.yaml`.

## CLI Usage
Run the CLI directly with the example config, XDP mode, and a TUN forward target:
```bash
sudo ./build/openpenny_cli \
  --config examples/configs/config_default.yaml \
  --mode active \
  --prefix 192.168.41.0/24 \
  --iface ens5f0np0 \
  --xdp-mode drv \
  --queue 0 \
  --tun xdp-tun
```
- `--prefix` accepts CIDR (e.g., `192.168.41.0/24`).
- `--mode` can be `active` or `passive`.
- `--tun` forwards matched packets to the named TUN device.

## gRPC Server (`pennyd`)
Start the gRPC daemon with the example config and a listen address:
```bash
sudo ./build/pennyd \
  --config examples/configs/config_default.yaml \
  --listen 0.0.0.0:50051
```

### Invoke via `penny_worker` (spawned by the service)
The gRPC service uses `penny_worker` under the hood. You can run it directly to mimic RPC calls:
```bash
sudo ./build/penny_worker \
  --config examples/configs/config_default.yaml \
  --prefix 192.168.41.0 \
  --mask-bits 24 \
  --mode active \
  --forward-to-tun \
  --tun-name xdp-tun
```

### Example gRPC Request
Use a gRPC client (e.g., `grpcurl`) to start a test:
```bash
grpcurl -plaintext -d '{
  "prefix": "192.168.41.0",
  "mask_bits": 24,
  "mode": "active",
  "forward_to_tun": true,
  "tun_name": "xdp-tun"
}' localhost:50051 openpenny.api.PennyService/StartTest
```
This blocks until the test completes and returns counters from `ModeResult`.

## Configuration Notes
- The full schema is in `examples/configs/config_schema.json`.
- `config_default.yaml` contains:
  - `input_sources.xdp` and `input_sources.dpdk` for ingress selection.
  - `traffic_forwarding` for TUN/raw socket targets.
  - `monitoring.active/passive` for Penny heuristics.
- gRPC defaults rely on this file; tune `input_sources` and `monitoring` as needed before running `pennyd`.
