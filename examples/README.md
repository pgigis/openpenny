# OpenPenny Examples

This guide shows how to run OpenPenny using the bundled example config, both via the CLI and the gRPC server. The example config is organised around traffic policy, Penny runtime policy, and platform config.

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

## Passive Mode
A second root config, `examples/configs/config_passive.yaml`, is provided for passive observation. It pulls in:
  - `policies/runtime_passive.yaml` — passive mode, ratio thresholds, and stop conditions (`passive_min_flows_to_finish`, `passive_max_execution_time_seconds`).
  - `platform/af_packet_mirror.yaml` — copy-mode ingress; the kernel still delivers packets to the final app.
  - `platform/egress_none.yaml` — no TUN, no reinjection.

Run with:
```bash
sudo ./build/openpenny_cli \
  --config examples/configs/config_passive.yaml \
  --iface ens5f0np0
```

## Configuration Notes
- The full schema is in `examples/configs/config_schema.json`.
- `config_default.yaml` is a small root config that includes subfiles from:
  - `examples/configs/policies/traffic_default.yaml` for include/exclude 5-tuple traffic selection.
  - `examples/configs/policies/runtime_active.yaml` for active/passive mode, thresholds, timers, budgets, and safety controls.
  - `examples/configs/platform/af_xdp.yaml` for deployment/admin dataplane settings such as AF_XDP/DPDK backend, interface, and queue topology.
  - `examples/configs/platform/egress_tun.yaml` for TUN forwarding (replaces the deprecated `forwarding_*.yaml` files).
  - `examples/configs/platform/grpc.yaml` for daemon listener settings.
- Normal operator changes should usually stay in `traffic_policy` and `runtime_policy`.
- Include paths are resolved relative to the root config file.
- More intent-first examples are in `docs/run/configuration-examples.md`.
