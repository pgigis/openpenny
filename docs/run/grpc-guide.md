# gRPC Guide

OpenPenny ships a gRPC server (`pennyd`) and a worker process
(`penny_worker`) that runs the actual pipeline. Use the gRPC API when you
need to drive OpenPenny from another service or from a script.

The full service is defined in [`proto/penny.proto`](../../proto/penny.proto).

## Before you start

Build with gRPC enabled (default if gRPC is installed). After building, you
should have:

- `./build/pennyd` — the server.
- `./build/penny_worker` — the worker the server runs.
- Sample clients in `examples/`:
  - `examples/grpc_active_example.py`
  - `examples/grpc_passive_example.py`

If `pennyd` is missing after a build, point CMake at your gRPC install:

```bash
cmake -S . -B build \
  -DgRPC_DIR=/usr/lib64/cmake/grpc \
  -DProtobuf_DIR=/usr/lib64/cmake/protobuf \
  -DGRPC_CPP_PLUGIN=/usr/bin/grpc_cpp_plugin
cmake --build build --target pennyd penny_worker
```

## Start the server

```bash
./build/pennyd \
  --config examples/configs/config_default.yaml \
  --listen 0.0.0.0:50051 \
  --worker-bin ./build/penny_worker
```

| Flag            | Purpose                                                  |
| --------------- | -------------------------------------------------------- |
| `--config`      | YAML config used as the base for all requests.           |
| `--listen`      | Address and port to serve on.                            |
| `--worker-bin`  | Path to `penny_worker` (the server runs it per request). |

## Main RPCs

Use these for normal operation:

- `SetTrafficPolicy` — pick which traffic to include or exclude (5-tuple rules).
- `SetRuntimePolicy` — switch active/passive, set thresholds and safety flags.
- `SetMode` — toggle active/passive without changing other policy.
- `ApplyConfig` — set both policies in one call.
- `GetDesiredConfig` — read back the policy you set.
- `GetEffectiveConfig` — read the config the daemon actually uses.
- `GetRuntimeStatus` — current daemon status.
- `StartTest` — run one test and wait for the result.

## Examples

### Set a traffic policy

```bash
grpcurl -plaintext \
  -import-path proto -proto penny.proto \
  -d '{
    "traffic_policy": {
      "default_decision": "TRAFFIC_DECISION_EXCLUDE",
      "rules": [{
        "name": "https",
        "priority": 10,
        "enabled": true,
        "dst_prefix": "203.0.113.0/24",
        "protocol": "tcp",
        "dst_port": 443,
        "decision": "TRAFFIC_DECISION_INCLUDE"
      }]
    }
  }' \
  localhost:50051 openpenny.api.PennyService/SetTrafficPolicy
```

### Set a runtime policy (active mode)

```bash
grpcurl -plaintext \
  -import-path proto -proto penny.proto \
  -d '{
    "runtime_policy": {
      "mode": "RUNTIME_MODE_ACTIVE",
      "safety": { "allow_ssh_bypass": true },
      "thresholds": {
        "packet_drop_probability": 0.05,
        "max_duplicate_ratio": 0.15,
        "max_reordering_ratio": 0.8,
        "retransmission_timeout_multiplier": 3.0,
        "max_packet_drops_per_flow": 6,
        "max_packet_drops_global_aggregate": 12
      }
    }
  }' \
  localhost:50051 openpenny.api.PennyService/SetRuntimePolicy
```

### Run an active test

```bash
grpcurl -plaintext \
  -import-path proto -proto penny.proto \
  -d '{
    "prefix": "192.168.41.1",
    "mask_bits": 32,
    "mode": "active",
    "test_id": "demo-active"
  }' \
  localhost:50051 openpenny.api.PennyService/StartTest
```

### Run a passive test

```bash
grpcurl -plaintext \
  -import-path proto -proto penny.proto \
  -d '{
    "prefix": "192.168.41.1",
    "mask_bits": 32,
    "mode": "passive",
    "test_id": "demo-passive"
  }' \
  localhost:50051 openpenny.api.PennyService/StartTest
```

`StartTest` blocks until the run finishes or fails.

## Inline overrides

`StartTestRequest.config_override_json` lets you tweak config for one run
without changing the daemon's base YAML:

```json
{
  "platform": {
    "backend": "af_xdp",
    "ingress_mode": "auto",
    "interface": "ens5f0np0",
    "queue": 0,
    "queue_count": 1
  },
  "egress": {
    "kind": "tun",
    "device": "xdp-tun",
    "tun": { "multi_queue": true, "mtu": 9000, "rp_filter_loose": true }
  }
}
```

Valid values:

- `platform.backend`: `af_xdp`, `af_packet_mirror`, `dpdk`.
- `platform.ingress_mode`: `auto` (default), `copy`, `redirect`.
- `egress.kind`: `none`, `tun`, `raw_socket`, `raw_nic`.

`auto` picks `copy` for passive runs and `redirect` for active runs.

## What the response looks like

`StartTest` returns:

- A status string and the `test_id` you passed in.
- Packet counters: processed, forwarded, errors, duplicate, in-order,
  out-of-order, retransmitted, etc.
- Flow counters: tracked SYN flows, tracked data flows.
- Completion flags: `penny_completed`, `aggregates_completed`,
  `aggregates_enabled`.
- For active mode: aggregate evaluation fields (`aggregates_status`,
  `aggregates_decision_complete`, `aggregate_flows_*`, etc.).
- `json_summary`: the same detail in a JSON string, ready to log or store.

For the full override schema, see
[`docs/dev/grpc-override-format.md`](../dev/grpc-override-format.md).
