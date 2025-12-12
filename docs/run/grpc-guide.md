# gRPC Usage Guide

Penny exposes a blocking `StartTest` RPC (defined in `proto/penny.proto`).  
The gRPC daemon (`pennyd`) launches `penny_worker` to run a full test pipeline and returns a structured summary once the run completes.

This guide describes how to start the daemon, how to trigger active or passive tests, and how to apply per-request configuration overrides.

## Prerequisites

- Build the project with gRPC enabled (default in CMake).
- Binaries produced after building from the repository root:
  - **Server:** `./build/pennyd`
  - **Worker:** `./build/penny_worker`
  - **Sample clients:**  
    - `examples/grpc_active_example.py`  
    - `examples/grpc_passive_example.py`
- Protocol definition file: `proto/penny.proto`  
  Use it to generate client stubs in any supported language.

## Starting the gRPC Server

```bash
./build/pennyd     --config examples/configs/config_default.yaml     --listen 0.0.0.0:50051     --worker-bin ./build/penny_worker
```

**Build note:** if `pennyd` is missing, reconfigure with explicit gRPC paths, e.g.:
```bash
cmake -S . -B build \
  -DgRPC_DIR=/usr/lib64/cmake/grpc \
  -DProtobuf_DIR=/usr/lib64/cmake/protobuf \
  -DGRPC_CPP_PLUGIN=/usr/bin/grpc_cpp_plugin
cmake --build build --target pennyd penny_worker
```

### Flags

- **`--config`**  
  Path to the base YAML configuration; used unless the request provides overrides.

- **`--listen`**  
  Address on which the gRPC service should listen.

- **`--worker-bin`**  
  Path to the `penny_worker` binary that executes test pipelines.

## Request Fields (`StartTestRequest`)

- `prefix` / `mask_bits` — optional flow filter  
- `mode` — `"active"` (default) or `"passive"`  
- `test_id` — identifier attached to the run  
- Forwarding controls:  
  - `forward_to_tun`  
  - `tun_name`  
  - `forward_raw_socket`  
  - `forward_device`  
- `config_override_json` — inline JSON that **replaces** the worker configuration for this request

### Overriding interface and queue settings

If needed, override NIC or TUN settings directly in the JSON:

```json
{
  "ifname": "ens5f0np0",
  "queue": 0,
  "queue_count": 4,
  "tun_multi_queue": true,
  "forward_to_tun": true,
  "monitoring": {}
}
```

## Passive Mode Example (grpcurl, with proto)

```bash
PROTO_DIR=$(pwd)/proto  # adjust if your working dir differs
grpcurl -plaintext \
  -import-path "$PROTO_DIR" \
  -proto penny.proto \
  -d '{
    "prefix": "192.168.41.1",
    "mask_bits": 32,
    "mode": "passive",
    "test_id": "demo-passive",
    "config_override_json": "{\"monitoring\":{\"active\":{\"enabled\":false},\"passive\":{\"enabled\":true,\"min_number_of_flows_to_finish\":10,\"max_parallel_flows\":10,\"max_execution_time\":150,\"timeouts\":{\"admission_grace_period_seconds\":3.0,\"monitored_flow_idle_expiry_seconds\":15.0}}}}"
  }' \
  localhost:50051 openpenny.api.PennyService/StartTest
```

## Active Mode Example (grpcurl, with proto)

```bash
PROTO_DIR=$(pwd)/proto  # adjust if your working dir differs
grpcurl -plaintext \
  -import-path "$PROTO_DIR" \
  -proto penny.proto \
  -d '{
    "prefix": "192.168.41.1",
    "mask_bits": 32,
    "mode": "active",
    "test_id": "demo-active",
    "config_override_json": "{\"monitoring\":{\"active\":{\"enabled\":true,\"aggregates\":{\"enabled\":true,\"max_packet_drops_global_aggregate\":12,\"fallback_to_individual\":true},\"drop_policy\":{\"packet_drop_probability\":0.05,\"max_duplicate_ratio\":0.15,\"max_reordering_ratio\":0.8},\"timeouts\":{\"retransmission_timeout_seconds\":3.0,\"admission_grace_period_seconds\":3.0,\"monitored_flow_idle_expiry_seconds\":30.0},\"execution\":{\"max_packet_drops_per_flow\":6,\"max_number_of_individual_flows\":10,\"stop_after_individual_flows\":10}},\"passive\":{\"enabled\":false}}}"
  }' \
  localhost:50051 openpenny.api.PennyService/StartTest
```

## Response Shape

- status, `test_id`
- packet counters (processed, forwarded, duplicate, in-order/out-of-order, retransmitted, etc.)
- flow counters (tracked SYN/data flows)
- completion flags:
  - `penny_completed`
  - `aggregates_completed`
  - `aggregates_enabled`
- aggregate evaluation (active mode):
  - `aggregates_status`, `aggregates_decision_complete`, `aggregates_has_eval`, `aggregates_snapshots`
  - `aggregates_eval_*` counters (data/duplicate/retransmitted/non_retransmitted)
  - `aggregate_flows_*` snapshot counters (monitored/finished/closed_loop/not_closed_loop/rst/duplicates_exceeded)
- `json_summary`: JSON string with CLI-like detail:
  - `packets`: processed/forwarded/errors/pure_ack/data/duplicate/in_order/out_of_order/retransmitted/non_retransmitted
  - `flows`: tracked_syn / tracked_data
  - `penny_completed`, `aggregates_completed`, `aggregates_enabled`
  - `aggregates_status`, `aggregates_decision_complete`, `aggregates_decision_state`
  - `aggregates_eval` (object) and `aggregate_flows` (object)
  - `passive` (when applicable): finished/open_gaps_flows/open_gaps/rst/syn_only/details[]

## Notes

- `config_override_json` **fully replaces** the worker configuration for that call.
- The RPC call is **blocking** until the pipeline completes or errors.
- TUN forwarding is enabled by default; disable with `"forward_to_tun": false`.
