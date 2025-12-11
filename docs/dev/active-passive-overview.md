# Active vs Passive Overview

## Pipeline at a glance
Per queue, the worker thread follows the same structure; only the mode-specific engine differs.

```
NIC/XDP/DPDK -> PacketSource -> PacketParser -> per-queue worker
                                           |
                 +-------------------------+-------------------------+
                 |                                                   |
      +--------------------+                             +--------------------+
      | Active pipeline    |                             | Passive pipeline   |
      | FlowManager/Engine |                             | PassiveFlowState   |
      | - drop heuristics  |                             | - gap coverage     |
      | - snapshot timers  |                             | - FIN/RST/idle end |
      +--------------------+                             +--------------------+
                 |                                                   |
                 +-------------------------+-------------------------+
                                           |
                             Optional forwarding (TUN/raw)
                                           |
                            Per-thread stats → aggregate summary
```

- `OpenpennyPipelineDriver::drive_pipeline` spawns one worker per queue and chooses XDP or DPDK via `net::create_packet_source`.
- `net::PacketParser` normalises packets into `PacketView` structs for both modes.
- Optional forwarding is handled in the worker (TUN or raw socket) before emitting the summary counters returned to the CLI/gRPC layer.

## Active mode
- Injects controlled drops to elicit retransmissions (Penny heuristic).
- Key config (`monitoring.active`):
  - `drop_policy`: `packet_drop_probability`, `max_duplicate_ratio`, `max_reordering_ratio`.
  - `timeouts`: `retransmission_timeout_seconds`, `admission_grace_period_seconds`, `monitored_flow_idle_expiry_seconds`.
  - `execution`: `max_packet_drops_per_flow`, `max_packet_drops_global_aggregate`, `stop_after_individual_flows`.
- Flow lifecycle:
  - `ThreadFlowManager` admits flows, binds drop sinks, and hands packets to `FlowEngine`.
  - Drops data packets according to probability and capacity limits; snapshots are collected for retransmit/duplicate decisions.
  - Tracks gaps, retransmissions, duplicates/out-of-order; `FlowEngine` timers mark gaps expired/filled.
  - Aggregated counters can short-circuit decisions once enough drops have outcomes.
- Forwarding:
  - Default TUN forwarding (can be disabled or replaced with raw-socket forwarding).

## Passive mode
- Observes flows without inducing drops.
- Key config (`monitoring.passive`):
  - `min_number_of_flows_to_finish`, `max_execution_time`, `max_parallel_flows`.
  - `timeouts.monitored_flow_idle_expiry_seconds` for idle eviction.
- Flow lifecycle:
  - `PassiveFlowState` tracks seq coverage, duplicates, and open gaps without injecting loss.
  - Ends on FIN/RST, idle expiry, or when `min_number_of_flows_to_finish` is reached plus a short grace window.
  - Finished flows are archived; per-flow stats are logged in summaries.
- Forwarding:
  - Typically disabled; can be enabled with TUN or raw-socket options if desired.

## CLI vs gRPC
- CLI: `openpenny_cli --mode active|passive ...` uses on-disk config, optionally overridden by flags.
- gRPC: `StartTest` can pass `config_override_json` to replace the monitoring block per request; response includes counters and `json_summary`.

## Quick pointers
- Config example: `examples/configs/config_default.yaml` (enable/disable XDP or DPDK in `input_sources`).
- Docs:
  - `docs/run/cli-guide.md` – CLI usage
  - `docs/run/grpc-guide.md` – gRPC usage
  - `docs/run/grpc-client-example.md` – client + payload examples
