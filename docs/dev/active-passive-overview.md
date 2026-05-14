# Active vs Passive Overview

Per queue, the worker thread follows the same structure; only the
mode-specific engine differs.

```
NIC ─► {AF_XDP redirect | AF_PACKET copy | DPDK} ─► PacketSource ─► PacketParser
                                                                        │
                  ┌─────────────────────────────────┬───────────────────┘
                  ▼                                 ▼
        ┌──────────────────┐               ┌──────────────────┐
        │ Active pipeline  │               │ Passive pipeline │
        │ FlowManager /    │               │ PassiveFlowState │
        │   FlowEngine     │               │ - gap coverage   │
        │ - drop heuristic │               │ - FIN/RST/idle   │
        │ - snapshot timer │               │   end conditions │
        └────────┬─────────┘               └────────┬─────────┘
                 └───────────────┬──────────────────┘
                                 ▼
                  egress::PacketSink  (cfg.egress.kind)
                                 │
                                 ▼
                    Per-thread stats ─► aggregate summary
```

`OpenpennyPipelineDriver::drive_pipeline` spawns one worker per queue.
The ingress backend is chosen from `cfg.input.backend` after `cfg.input.mode`
is resolved: `auto` picks `copy` for passive and `redirect` for active.
`net::PacketParser` normalises packets into `PacketView` structs.
Egress is a single `PacketSink` built from `cfg.egress` and shared by
all workers.

## Copy vs redirect

- **copy** — tap the interface via `AF_PACKET/SOCK_RAW`. The kernel keeps
  delivering each packet to the final app, so OpenPenny observes without
  perturbing the traffic. Default for passive mode; no XDP program loaded.
- **redirect** — the XDP program pulls matched packets out of the kernel
  into AF_XDP. Required for active mode so packets can be dropped (or
  reinjected through `cfg.egress`).

## Active mode

- Injects controlled drops to elicit retransmissions (the Penny heuristic).
- Key thresholds (`runtime_policy.thresholds`):
  - `packet_drop_probability`, `max_duplicate_ratio`, `max_reordering_ratio`.
  - `retransmission_timeout_in_seconds`, `admission_grace_period_seconds`,
    `monitored_flow_idle_expiry_seconds`.
  - `max_packet_drops_per_flow`, `max_packet_drops_global_aggregate`,
    `stop_after_individual_flows`.
- Flow lifecycle:
  - `ThreadFlowManager` admits flows, binds drop sinks, hands packets
    to `FlowEngine`.
  - `FlowEngine` drops data packets according to probability and capacity
    limits, snapshots each drop, tracks gaps, and reaches a per-flow
    decision (`FINISHED_CLOSED_LOOP`, `FINISHED_NOT_CLOSED_LOOP`,
    `FINISHED_DUPLICATE_EXCEEDED`).
  - With `aggregates.enabled: true`, an aggregate verdict can short-circuit
    the run once enough drops have outcomes.

Egress is `tun` by default; switch to `raw_socket` (routed L3 — kernel
picks the next hop) or `raw_nic` (L2 replay — original frame, no route /
ARP resolution) when those semantics fit the deployment.

## Passive mode

- Observes flows; never drops.
- Key thresholds (`runtime_policy.thresholds`):
  - `passive_min_flows_to_finish`, `passive_max_execution_time_seconds`,
    `passive_max_parallel_flows`.
  - `monitored_flow_idle_expiry_seconds` for idle eviction.
- Flow lifecycle:
  - `PassiveFlowState` tracks seq coverage, duplicates, and open gaps
    without injecting loss.
  - Ends on FIN/RST, idle expiry, or the configured minimum flow count
    plus a short grace window.
  - Finished flows are archived; per-flow stats appear in the summary.
- Ingress defaults to `ingress_mode: auto` → `copy`. Override with
  `ingress_mode: redirect` to force AF_XDP in passive mode; the captured
  stream must then be reinjected through a TUN egress to reach the
  application.
- Egress is typically `none` in copy mode (the kernel has already
  delivered the packet). Enable `tun` / `raw_socket` / `raw_nic` only if
  the captured stream should be mirrored elsewhere.

## CLI vs gRPC

- CLI: `openpenny_cli --mode active|passive ...` uses on-disk config,
  optionally overridden by flags.
- gRPC: `SetTrafficPolicy`, `SetRuntimePolicy`, and `SetMode` drive the
  daemon. `StartTestRequest.config_override_json` is available for
  per-run overrides.

## See also

- [`docs/run/cli-guide.md`](../run/cli-guide.md) — CLI usage.
- [`docs/run/grpc-guide.md`](../run/grpc-guide.md) — gRPC usage.
- [`docs/run/tuning-reference.md`](../run/tuning-reference.md) — full
  threshold list.
- [`drop-snapshot-flow.md`](drop-snapshot-flow.md) — how drop snapshots
  move across workers in active mode.
