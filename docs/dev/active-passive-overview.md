# Active vs Passive Overview

## Pipeline at a glance
Per queue, the worker thread follows the same structure; only the mode-specific engine differs.

```
NIC -> {AF_XDP redirect | AF_PACKET copy | DPDK} -> PacketSource -> PacketParser
                                                                        |
                                 +--------------------------------------+--------------------------------------+
                                 |                                                                             |
                      +--------------------+                                                       +--------------------+
                      | Active pipeline    |                                                       | Passive pipeline   |
                      | FlowManager/Engine |                                                       | PassiveFlowState   |
                      | - drop heuristics  |                                                       | - gap coverage     |
                      | - snapshot timers  |                                                       | - FIN/RST/idle end |
                      +--------------------+                                                       +--------------------+
                                 |                                                                             |
                                 +--------------------------------------+--------------------------------------+
                                                                        |
                                                        egress::PacketSink (kind from cfg.egress)
                                                                        |
                                                      Per-thread stats → aggregate summary
```

- `OpenpennyPipelineDriver::drive_pipeline` spawns one worker per queue. The ingress backend is chosen from `cfg.input.backend` (`af_xdp`, `af_packet_mirror`, `dpdk`) after `cfg.input.mode` is resolved: `auto` picks `copy` (AF_PACKET mirror) for passive and `redirect` (AF_XDP) for active.
- Copy vs redirect:
  - `copy` taps the interface via `AF_PACKET/SOCK_RAW`; the kernel keeps delivering packets up the stack to the final app, so we observe without perturbing the traffic. This is the default for passive mode and avoids the fragile reinject round-trip entirely.
  - `redirect` pulls matched packets out of the kernel via the XDP program into an AF_XDP socket; required for active mode so packets can be dropped (or optionally reinjected through `cfg.egress`).
- `net::PacketParser` normalises packets into `PacketView` structs for both modes.
- Egress is a single `PacketSink` built from `cfg.egress` (kinds: `none`, `tun`, `raw_socket`, `raw_nic`) and shared by all workers. The old `forward_to_tun` / `forward_raw_socket` flags are gone; see `docs/run/configuration-examples.md` for the YAML shape.

## Active mode
- Injects controlled drops to elicit retransmissions (Penny heuristic).
- Key config (`runtime_policy.thresholds`):
  - `packet_drop_probability`, `max_duplicate_ratio`, `max_reordering_ratio`.
  - `retransmission_timeout_in_seconds`, `admission_grace_period_seconds`, `monitored_flow_idle_expiry_seconds`.
  - `max_packet_drops_per_flow`, `max_packet_drops_global_aggregate`, `stop_after_individual_flows`.
- Flow lifecycle:
  - `ThreadFlowManager` admits flows, binds drop sinks, and hands packets to `FlowEngine`.
  - Drops data packets according to probability and capacity limits; snapshots are collected for retransmit/duplicate decisions.
  - Tracks gaps, retransmissions, duplicates/out-of-order; `FlowEngine` timers mark gaps expired/filled.
  - Aggregated counters can short-circuit decisions once enough drops have outcomes.
- Egress:
  - `cfg.egress.kind = tun` by default in examples; switch to `raw_socket` / `raw_nic` / `none` as needed.
  - `raw_socket` is the routed L3 path: the kernel picks the next hop and rewrites the Ethernet header.
  - `raw_nic` is the L2 replay path: it sends the original Ethernet frame unchanged and is only correct when that captured L2 header is still valid on the target segment.

## Passive mode
- Observes flows without inducing drops.
- Key config (`runtime_policy.thresholds`):
  - `passive_min_flows_to_finish`, `passive_max_execution_time_seconds`, `passive_max_parallel_flows`.
  - `monitored_flow_idle_expiry_seconds` for idle eviction.
- Flow lifecycle:
  - `PassiveFlowState` tracks seq coverage, duplicates, and open gaps without injecting loss.
  - Ends on FIN/RST, idle expiry, or when `min_number_of_flows_to_finish` is reached plus a short grace window.
  - Finished flows are archived; per-flow stats are logged in summaries.
- Ingress:
  - Default is `ingress_mode: auto`, which resolves to `copy` for passive. Packets are tapped via `AF_PACKET/SOCK_RAW` and continue to flow up the kernel stack to the real application, so OpenPenny is a non-perturbing observer. No XDP program is loaded, no reinject round-trip is required.
  - Override with `ingress_mode: redirect` to force AF_XDP in passive mode (e.g. to measure the fast path); the captured stream must then be reinjected through a TUN egress to reach the application.
- Egress:
  - Typically `cfg.egress.kind = none` in copy mode (the kernel has already delivered the packet). Enable `tun` / `raw_socket` / `raw_nic` only if the captured stream should be mirrored elsewhere or if `ingress_mode: redirect` is in use.
  - For redirected traffic that must still reach a local app or a routed downstream host, prefer `tun` or `raw_socket`; `raw_nic` does not perform route / ARP resolution.

## CLI vs gRPC
- CLI: `openpenny_cli --mode active|passive ...` uses on-disk config, optionally overridden by flags.
- gRPC: use `SetTrafficPolicy`, `SetRuntimePolicy`, and `SetMode` to drive the daemon. `StartTest.config_override_json` is available for inline overrides.

## Quick pointers
- Config example: `examples/configs/config_default.yaml` includes traffic policy, runtime policy, and platform subfiles.
- Docs:
  - `docs/run/cli-guide.md` – CLI usage
  - `docs/run/grpc-guide.md` – gRPC usage
  - `docs/run/grpc-client-example.md` – client + payload examples
