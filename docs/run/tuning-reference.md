# Tuning Reference

All threshold knobs accepted under `runtime_policy.thresholds`. The
example files (`examples/configs/policies/runtime_*.yaml`) carry only
the handful you typically touch; everything else uses the defaults
below.

## Active mode

| Knob                                       | Default | What it does                                                                          |
| ------------------------------------------ | ------- | ------------------------------------------------------------------------------------- |
| `packet_drop_probability`                  | 0.05    | Probability of dropping any given data packet.                                        |
| `max_duplicate_ratio`                      | 0.15    | If duplicates / total exceeds this, stop dropping in the flow.                        |
| `max_reordering_ratio`                     | 0.80    | If out-of-order / total exceeds this, stop dropping in the flow.                      |
| `retransmission_observation_miss_rate`     | 0.05    | Below this fraction of expected retransmits seen, treat as "none observed".           |
| `retransmission_timeout_in_seconds`        | 3.0     | Wait this long before declaring a retransmit missed.                                  |
| `admission_grace_period_seconds`           | 3.0     | After admitting a flow, wait this long before starting drops.                         |
| `monitored_flow_idle_expiry_seconds`       | 30.0    | Drop a tracked flow that has been silent this long.                                   |
| `drop_state_seconds`                       | 0.0     | Retention window for per-drop state. 0 = use default.                                 |
| `min_packet_drops_per_flow`                | 0       | Lower bound on drops before a flow is eligible to finish.                             |
| `max_packet_drops_per_flow`                | 6       | Upper bound on drops within a single flow.                                            |
| `max_packet_drops_global_aggregate`        | 12      | Total drops across all flows that must complete before the aggregate verdict fires.   |
| `max_monitored_flows`                      | 0       | Cap on simultaneously tracked flows. 0 = unlimited.                                   |
| `stop_after_individual_flows`              | 0       | Stop once this many flows have terminated. 0 = no early stop.                         |
| `min_closed_loop_flows`                    | 0       | If the aggregate falls back, wait for this many `FINISHED_CLOSED_LOOP` flows.         |

`aggregates: { enabled: true }` (sibling block) enables aggregate-level
evaluation. With it off, only per-flow heuristics fire.

`safety: { allow_ssh_bypass: true }` keeps TCP/22 untouched regardless
of `traffic_policy` rules.

## Passive mode

| Knob                                       | Default | What it does                                                       |
| ------------------------------------------ | ------- | ------------------------------------------------------------------ |
| `passive_min_flows_to_finish`              | 0       | Stop when this many flows have terminated naturally (FIN/RST/idle). |
| `passive_max_parallel_flows`               | 5       | Cap on flows tracked concurrently across all workers. 0 = unlimited. |
| `passive_max_execution_time_seconds`       | 0.0     | Wall-clock cap on the run. 0 = no timeout.                          |
| `monitored_flow_idle_expiry_seconds`       | 0.0     | Idle eviction. Set non-zero to bound stale flow state.             |
| `admission_grace_period_seconds`           | 0.0     | Reserved for symmetry with active mode; not enforced in passive.   |

## Notes

- These knobs are validated against `examples/configs/config_schema.json`. Out-of-range values fail at load time.
- The same knobs are accepted over gRPC via `SetRuntimePolicy` or inline via `StartTestRequest.config_override_json`. See `docs/run/grpc-guide.md`.
- For day-to-day operation, the four knobs in the active example (`packet_drop_probability`, `max_packet_drops_per_flow`, `max_packet_drops_global_aggregate`, `stop_after_individual_flows`) are the ones that matter.
