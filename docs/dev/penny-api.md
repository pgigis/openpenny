# Penny API Reference

The Penny heuristics layer: types that model TCP flows, how drops and
retransmissions are tracked, and the knobs that drive behaviour. Read
this when embedding the Penny components outside the CLI or extending
the packet-processing loop.

For tuning the public knobs without touching code, see
[`docs/run/tuning-reference.md`](../run/tuning-reference.md).

## Responsibilities

- **Per-flow modelling** — `penny::FlowEngine` tracks sequence coverage,
  duplicates, and drop/retransmit bookkeeping, and produces a decision
  status when thresholds are met.
- **Flow table management** — `penny::ThreadFlowManager` owns the set of
  tracked flows and enforces `max_monitored_flows` admission.
- **Asynchronous timers** — `penny::ThreadFlowEventTimerManager`
  (thread-local) marks dropped ranges as expired if no retransmission is
  seen before the retransmission timeout
  (`retransmission_timeout_in_seconds`).
- **Statistics** — `penny::PennyStats` keeps counters aligned between
  live flows and snapshots so totals can be exported cheaply.
- **Pipeline integration** — `openpenny::ActiveTestPipelineRunner` wires
  the above into a packet source, performs flow admission, applies the
  thresholds, and forwards or zeroes packets according to the decision.

## Configuration knobs

Internal struct: `Config::ActiveConfig` (`include/openpenny/config/Config.h`).
Populated from `runtime_policy.thresholds` in YAML / JSON via the
planner. See [tuning-reference](../run/tuning-reference.md) for the
public-facing names.

| Internal field                          | YAML key                                 | Default |
| --------------------------------------- | ---------------------------------------- | ------- |
| `drop_probability`                      | `packet_drop_probability`                | `0.0`   |
| `max_duplicate_fraction`                | `max_duplicate_ratio`                    | `0.15`  |
| `max_out_of_order_fraction`             | `max_reordering_ratio`                   | `0.8`   |
| `retransmission_miss_probability`       | `retransmission_observation_miss_rate`   | `0.05`  |
| `rtt_timeout_factor`                    | `retransmission_timeout_in_seconds`      | `3.0`   |
| `flow_grace_period_seconds`             | `admission_grace_period_seconds`         | `3.0`   |
| `flow_idle_timeout_seconds`             | `monitored_flow_idle_expiry_seconds`     | `0.0`   |
| `drop_state_seconds`                    | `drop_state_seconds`                     | `0.0`   |
| `min_drops_per_flow`                    | `min_packet_drops_per_flow`              | `0`     |
| `max_drops_per_indiv_flow`              | `max_packet_drops_per_flow`              | `0`     |
| `max_drops_aggregates`                  | `max_packet_drops_global_aggregate`      | `0`     |
| `max_tracked_flows`                     | `max_monitored_flows`                    | `0`     |
| `stop_after_individual_flows`           | `stop_after_individual_flows`            | `0`     |
| `min_closed_loop_flows`                 | `min_closed_loop_flows`                  | `0`     |
| `aggregates_enabled`                    | `aggregates.enabled`                     | `false` |

## Core types

### FlowDecision

```cpp
enum class FlowDecision {
    PENDING,
    FINISHED_CLOSED_LOOP,
    FINISHED_NOT_CLOSED_LOOP,
    FINISHED_DUPLICATE_EXCEEDED,
    FINISHED_NO_DECISION,
};
```

### FlowEngine

`include/openpenny/penny/flow/engine/FlowEngine.h`,
`src/penny/flow/engine/FlowEngine.cpp`.

Per-flow engine. Tracks sequencing, drops, retransmissions, and produces
a `FlowDecision`.

- Lifecycle: construct with `Config::ActiveConfig`, then `configure(cfg)`
  to reset state and start the timer manager; `reset()` clears counters
  mid-run.
- Recording: `record_syn`, `record_data`, `record_packet`,
  `record_pure_ack`, `record_data_packet`, `record_duplicate_packet`,
  `record_droppable_packet`.
- Ordering / coverage: `track_ordering(seq)` updates in-order /
  out-of-order counters; `mark_interval(start, end)` marks coverage and
  flags duplicates when intervals overlap.
- Gap tracking: `register_gap` stores a dropped interval keyed by
  `packet_id`; `fill_gaps` / `register_filled_gaps` mark retransmissions;
  `register_duplicate_snapshot` propagates duplicate counts into snapshots.
- Drop enforcement: `drop_packet(start, end, packet_id, flow_key)` rolls
  a uniform random, drops when `< drop_probability`, records a snapshot,
  registers a timer, inserts the gap. Returns `true` when the caller
  should zero / not forward.
- Decision: `evaluate()` recommends pass-through if the duplicate budget
  is exceeded, or a drop verdict when `min_drops_per_flow` is satisfied.
  Otherwise stays `PENDING`.
- Snapshots: `drop_snapshots()` returns `{packet_id, Snapshot}` pairs.
  Each snapshot captures counters at drop time and whether it was later
  retransmitted (`mark_snapshot_retransmitted`) or expired
  (`mark_snapshot_expired`).

### ThreadFlowManager

`include/openpenny/penny/flow/manager/ThreadFlowManager.h`.

Container for tracked flows plus monitor-state transitions.

- Admission: `is_flow_monitoring_capacity_full()` enforces
  `max_monitored_flows`; `packet_in_context()` reports whether a flow is
  already tracked.
- Insertion: `add_new_flow` seeds state and counters (including TFO
  payload bookkeeping) for both SYN-first and data-first flows.
- States: `FlowTrackingState` is one of `PENDING`, `PENDING_SEEN_DATA`,
  `ACTIVE_SEEN_SYN`, `ACTIVE_SEEN_DATA`, `NOT_ACTIONABLE`.
- Maintenance: `find`, `flow_state`, `erase`, `clear`, `size`.

### ThreadFlowEventTimerManager

`include/openpenny/penny/flow/timer/ThreadFlowEventTimer.h`,
`src/penny/flow/timer/ThreadFlowEventTimer.cpp`.

Thread-local timer thread handling drop expirations and retransmit /
duplicate events.

- `start(timeout_sec)` spins up the background thread (called from
  `FlowEngine::configure`).
- `register_drop(key, packet_id, ts, alive_flag, flow)` schedules
  expiration at `ts + retransmission_timeout_in_seconds`; expiration calls
  `flow->mark_snapshot_expired`.
- `enqueue_retransmitted(packet_id, flow)` cancels the timer and notifies
  the owning flow to mark the snapshot retransmitted.
- `enqueue_duplicate(flow, seq)` updates historical snapshots when later
  duplicates arrive.
- `purge_flow(flow)` removes pending timers when a flow is destroyed.

## Runtime flow inside ActiveTestPipelineRunner

`src/app/core/active/ActiveTestPipeline.cpp`. Typical driving pattern:

- Each packet is counted, then `admit_or_forward_flow` either starts
  tracking the flow (respecting capacity limits) or forwards immediately
  when untracked.
- ACK-only path: `handle_pure_ack` bumps ACK counters and forwards.
- Data path: `handle_data_packet` updates ordering counters, detects
  duplicates via `mark_interval`, fills any repaired gaps, and:
  - For duplicates: record duplicate snapshot updates and forward.
  - For first-seen payloads: call `drop_packet`. Dropped packets are
    zeroed and not forwarded; accepted packets are forwarded (optionally
    to TUN).
- The runner returns a `ModeResult` with processed / forwarded counts
  and in/out-of-order / duplicate stats.

## Minimal embedding example

```cpp
openpenny::PipelineOptions opts;
opts.mode        = openpenny::PipelineOptions::Mode::Active;
opts.queue_count = cfg.input.queue_count;
opts.should_stop = [] { return false; };

auto source = openpenny::dataplane::create_session(cfg);
openpenny::ActiveTestPipelineRunner runner(
    cfg, opts,
    /* FlowMatcher */ [](const FlowKey&) { return true; },
    std::move(source));

auto result = runner.run();
if (result && result->penny_completed) {
    // Heuristics decided to stop; counters in result.
}
```

## Exporting decisions and counters

- `FlowEngine::drop_snapshots()` returns every enforced drop with its
  retransmission status and the counter state at drop time.
- `PennyStats` getters (`retransmitted_packets`,
  `pending_retransmissions`, `duplicate_packets`, etc.) supply telemetry.

## Extending the heuristics

- Plug alternative confidence models into `FlowEngine::evaluate`.
- Inject extra classification before `drop_packet` in
  `ActiveTestPipelineRunner::handle_data_packet`.
- Subscribe to `ThreadFlowEventTimerManager` retransmit / duplicate
  events to feed an external telemetry sink.
