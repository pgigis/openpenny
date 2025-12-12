# Penny API Reference

This document explains the Penny heuristics layer inside openpenny: the data structures that model TCP flows, how drops and retransmissions are tracked, and the knobs exposed through configuration. Use it as a guide when embedding the Penny components outside the demo CLI or when extending the packet-processing loop.

## Scope and Responsibilities
- **Per-flow modelling**: `penny::FlowEngine` maintains sequence coverage, duplicate detection, drop/retransmit bookkeeping, and exposes a decision status when thresholds are met.
- **Flow table management**: `penny::ThreadFlowManager` owns the set of tracked flows and enforces admission limits (`max_monitored_flows` in YAML; `max_tracked_flows` internally).
- **Asynchronous timers**: `penny::ThreadFlowEventTimerManager` (thread-local) runs a background thread per packet thread/queue that marks dropped ranges as expired if no retransmission is seen before the retransmission timeout threshold (`rtt_timeout_factor` in seconds).
- **Statistics aggregation**: `penny::PennyStats` keeps counters aligned between live flows and snapshots so totals can be exported cheaply.
- **Pipeline integration**: `openpenny::ActiveTestPipelineRunner` wires the above pieces into a packet source, performs flow admission, applies ratio thresholds (live flow and snapshots), and forwards or zeroes packets according to Penny’s decision.

## Configuration Knobs (`Config::ActiveConfig`)
All Penny behaviour is controlled by the `penny` block inside the YAML config (`openpenny/config/Config.h`):

| Key | Purpose | Default |
| --- | --- | --- |
| `drop_probability` | Per-packet probability that a droppable payload will be zeroed and tracked as a drop. | `0.0` |
| `max_duplicate_fraction` | Maximum duplicate ratio (duplicates / unique data packets) before recommending pass-through. | `0.15` |
| `retransmission_miss_probability` | Models missed retransmits; reduces confidence in drop-based decisions. Clamped to \[0,1\]. Must be >0. | `0.05` |
| `drop_state_seconds` | How long droppable/duplicate counters live without activity before being cleared. Seconds. | `0.0` (disabled) |
| `min_drops_per_flow` | Minimum enforced drops required before a drop recommendation is allowed. | `0` |
| `max_drops_per_indiv_flow` | When >0, evaluate hypotheses exactly at this drop count; otherwise require at least `min_drops_per_flow`. | `0` |
| `max_drops_aggregates` | Global drop cap across threads; when >0, stop dropping once this many have been dropped in total. | `0` |
| `rtt_timeout_factor` / `retransmission_timeout_seconds` | Absolute timeout (seconds) used by `ThreadFlowEventTimerManager` before declaring a dropped range non-retransmitted. | `3.0` |
| `flow_grace_period_seconds` | Pending data-only flows must wait this long (and show seq progress) before promotion to active. Seconds. | `3.0` |
| `max_out_of_order_fraction` | Maximum fraction of out-of-order packets allowed (out_of_order / (in_order + out_of_order)). Above this, Penny recommends pass-through. | `0.8` |
| `max_monitored_flows` | Hard cap on simultaneously tracked flows. `0` means unlimited. | `0` |

## Core Types

### FlowDecision
- Enum representing the flow decision status: `PENDING`, `FINISHED_CLOSED_LOOP`, `FINISHED_NOT_CLOSED_LOOP`, or `FINISHED_NO_DECISION`.

### FlowEngine (`openpenny/penny/flow/engine/FlowEngine.h` + `src/penny/flow/engine/FlowEngine.cpp`)
Per-flow engine that tracks sequencing, drops, retransmissions, and produces a decision status.
- **Lifecycle**: construct with `Config::ActiveConfig`, call `configure(cfg)` to reset state and start the shared `ThreadFlowEventTimerManager`, and `reset()` to clear counters mid-run.
- **Recording helpers**: `record_syn`, `record_data`, `record_packet`, `record_pure_ack`, `record_data_packet`, `record_duplicate_packet`, `record_droppable_packet`.
- **Ordering/coverage**: `track_ordering(seq)` updates in/out-of-order counters; `mark_interval(start,end)` marks payload coverage and flags duplicates when intervals overlap.
- **Gap tracking**: `register_gap` stores a dropped interval keyed by `packet_id`; `fill_gaps`/`register_filled_gaps` mark retransmissions, and `register_duplicate_snapshot` propagates duplicate counts into snapshots.
- **Drop enforcement**: `drop_packet(start,end,packet_id,flow_key)` samples a uniform random, drops when `< drop_probability`, records a snapshot, registers a timer, and inserts the gap. Returns `true` when the caller should zero/forward nothing.
- **Decision logic**: `evaluate()` recommends pass-through if duplicate budget exceeded or recommends drop when `min_drops_per_flow` thresholds are satisfied. Decisions remain `Pending` when evidence is insufficient.
- **Snapshots**: `drop_snapshots()` exposes a vector of `{packet_id, Snapshot}` pairs where each snapshot captures counters at drop time and whether it was later retransmitted (`mark_snapshot_retransmitted`) or expired (`mark_snapshot_expired`).

### ThreadFlowManager (`openpenny/penny/flow/manager/ThreadFlowManager.h`)
Container for all tracked flows plus monitor-state transitions.
- Admission: `is_flow_monitoring_capacity_full()` enforces `max_monitored_flows` (YAML `active.aggregates.max_monitored_flows`); `packet_in_context()` reports whether a flow is already tracked.
- Insertion: `add_new_flow` seeds state/counters (including TFO payload bookkeeping) for both SYN-first and data-first flows.
- Monitoring state: `FlowTrackingState` enumerates `PENDING`, `PENDING_SEEN_DATA`, `ACTIVE_SEEN_SYN`, `ACTIVE_SEEN_DATA`, `NOT_ACTIONABLE`.
- Lookup/maintenance: `find`, `flow_state`, `erase`, `clear`, `size`.
- `track_packet` is a helper used by the pipeline to skip packets when the table is at capacity.

### ThreadFlowEventTimerManager (`openpenny/penny/flow/timer/ThreadFlowEventTimer.h` + `src/penny/flow/timer/ThreadFlowEventTimer.cpp`)
Thread-local timer thread (one per packet thread/queue) handling drop expirations and retransmit/duplicate events.
- `start(timeout_sec)` spins up the background thread (called from `FlowEngine::configure`).
- `register_drop(key, packet_id, ts, alive_flag, flow)` schedules expiration at `ts + rtt_timeout_factor`; expiration calls `flow->mark_snapshot_expired`.
- `enqueue_retransmitted(packet_id, flow)` cancels the timer and notifies the owning flow to mark the snapshot retransmitted.
- `enqueue_duplicate(flow, seq)` updates historical snapshots when later duplicates arrive.
- `purge_flow(flow)` removes pending timers when a flow is destroyed/reset.

## Runtime Flow Inside `ActiveTestPipelineRunner`
`openpenny/app/core/ActiveTestPipeline.cpp` demonstrates how the Penny API is typically driven:
- Each packet is logged and counted, then `admit_or_forward_flow` either starts tracking the flow (respecting capacity limits) or forwards immediately when untracked.
- **ACK-only path**: `handle_pure_ack` bumps ACK counters and forwards.
- **Data path**: `handle_data_packet` updates ordering counters, detects duplicates via `mark_interval`, fills any repaired gaps, and:
  - For duplicates: record duplicate snapshot updates and forward.
  - For first-seen payloads: call `drop_packet`; dropped packets are zeroed (payload set to zero) and not forwarded, while accepted packets are forwarded (optionally to TUN).
- The pipeline returns a `ModeResult` with processed/forwarded counts and in/out-of-order/duplicate stats.

## Minimal Usage Patterns

### Integrating With a Packet Source
```cpp
openpenny::PipelineOptions opts = {/* prefix/tun/stop config */};
auto source = openpenny::net::create_packet_source(cfg); // see PacketSourceFactory
openpenny::ActiveTestPipelineRunner runner(cfg, opts, /* FlowMatcher */ [](const FlowKey&) { return true; }, std::move(source));

auto result = runner.run();
if (result && result->penny_completed) {
    // Heuristics decided to stop; inspect counters in result.
}
```

## Penny Daemon (gRPC)
`pennyd` is a long-running daemon that loads YAML defaults and exposes a gRPC API (industry-standard C++ gRPC) for external callers to launch Penny tests:
- Proto: `proto/penny.proto` defines `StartTest(StartTestRequest) -> StartTestResponse`.
- Request: provide `prefix` and `mask_bits` to scope the test (defaults come from YAML config).
- Behaviour: `StartTest` applies the prefix/mask override, runs the pipeline synchronously until Penny completes, then returns the `ModeResult` counters in the response.
- Build: requires Protobuf + gRPC development packages; when found, CMake builds the `pennyd` binary and generates protobuf/grpc stubs automatically.
- Run: `pennyd --config /path/to/openpenny.yaml --listen 0.0.0.0:50051`.

## Exporting Decisions and Counters
- Use `FlowEngine::drop_snapshots()` to inspect every enforced drop: whether it was retransmitted, plus the counter state at the time of the drop.
- Use `PennyStats` getters (e.g., `retransmitted_packets`, `pending_retransmissions`, `duplicate_packets`) to build telemetry.

## Extending the Heuristics
- Update `FlowEngine::evaluate` to plug in alternative confidence models or thresholds.
- Extend `ActiveTestPipelineRunner::handle_data_packet` to inject additional packet classification before `drop_packet`.
- Attach to `ThreadFlowEventTimerManager` events (retransmit/duplicate) for external logging or to feed another telemetry sink.
