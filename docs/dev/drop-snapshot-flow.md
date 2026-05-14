# Drop Snapshot Data Flow

How drop snapshots move through the system: which component owns what,
and when each one updates.

## Components

- **FlowEngine (per flow)** — owns `flow_drop_snapshots_`, a vector of
  `{packet_id, PacketDropSnapshot}`, plus the `packet_id → index` map.
  All mutations happen on the packet thread or the timer callback thread.
- **PerThreadStats (per thread, telemetry)** — `drop_snapshots` is a
  lightweight log on `openpenny::app::current_thread_counters()`. Purely
  telemetry; neither timers nor the collector read it.
- **DropCollector (shared across workers)** — created by the pipeline
  driver and shared with every `ActiveTestPipelineRunner`. Holds
  `DropSnapshotRecord { FlowKey, packet_id, PacketDropSnapshot,
  AggregatedCounters, thread_name }` for all threads.
- **Bindings (flow → collector)** — when a new flow is added, the runner
  binds the `FlowEngine*` to the shared collector plus the worker's
  `thread_name` via `bind_flow(...)`. `unbind_flow(...)` runs on
  completion.

## Update flow

1. **Drop creation**
   - `FlowEngine::drop_packet` builds a `PacketDropSnapshot`.
   - The drop sink installed by `ActiveTestPipelineRunner` overwrites
     the snapshot's `PennyStats` with `aggregate_counters()` (so fields
     reflect cross-thread totals) and upserts a `DropSnapshotRecord`
     into the shared `DropCollector`.
   - Per-thread telemetry is also updated in
     `PerThreadStats::drop_snapshots`.

2. **Timer-driven transitions (expire / retransmit / duplicate)**
   - Packet path enqueues events (`enqueue_retransmitted`,
     `enqueue_duplicate`) and expiry timers (`register_drop`) into
     `ThreadFlowEventTimerManager`.
   - The timer thread later runs callbacks
     (`mark_snapshot_retransmitted`, `mark_snapshot_expired`,
     duplicate-threshold check) on the owning `FlowEngine`.
   - After each callback the timer manager invokes the global snapshot
     hook (set once with `std::call_once` in `ActiveTestPipelineRunner`).
   - The hook looks up the `FlowEngine* → CollectorBinding` and:
     - pulls the flow's current `drop_snapshots()`,
     - overwrites each touched snapshot's stats with fresh
       `aggregate_counters()`,
     - upserts a `DropSnapshotRecord` keyed by
       `(packet_id, FlowKey, thread_name)`.

3. **Completion**
   - The pipeline driver locks the shared collector, sorts records
     newest-first, and returns them in `PipelineSummary::drop_snapshots`.
   - Stop / decision logic is not automatic; the collector simply
     reflects the latest snapshot states. Higher-level decision code can
     inspect `drop_snapshots` and pending counts to decide whether to
     stop workers.

## What's not updated

- The shared collector never touches `PerThreadStats::drop_snapshots`.
- Per-flow `flow_drop_snapshots_` remains authoritative; the collector
  mirrors it for cross-thread consumption.

## Threading model

- `FlowEngine` snapshot changes happen on the timer thread and the
  packet-processing thread; the engine is single-threaded per flow.
- The shared collector is protected by its mutex; all writers lock
  before upserting.
- The timer hook and the drop sink share the same upsert helper to
  avoid duplication.

## Key files

- `src/penny/flow/engine/FlowEngine.cpp` — per-flow snapshots, drop logic.
- `src/penny/flow/timer/ThreadFlowEventTimer.cpp` — timer callbacks, snapshot
  hook invocation.
- `src/app/core/active/ActiveTestPipeline.cpp` — installs drop sinks,
  manages flow → collector bindings, upserts shared records.
- `src/app/core/OpenpennyPipelineDriver.cpp` — creates the shared
  collector, starts workers, aggregates / sorts snapshots for the
  summary.
