# Drop Snapshot Data Flow

This notes how drop snapshots move through the system so it is clear which component owns what and when it updates.

## Components
- **FlowEngine (per flow)**: owns `flow_drop_snapshots_` (vector of `{packet_id, PacketDropSnapshot}`) and the packet_id → index map. All mutations happen on the packet-processing thread or the timer callback thread.
- **PerThreadStats (per thread, telemetry)**: `drop_snapshots` is a lightweight log stored in `openpenny::app::current_thread_counters()`. It is purely per-thread telemetry and is *not* read by timers or the collector.
- **DropCollector (shared across workers)**: created by the pipeline driver and shared with every `ActiveTestPipelineRunner`. It holds `DropSnapshotRecord { FlowKey, packet_id, PacketDropSnapshot, AggregatedCounters, thread_name }` for all threads.
- **Bindings (flow → collector)**: when a new flow is added, the runner binds the `FlowEngine*` to the shared collector plus the worker’s `thread_name` via `bind_flow(...)`. On completion, `unbind_flow(...)` is called.

## Update flow
1) **Drop creation**
   - `FlowEngine::drop_packet` creates a `PacketDropSnapshot`.
   - The drop sink installed by `ActiveTestPipelineRunner` overwrites the snapshot’s `PennyStats` with `aggregate_counters()` (so fields reflect cross-thread totals) and pushes/updates a `DropSnapshotRecord` in the shared `DropCollector`.
   - Per-thread telemetry is also updated in `PerThreadStats::drop_snapshots` (bounded only by memory).

2) **Timer-driven transitions (expire / retransmit / duplicate)**
   - Packet path enqueues events (`enqueue_retransmitted`, `enqueue_duplicate`) and expiry timers (`register_drop`) into `ThreadFlowEventTimerManager`.
   - The timer thread later runs callbacks (`mark_snapshot_retransmitted`, `mark_snapshot_expired`, duplicate threshold check) on the owning `FlowEngine`.
   - After each callback, the timer manager invokes the global snapshot hook (set once with `std::call_once` in `ActiveTestPipelineRunner`).
   - The hook looks up the `FlowEngine*` → `CollectorBinding` (collector + thread name) and:
     - pulls the flow’s current `drop_snapshots()`,
     - overwrites each touched snapshot’s stats with fresh `aggregate_counters()`,
     - upserts a `DropSnapshotRecord` in the shared `DropCollector` keyed by `(packet_id, FlowKey, thread_name)`.

3) **Completion**
   - When the pipeline driver finishes, it locks the shared collector, sorts records newest-first, and returns them in `PipelineSummary::drop_snapshots`.
   - Aggregate stop/decision logic is *not* automatic; the collector simply reflects the latest snapshot states. Any higher-level decision can inspect `drop_snapshots` and pending counts to decide whether to stop workers.

## What is **not** updated
- The shared collector never touches `PerThreadStats::drop_snapshots`.
- Per-flow `flow_drop_snapshots_` remains authoritative; the collector mirrors it for cross-thread consumption.

## Threading model
- FlowEngine snapshot changes happen on the timer thread and packet-processing thread (single-threaded per FlowEngine).
- The shared collector is protected by its mutex; all writers lock it before upserting records.
- The timer hook and the drop sink both use the same upsert helper to avoid duplication.

## Key files
- `src/penny/flow/engine/FlowEngine.cpp`: per-flow snapshots and packet drop logic.
- `src/penny/flow/timer/ThreadFlowEventTimer.cpp`: timer callbacks and snapshot hook invocation.
- `src/app/core/active/ActiveTestPipeline.cpp`: installs drop sinks, manages flow→collector bindings, and upserts shared records.
- `src/app/core/OpenpennyPipelineDriver.cpp`: creates the shared collector, starts workers, and aggregates/sorts snapshots for the summary.
