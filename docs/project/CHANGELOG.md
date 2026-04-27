# Changelog

## 1.1.0

This release is a clean-up and consolidation pass on top of 1.0.0. It
introduces an alternative observation backend, a clearer separation of
operator policy from host-specific platform settings, several new
diagnostics, and a documentation overhaul.

### Added

- AF_PACKET mirror ingress backend (`platform.backend: af_packet_mirror`)
  for non-perturbing observation. No XDP program is loaded; the kernel
  keeps delivering packets to the real application.
- Ingress mode selection (`platform.ingress_mode`):
  - `copy` taps the interface via AF_PACKET (default for passive).
  - `redirect` pulls matched packets out of the kernel into AF_XDP
    (default for active).
  - `auto` resolves from the runtime mode at startup.
- Egress as a first-class config block: `egress.kind` of `none`, `tun`,
  `raw_socket`, or `raw_nic`, with one shared sink across queue workers.
- Traffic policy (include/exclude rules with priority, prefix, protocol,
  port) and runtime policy (active/passive thresholds, safety controls)
  as the public configuration surface; `platform:` carries host-specific
  fields separately.
- Aggregate evaluation in active mode: cross-flow drop snapshots,
  closed-loop verdict, and early stop on aggregate decisions.
- Passive-mode example config (`examples/configs/config_passive.yaml`)
  and split policy / platform includes under `examples/configs/`.
- RSS coverage check that warns when the NIC's RSS indirection table
  routes to queues OpenPenny isn't serving.
- Stale BPF pin detection at startup with a copy-paste cleanup hint.
- Diagnostic counters: kernel `[xdp_counters]` (INFO, every 5s) plus
  per-socket `XDP_STATISTICS` and userspace RX counters (DEBUG).
- No-packets watchdog: a single WARN block 5 seconds after start with
  numbered things to check if `aggregate.packets` is still zero.
- Queue over-subscription clamp: `--queues N` is reduced when N exceeds
  the NIC's RX queue count, with a warning instead of a silent socket
  failure.

### Changed

- Pipeline split into modular blocks: `PacketSink` egress abstraction,
  shared `PipelineRunner`, separate ingress and egress configuration.
- Active and passive pipelines de-duplicated into one runner.
- TUN reinjection now sets `rp_filter_loose` automatically when enabled
  to stop reverse-path filtering from silently dropping reinjected
  packets.
- Per-worker AF_XDP log lines demoted to DEBUG; cross-queue kernel XDP
  counters printed once every 5s at INFO.
- Single-line startup summary at INFO with backend, queue range, and
  egress configuration.
- README rewritten: shorter and focused on what the tool does and how
  to run it.
- Docs hub simplified; CLI quick reference merged into the CLI guide;
  configuration examples rewritten in plain language.

### Fixed

- TUN reinjection so packets reach the final application end-to-end.
- Stray `std::cout` calls in the active pipeline routed through the
  logger.
- Various log-level adjustments to reduce noise at INFO with many queue
  workers.

### Known limitations

- AF_XDP currently compiles **one** runtime traffic-match rule per run.
  The planner emits a warning if policy intent exceeds that.

## 1.0.0

### Added

- CLI (`openpenny_cli`) and gRPC daemon (`pennyd` + `penny_worker`) with
  XDP/DPDK backends.
- Active mode (drop-based, Penny heuristic) and passive mode
  (mirror-only) pipelines.
- XDP attach helper (`scripts/xdp_attach.py`) and `xdp_bpf` build target.
- Documentation overhaul with deployment diagram, ops/run/dev guides,
  traffic generation examples, and dependency licenses.
- Dependency license manifest (`docs/project/DEPENDENCIES-LICENSES.md`)
  and traffic generator requirements.
- CI workflow (build/tests), issue/PR templates, and
  `docs/project/SECURITY.md`.

### Changed

- Moved source/config/docs to repo root; CMake target renamed to
  `openpenny_cli`.
- Refactored aggregate control and runtime setup into separate modules.
- README now includes deployment context, articles/papers, funding
  acknowledgement, and disclaimers.

### Fixed

- Stabilised flow evaluation guards (avoid zero-data errors) and aligned
  tests to current flow tracking.
- CI package installation for gRPC plugin; XDP helper path fixes.
