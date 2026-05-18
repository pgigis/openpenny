# Control-Plane Architecture

OpenPenny separates **what** the operator wants from **how** the
dataplane runs it. The public API talks about traffic policy and
runtime behaviour; AF_XDP, DPDK, queue routing, XDP attach details, and
BPF map layout are internal.

## Layers

1. **API layer** — public gRPC messages: `TrafficPolicy`, `RuntimePolicy`,
   `SafetyPolicy`, `TestThresholds`, `PennyConfig`. Clients set policy
   and read desired / effective config. Clients never send queue ids,
   XSK map entries, or raw XDP settings.

2. **Planner / compiler** (`openpenny::control`) — compiles traffic policy
   into `net::TrafficMatchConfig`, compiles runtime policy into
   active / passive Penny settings, and produces an `EffectiveConfig`
   with a compiled summary and warnings.

3. **Dataplane manager** — a backend-neutral session layer hides
   AF_XDP / eBPF and DPDK details from the runtime. AF_XDP and DPDK
   readers stay as the high-performance execution layer behind that
   interface. BPF object loading, XDP attach / detach, AF_XDP socket
   setup, and map population all live here.

4. **Penny runtime manager** — owns active / passive mode, thresholds,
   timers, retry limits, budgets, and safety controls. All userspace, no
   kernel ABI.

## Configuration domains

| Domain          | Section            | Contents                                                                                |
| --------------- | ------------------ | --------------------------------------------------------------------------------------- |
| Traffic policy  | `traffic_policy:`  | default include / exclude, rules (5-tuple), priorities.                                 |
| Runtime policy  | `runtime_policy:`  | active / passive mode, thresholds, aggregates toggle, safety controls (e.g. SSH bypass).|
| Platform        | `platform:`        | backend (`af_xdp`, `af_packet_mirror`, `dpdk`), interface, queue / worker topology, XDP attach / ring / batch sizing, BPF object path. |
| Egress          | `egress:`          | `kind` (`none`, `tun`, `raw_socket`, `raw_nic`) + per-kind device and options.          |
| Logging         | `log:`             | mode, level.                                                                            |

Each section can be inlined in the root file or pulled in via
`includes:`. See
[`docs/run/configuration-examples.md`](../run/configuration-examples.md)
for both layouts.

## Key files

- `include/openpenny/control/Policy.h`, `src/control/Policy.cpp` — domain
  model and string-conversion helpers.
- `include/openpenny/control/Planner.h`, `src/control/Planner.cpp` —
  compiles traffic and runtime policy and produces the effective config.
- `include/openpenny/control/PolicyJson.h`, `src/control/PolicyJson.cpp`
  — JSON view of desired and effective config.
- `include/openpenny/dataplane/Session.h`, `Factory.h`,
  `src/dataplane/Factory.cpp` — backend-neutral session interface and
  factory; produces AF_XDP or DPDK sessions.
- `include/openpenny/config/Config.h`, `src/config/Config.cpp` — loads
  YAML, parses traffic / runtime / platform / egress.
- `proto/penny.proto` — gRPC objects and RPCs: `ApplyConfig`,
  `SetTrafficPolicy`, `SetRuntimePolicy`, `SetMode`, `GetDesiredConfig`,
  `GetEffectiveConfig`, `ReloadConfig`, `Stop`, `GetRuntimeStatus`,
  `StartTest`.
- `include/openpenny/grpc/PennyService.h`, `src/grpc/PennyService.cpp` —
  daemon-side handlers; convert gRPC messages to control-plane objects,
  validate, run them through the planner.
- `examples/configs/config_default.yaml`,
  `examples/configs/config_schema.json` — example config plus the JSON
  schema used for validation.
- `tests/unit/control/test_control_planner.cpp` — unit tests for traffic
  and runtime compilation, plus warnings.

## Startup flow

1. CLI or daemon loads the YAML.
2. `Config::from_file` resolves any `includes:` relative to the root file.
3. The combined YAML is schema-validated.
4. `Config::from_file` parses `traffic_policy`, `runtime_policy`,
   `platform`, and `egress`.
5. The planner compiles desired into effective config.
6. AF_XDP / DPDK readers receive a `TrafficMatchConfig`.
7. AF_XDP attaches the BPF program and publishes the compiled rule into
   internal maps after the socket is ready.
8. The Penny runtime is started with active / passive mode and
   thresholds from runtime policy.

## Split config files

A root YAML can include smaller files per domain:

```yaml
log:
  mode: console
  level: info

includes:
  traffic_policy: policies/traffic_default.yaml
  runtime_policy: policies/runtime_active.yaml
  platform:       platform/af_xdp.yaml
  egress:         platform/egress_tun.yaml
```

Each included file can either contain the section body directly or wrap
it in the section name. Anything written inline in the root overrides
the included version — useful for sharing a platform profile across
hosts and only overriding `platform.interface` per host.
