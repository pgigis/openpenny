# Control-Plane Architecture

OpenPenny separates **what** the operator wants from **how** the
dataplane runs it. The public API talks about traffic policy and runtime
behaviour. AF_XDP, DPDK, queue routing, XDP attach details, and BPF map
layout are internal.

## Layers

1. **API layer**
   - Public gRPC messages: `TrafficPolicy`, `RuntimePolicy`, `SafetyPolicy`,
     `TestThresholds`, `PennyConfig`.
   - Clients set policy and read desired/effective config.
   - Clients never send queue ids, XSK map entries, or raw XDP settings.

2. **Planner / compiler** (`openpenny::control`)
   - Compiles traffic policy into `net::TrafficMatchConfig`.
   - Compiles runtime policy into active/passive Penny runtime settings.
   - Produces an `EffectiveConfig` with a compiled summary and warnings.

3. **Dataplane manager**
   - A backend-neutral session layer hides AF_XDP/eBPF and DPDK details
     from the runtime.
   - The AF_XDP and DPDK readers stay as the high-performance execution
     layer behind that interface.
   - BPF object loading, XDP attach/detach, AF_XDP socket setup, and map
     population all live here.

4. **Penny runtime manager**
   - Owns active/passive mode, thresholds, timers, retry limits, budgets,
     and safety controls. All userspace, no kernel ABI.

## Configuration Domains

### Traffic policy

What packets to touch:

- default include/exclude
- include/exclude rules
- IPv4 source/destination prefixes
- protocol
- source/destination ports
- rule name and priority

### Runtime policy

What Penny does with selected packets:

- `active` or `passive` mode
- evidence and confidence thresholds
- packet drop and duplicate thresholds
- timeout thresholds
- safety controls (e.g. SSH bypass)
- scheduler/test budgets

### Platform config

Host-specific dataplane settings:

- backend: `af_xdp`, `af_packet_mirror`, or `dpdk`
- interface
- queue and worker topology
- XDP attach preferences
- UMEM/ring/batch sizing
- DPDK burst sizing
- eBPF object/program path

## Key Files

- `include/openpenny/control/Policy.h`, `src/control/Policy.cpp`
  Domain model and string-conversion helpers.
- `include/openpenny/control/Planner.h`, `src/control/Planner.cpp`
  Compiles traffic and runtime policy and produces the effective config.
- `include/openpenny/control/PolicyJson.h`, `src/control/PolicyJson.cpp`
  JSON view of desired and effective config.
- `include/openpenny/dataplane/Session.h`, `Factory.h`,
  `src/dataplane/Factory.cpp`
  Backend-neutral session interface and factory; produces AF_XDP or
  DPDK sessions.
- `include/openpenny/config/Config.h`, `src/config/Config.cpp`
  Loads YAML, parses traffic, runtime, and platform sections.
- `proto/penny.proto`
  gRPC objects and RPCs: `ApplyConfig`, `SetTrafficPolicy`,
  `SetRuntimePolicy`, `SetMode`, `GetDesiredConfig`, `GetEffectiveConfig`,
  `ReloadConfig`, `Stop`, `GetRuntimeStatus`, and `StartTest`.
- `include/openpenny/grpc/PennyService.h`, `src/grpc/PennyService.cpp`
  Daemon-side handlers; convert gRPC messages to control-plane objects,
  validate, and run them through the planner.
- `examples/configs/config_default.yaml`,
  `examples/configs/config_schema.json`
  Example config plus the JSON schema used for validation.
- `tests/unit/control/test_control_planner.cpp`
  Unit tests for traffic and runtime compilation and warnings.

## Startup Flow

1. CLI or daemon loads the YAML.
2. `Config::from_file` resolves any `includes:` relative to the root file.
3. The combined YAML is schema-validated.
4. `Config::from_file` parses the policy and platform sections.
5. The planner compiles desired config into effective config.
6. AF_XDP / DPDK readers receive a `TrafficMatchConfig`.
7. AF_XDP attaches the BPF program and publishes the compiled rule into
   internal maps after the socket is ready.
8. The Penny runtime is started with active/passive mode and thresholds
   from runtime policy.

## Split Config Files

A root YAML can include smaller files per domain:

```yaml
log:
  mode: console
  level: info

includes:
  traffic_policy: policies/traffic_default.yaml
  runtime_policy: policies/runtime_active.yaml
  platform: platform/af_xdp.yaml
```

Each included file can either contain the section body directly or wrap
it in a top-level section. Both of these are valid:

```yaml
# policies/traffic_default.yaml
default: exclude
rules: []
```

```yaml
# policies/traffic_default.yaml
traffic_policy:
  default: exclude
  rules: []
```

Anything written inline in the root file overrides the included version,
so deployments can share a platform profile and only override host-
specific fields such as `platform.interface`.
