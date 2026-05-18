# Developer Documentation

Notes on the internals: pipeline shape, backends, control plane, and the
gRPC API. Read this if you are working in the codebase rather than just
running the tool.

For setup and end-user docs, start at [`docs/README.md`](../README.md). For
PR conventions, see [`docs/project/CONTRIBUTING.md`](../project/CONTRIBUTING.md).

## Pipeline and flow engine

- [Active vs passive overview](active-passive-overview.md) — the per-queue
  pipeline, the active vs passive split, and which configuration knobs
  govern each.
- [Penny API reference](penny-api.md) — the flow engine: types, drop and
  retransmission tracking, and the knobs exposed through configuration.
- [Drop snapshot data flow](drop-snapshot-flow.md) — how drop outcomes
  move through the system and which component owns what.

## Backends

- [AF_XDP startup path](af-xdp-startup-path.md) — file-by-file walk of how
  the eBPF/AF_XDP backend brings itself up.

## Control plane

- [Control-plane architecture](control-plane-architecture.md) — the
  separation between operator-facing desired config (traffic policy /
  runtime policy / platform / egress) and the compiled effective config,
  and the planner/compiler that translates between them.

## gRPC API

- [gRPC override format](grpc-override-format.md) — the JSON shape
  accepted by `StartTestRequest.config_override_json` and the typed RPCs.
- [`grpc-config-example.json`](grpc-config-example.json) — sample
  override payload.
- [`grpc-summary-example.json`](grpc-summary-example.json) — sample
  `StartTestResponse.json_summary` reply.

The proto definitions live in [`proto/penny.proto`](../../proto/penny.proto).

## Code map

Where things live, at a glance:

| Area              | Path                                                        |
| ----------------- | ----------------------------------------------------------- |
| Public headers    | `include/openpenny/`                                        |
| Core library      | `src/`                                                      |
| Pipelines (active/passive) | `src/app/core/active/`, `src/app/core/passive/`    |
| Pipeline driver   | `src/app/core/OpenpennyPipelineDriver.cpp`                  |
| Flow engine       | `src/penny/flow/`                                           |
| Ingress backends  | `src/ingress/af_xdp/`, `src/ingress/af_packet/`, `src/ingress/dpdk/` |
| Egress sinks      | `src/egress/`                                               |
| Control plane     | `src/control/` (`Planner.cpp`, `PolicyJson.cpp`, `Policy.cpp`) |
| Config parsing    | `src/config/Config.cpp`                                     |
| gRPC service      | `src/grpc/PennyService.cpp`                                 |
| eBPF program      | `ebpf/af_xdp/`                                              |
| Proto definitions | `proto/penny.proto`                                         |
| Unit tests        | `tests/unit/`                                               |

## Build, test, regenerate

```bash
# Build with all backends.
cmake -S . -B build \
  -DOPENPENNY_WITH_XDP=ON \
  -DOPENPENNY_WITH_DPDK=OFF \
  -DgRPC_DIR=/path/to/lib/cmake/gRPC \
  -DProtobuf_DIR=/path/to/lib/cmake/protobuf \
  -DGRPC_CPP_PLUGIN=/usr/bin/grpc_cpp_plugin
cmake --build build

# Run the unit tests.
ctest --test-dir build --output-on-failure

# Rebuild just the eBPF object.
cmake --build build --target xdp_bpf
```

The proto stubs are regenerated automatically when `proto/penny.proto`
changes. If you add a new RPC or message, run a full rebuild so the
generated `penny.pb.h` and `penny.grpc.pb.h` pick it up.

## Conventions worth knowing

- **One canonical spelling per YAML/JSON enum value.** The parser and
  schema in `examples/configs/config_schema.json` accept only the
  canonical names (`af_xdp`, `copy`, `redirect`, `include`, `exclude`,
  etc.). Aliases that earlier releases tolerated have been retired.
- **`runtime_policy.thresholds` is the only home for thresholds.** The
  full list lives in [`docs/run/tuning-reference.md`](../run/tuning-reference.md).
  Active and passive knobs do not mix in one file; use
  `policies/runtime_active.yaml` or `policies/runtime_passive.yaml`.
- **`egress.kind` is the only forwarding selector.** Values are `none`,
  `tun`, `raw_socket`, `raw_nic`. The earlier `traffic_forwarding` /
  root-level `tun:` block has been removed.
- **The legacy `monitoring.{active,passive}` / `input_sources.*` /
  `active:` / `penny:` YAML shapes have been removed.** New configs and
  gRPC overrides use `traffic_policy`, `runtime_policy`, `platform`,
  `egress` only.

## See also

- [`docs/layout.md`](../layout.md) — full repository map.
- [`docs/run/configuration-examples.md`](../run/configuration-examples.md)
  — operator-facing config examples.
- [`docs/run/tuning-reference.md`](../run/tuning-reference.md) — full
  threshold reference.
