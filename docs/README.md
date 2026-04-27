# OpenPenny Documentation

Start here. Each link below is a short, focused page.

## Run it

- [Install and build](ops/install-and-build.md) — install dependencies and build the binaries.
- [CLI guide](run/cli-guide.md) — run active or passive mode from the command line.
- [gRPC guide](run/grpc-guide.md) — run the daemon and call it from a client.
- [Configuration examples](run/configuration-examples.md) — copy-paste YAML for common setups.
- [Sample gRPC client](run/grpc-client-example.md) — Python script that talks to the daemon.

## Understand it

- [Active vs passive](dev/active-passive-overview.md) — what each mode does and when to use which.
- [AF_XDP startup path](dev/af-xdp-startup-path.md) — how the XDP backend brings itself up.
- [Control-plane architecture](dev/control-plane-architecture.md) — daemon, planner, compiler, and configs.
- [Drop snapshot flow](dev/drop-snapshot-flow.md) — how active mode records drop outcomes.
- [Penny API](dev/penny-api.md) — flow engine internals.
- [gRPC override format](dev/grpc-override-format.md) — request override schema.

## Project

- [Changelog](project/CHANGELOG.md)
- [Contributing](project/CONTRIBUTING.md)
- [Security](project/SECURITY.md)
- [Code of conduct](project/CODE_OF_CONDUCT.md)
- [Dependency licenses](project/DEPENDENCIES-LICENSES.md)

## Something not working?

- XDP path issues: [install-and-build.md › Troubleshooting](ops/install-and-build.md#troubleshooting)
- Multi-queue (`--queues > 1`) returning `processed=0`:
  [multi-queue-troubleshooting.md](ops/multi-queue-troubleshooting.md)
- Common cleanup before a fresh run:
  ```bash
  sudo python3 scripts/xdp_attach.py --iface <if> --mode drv --detach
  sudo rm -rf /sys/fs/bpf/openpenny*
  ```
