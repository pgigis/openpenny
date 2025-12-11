# Changelog

## 1.0.0
### Added
- CLI (`openpenny_cli`) and gRPC daemon (`pennyd` + `penny_worker`) with XDP/DPDK backends.
- Active mode (drop-based, Penny heuristic) and passive mode (mirror-only) pipelines.
- XDP attach helper (`scripts/xdp_attach.py`) and `xdp_bpf` build target.
- Documentation overhaul with deployment diagram, ops/run/dev guides, traffic generation examples, and dependency licenses.
- Dependency license manifest (`DEPENDENCIES-LICENSES.md`) and traffic generator requirements.
- CI workflow (build/tests), issue/PR templates, SECURITY.md.

### Changed
- Moved source/config/docs to repo root; CMake target renamed to `openpenny_cli`.
- Refactored aggregate control and runtime setup into separate modules.
- README now includes deployment context, articles/papers, funding acknowledgement, and disclaimers.

### Fixed
- Stabilised flow evaluation guards (avoid zero-data errors) and aligned tests to current flow tracking.
- CI package installation for gRPC plugin; XDP helper path fixes.
