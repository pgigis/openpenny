# Documentation Hub

Use this page as the entry point to the project docs.

## Table of Contents
- **Run**
  - [CLI guide](run/cli-guide.md)
  - [CLI quick reference](run/cli-readme.md)
  - [gRPC guide](run/grpc-guide.md)
  - [gRPC client example](run/grpc-client-example.md)
- **Ops**
  - [Install & build](ops/install-and-build.md)
- **Dev**
  - [Active vs passive pipeline overview](dev/active-passive-overview.md)
  - [Drop snapshot data flow](dev/drop-snapshot-flow.md)
  - [gRPC override format](dev/grpc-override-format.md)
  - [gRPC example payloads](dev/grpc-config-example.json), [summary example](dev/grpc-summary-example.json)

## Quick Troubleshooting (XDP path)
- Ensure the XDP object is built: `cmake --build build --target xdp_bpf` or let the CLI auto-build.
- Clean stale pins if attachment looks wrong:
  ```bash
  sudo python3 scripts/xdp_attach.py --iface <if> --mode drv --detach
  sudo rm -rf /sys/fs/bpf/openpenny*
  sudo ./build/openpenny_cli --config examples/configs/config_default.yaml --mode active --iface <if> --queue 0 --tun xdp-tun
  ```
- Verify attachment and xsks map:
  ```bash
  ip -details link show dev <if> | grep -i xdp
  bpftool map dump pinned /sys/fs/bpf/openpenny_<if>_<mask>/xsks
  ```
- Allow fallbacks if the NIC/driver doesn’t support zero-copy:
  set `require_zerocopy: false`, `allow_skb_fallback: true`, `allow_copy_fallback: true` in `examples/configs/config_default.yaml`.
