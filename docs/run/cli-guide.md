# CLI Usage Guide

This guide shows how to run Penny in **active** and **passive** modes via the CLI binary (`openpenny_cli`), using the example config under `examples/configs/`.

## Prerequisites
- Build the project (XDP example):
  ```bash
  cmake -S . -B build -DOPENPENNY_WITH_XDP=ON
  cmake --build build
  ```
- Binary path (from the root of this repo): `./build/openpenny_cli`
- Example config: `examples/configs/config_default.yaml` (toggle the DPDK/XDP blocks as needed)

## Active mode (with TUN forwarding)
```bash
sudo ./build/openpenny_cli \
  --config examples/configs/config_default.yaml \
  --mode active \
  --prefix 192.168.41.0 \
  --mask-bits 24 \
  --iface <your_ifname> \
  --queue 0 \
  --tun xdp-tu
```
Key flags:
- `--config` : YAML config file (full `monitoring` block respected)
- `--mode active|passive` : pipeline mode
- `--prefix` / `--mask-bits` : filter flows by subnet
- `--iface` / `--queue` : input interface and queue
- `--tun` : TUN device name for forwarding (omit or add `--no-forward-to-tun` to disable)
- Add `--forward-raw-socket` and `--forward-device <if>` to forward via a raw socket instead of TUN.

Expected output: a CLI summary with packet/flow counts and the aggregate decision (closed_loop / not_closed_loop / duplicates_exceeded).

## Passive mode
```bash
sudo ./build/openpenny_cli \
  --config examples/configs/config_default.yaml \
  --mode passive \
  --prefix 192.168.41.0 \
  --mask-bits 24 \
  --iface <your_ifname> \
  --queue 0 \
  --no-forward-to-tun
```
Notes:
- Passive mode ignores drop heuristics; it observes flows until `monitoring.passive.min_number_of_flows_to_finish` and `max_execution_time` thresholds are met.
- Idle expiry is controlled by `monitoring.passive.timeouts.monitored_flow_idle_expiry_seconds`.
- Summary prints per-flow stats (start/end reason, gaps).

## DPDK example
If built with DPDK (`-DOPENPENNY_WITH_DPDK=ON -DOPENPENNY_WITH_XDP=OFF` and `input_sources.dpdk.enable: true` in the config):
```bash
sudo ./build/openpenny_cli --config examples/configs/config_default.yaml --mode active
```
Use the config file to set the PCI device/port; CLI flags can still override prefix/mask/mode.

## Tips
- Increase log verbosity with `--log-level debug`.
- To disable TUN/forwarding entirely, pass `--no-forward-to-tun` (and omit `--forward-raw-socket`).
- Ensure the interface/queue exists and permissions (CAP_NET_ADMIN) are available when using XDP/TUN.
