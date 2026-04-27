# CLI Guide

How to run OpenPenny from the command line, in either active or passive mode.

## Before you start

You need:

- A built binary at `./build/openpenny_cli` (see [install and build](../ops/install-and-build.md)).
- A YAML config file. The default in the repo is `examples/configs/config_default.yaml`.
- Root or `CAP_NET_ADMIN`. XDP, TUN, and raw sockets all need it.

## Active mode

Active mode redirects a slice of traffic, drops a few packets, and watches
which senders retransmit.

```bash
sudo ./build/openpenny_cli \
  --config examples/configs/config_default.yaml \
  --mode active \
  --prefix 192.168.41.0/24 \
  --iface <ifname> --queue 0 \
  --tun xdp-tun
```

What you'll see when it finishes: packet and flow counts, plus an aggregate
result — `closed_loop`, `not_closed_loop`, or `duplicates_exceeded`.

## Passive mode

Passive mode just watches. It never drops packets.

```bash
sudo ./build/openpenny_cli \
  --config examples/configs/config_default.yaml \
  --mode passive \
  --prefix 192.168.41.0/24 \
  --iface <ifname> --queue 0
```

Passive mode taps the interface; the kernel keeps delivering packets to your
real application as normal. No XDP program is loaded and no TUN is used.

It stops when one of these is true:

- The number of finished flows reaches `passive_min_flows_to_finish`.
- The run hits `passive_max_execution_time_seconds`.
- All tracked flows have been idle longer than `monitored_flow_idle_expiry_seconds`.

## DPDK

If you built with DPDK and set `platform.backend: dpdk` in the config (or
pass `--source dpdk`), the same commands work. Configure the PCI device and
port in the YAML.

```bash
sudo ./build/openpenny_cli --config examples/configs/config_default.yaml --mode active
```

## All flags

| Flag                              | What it does                                                                 |
| --------------------------------- | ---------------------------------------------------------------------------- |
| `-c, --config <path>`             | YAML config to use.                                                          |
| `--source <xdp\|dpdk>`            | Packet source backend (default: `xdp`).                                      |
| `--mode <active\|passive>`        | Pipeline mode (default: `active`).                                           |
| `-p, --prefix <ip>/<bits>`        | Filter flows by CIDR, e.g. `192.168.41.0/24` or `10.0.0.5/32`.               |
| `--iface <dev>`                   | Capture interface (XDP attaches here).                                       |
| `--xdp-mode <auto\|drv\|generic>` | XDP attachment mode (default: `auto`).                                       |
| `-q, --queue <id\|auto>`          | Queue id, or `auto` to probe and pick the active queue.                      |
| `--queue-probe-ms <ms>`           | Probe time per queue when using `--queue auto`.                              |
| `-Q, --queues <count>`            | Number of queue workers to spawn (default: 1).                               |
| `--tun <dev>` (`--tun-name`)      | Forward matched packets to a TUN device. Sets `egress.kind: tun`.            |
| `--stats-sock <path>`             | Optional Unix datagram socket for live stats.                                |
| `-h, --help`                      | Print this list.                                                             |

Forwarding kinds other than TUN (`none`, `raw_socket`, `raw_nic`) are
set in the YAML `egress:` block — see
[configuration examples](configuration-examples.md#egress-where-matched-packets-go).

## Tips

- Multiple queues: pass `-Q <count>` to spread work across queue workers.
  Match the count to your active flow count and configure RSS to steer
  traffic to the served queues — see
  [multi-queue troubleshooting](../ops/multi-queue-troubleshooting.md).
- Pin workers to specific CPUs in YAML via `platform.worker_cpus`.
- If a previous run left BPF pins behind, the CLI will print a one-line
  hint with the cleanup commands. You can also clean up manually:
  ```bash
  sudo python3 scripts/xdp_attach.py --iface <if> --mode drv --detach
  sudo rm -rf /sys/fs/bpf/openpenny*
  ```
