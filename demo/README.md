# Demo traffic

Wrapper around `tools/traffic_generator/` for live walkthroughs of penny.
Each scenario opens with a banner naming what's sent and the aggregate
verdict to look for on the penny pane.

## Topology

```
   reeves1                reeves2                reeves3
   (sender)               (penny)                (receiver)
       ──────── forward ─────────▶
                    │
                    ▼
            aggregate decision
```

Penny observes the **forward direction only**. The reverse path is
ignored. As soon as an aggregate (src→dst) reaches a decision, the test
ends for that aggregate.

## Scenarios

| #  | Scenario                                     | Aggregate verdict          |
| -- | -------------------------------------------- | -------------------------- |
| 01 | [legitimate](scenarios/01-legitimate.md)     | legitimate closed-loop     |
| 02 | [spoofed](scenarios/02-spoofed.md)           | not closed-loop            |
| 03 | [mixed](scenarios/03-mixed.md)               | one of each                |
| 04 | [duplicates](scenarios/04-duplicates.md)     | duplicate exceeded         |

## Run

```bash
cd demo
./demo_traffic.sh legitimate          # one scenario
./demo_traffic.sh walkthrough         # all four, press-Enter between each
./demo_traffic.sh walkthrough --auto 5  # 5s pause between each (unattended)
./demo_traffic.sh stop                # tear down anything left running
./demo_traffic.sh dry-run             # print banners + commands, run nothing
```

## Per-host setup

| Host    | What it runs                                              |
| ------- | --------------------------------------------------------- |
| reeves1 | `python3`, `iperf3`, sudo for raw sockets. Runs the orchestrator. |
| reeves2 | penny in active mode pointed at the reeves1 aggregate.    |
| reeves3 | `iperf3 -s -p 5201` (manual, leave running).              |

Spoofed scenarios additionally need `scapy` on reeves1 (created
automatically by `tools/traffic_generator/run.sh install` on first run).

## Common knobs (env vars)

```bash
DURATION_SECONDS=60   ./demo_traffic.sh legitimate
IPERF_PARALLEL=32     ./demo_traffic.sh legitimate
PACKET_RATE=200       ./demo_traffic.sh spoofed
DUPLICATE_RATE=0.8    ./demo_traffic.sh duplicates
AUTO_PAUSE_SECS=5     ./demo_traffic.sh walkthrough
SPOOFED_IFACE=eth1 SPOOFED_SRC_IP=198.51.100.42 ./demo_traffic.sh spoofed
```

Full list at the top of `demo_traffic.sh`.

## Logs and markers

- `/tmp/openpenny-demo-traffic.log` — full prefixed output.
- `/tmp/openpenny-demo-traffic.markers` — scenario BEGIN/END markers.
  `tail -F` it from the penny pane to align verdicts with scenarios.

## Use only on networks you own

Spoofed modes forge source IPs. Defaults use RFC 5737 documentation
space (`198.51.100.0/24`) so an unconfigured run can't aim at production.
Override destination knobs deliberately for a real lab.
