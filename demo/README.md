# Demo traffic

Thin wrapper around `tools/traffic_generator/` so a live demo can flip
between four canned scenarios from a single command without
remembering every flag. Doesn't touch openpenny itself, doesn't
reimplement any of the existing generators — just shells out to
`tools/traffic_generator/run.sh` with the right arguments and tears
the children down cleanly when you're done.

## Modes

| Mode         | What it runs                                          | What openpenny should see                  |
| ------------ | ----------------------------------------------------- | ------------------------------------------ |
| `legitimate` | `client.py` against the receiver, real TCP handshake. | Closed-loop verdict on the flow.           |
| `spoofed`    | `spoofed_client.py --routed`, forged source IP.       | Closed-loop check fails (no return path).  |
| `mixed`      | Both of the above, started a few seconds apart.       | Closed-loop holds for the legit flow, fails for the spoofed background. |
| `duplicates` | Spoofed flow with `--duplication-prob` cranked up.    | Duplicate-fraction threshold trips on the aggregate. |
| `stop`       | Terminates every background generator we started.     | n/a                                        |
| `dry-run`    | Prints the commands instead of running them.          | n/a                                        |

## Run

From a host that can reach the openpenny receiver:

```bash
cd demo
./demo_traffic.sh legitimate
./demo_traffic.sh spoofed
./demo_traffic.sh mixed
./demo_traffic.sh duplicates
./demo_traffic.sh stop
./demo_traffic.sh dry-run            # prints all four
./demo_traffic.sh dry-run mixed      # prints just one
```

## Config

All knobs live at the top of `demo_traffic.sh` and can be overridden
from the environment:

```bash
DURATION_SECONDS=60   ./demo_traffic.sh mixed
PACKET_RATE=200       ./demo_traffic.sh spoofed
DUPLICATE_RATE=0.8    ./demo_traffic.sh duplicates
SPOOFED_IFACE=eth1 SPOOFED_SRC_IP=198.51.100.42 ./demo_traffic.sh spoofed
```

The defaults intentionally use the RFC 5737 documentation prefixes
(`198.51.100.0/24`, TEST-NET-2) so a copy-paste can't aim the spoofed
flow at production by accident. Override the destination knobs
deliberately for a real lab.

## Required tools

- `bash` 4+
- `python3` 3.8+
- GNU coreutils (`timeout`, `stdbuf`, `tee`, `sed`)
- Whatever `tools/traffic_generator/run.sh` already needs: `scapy`
  (the wrapper creates its own venv on first run via
  `run.sh install`) and iproute2 for the preflight checks.

`iperf3` is **not** required. `mixed` mode runs `client.py` plus
`spoofed_client.py` together rather than the iperf3 path in
`tools/traffic_generator/mixed_traffic.py`. If you want iperf-style
saturation alongside spoofed flows, run `mixed_traffic.py` directly.

## Privileges

`legitimate` runs as a regular user (plain TCP `connect`).

`spoofed`, `mixed`, and `duplicates` go through
`tools/traffic_generator/run.sh spoof`, which uses Scapy raw sockets
and re-execs itself under `sudo` if you aren't already root. The demo
script doesn't call `sudo` itself; the prompt comes from `run.sh`.
Cache the sudo timestamp once up front:

```bash
sudo -v
```

## Receiver side

On the openpenny analysis box, run a listener so the legitimate flow
has a real socket to talk to (otherwise the kernel sends RSTs and the
closed-loop check sees a half-open dance):

```bash
cd tools/traffic_generator
./run.sh server 9000
```

Then start openpenny in active mode pointed at the spoofed prefix as
described under "Using with openpenny CLI" in
`tools/traffic_generator/README.md`. This script doesn't start
openpenny — keep it on a separate pane and read its own logs / CLI
output for the verdict.

## Per-mode behaviour

- **legitimate** — baseline. Real handshake, steady payload, clean
  FIN. openpenny should reach a `CLOSED_LOOP` verdict.
- **spoofed** — same wire, same destination, forged source IP.
  Receiver's ACKs go nowhere, the flow never closes, the closed-loop
  check fails.
- **mixed** — closer to a real ingress. Legit and spoofed flows on
  the same wire, toward the same destination, started a few seconds
  apart. openpenny should still surface the closed-loop verdict for
  the legit flow while flagging the rest.
- **duplicates** — spoofed flow with a high duplicate probability.
  Stresses the aggregate analysis path; the duplicate-fraction
  threshold should trip.

## Cleanup and Ctrl-C

PIDs of background generators land in
`/tmp/openpenny-demo-traffic.pids`. `./demo_traffic.sh stop` reads
that file, sends `SIGTERM`, waits a second, then `SIGKILL`s anything
still alive, and removes the file. Ctrl-C during a foreground mode
hits the same path via a `trap`. `stop` is safe to run when nothing
is running.

Combined output from every mode is appended to
`/tmp/openpenny-demo-traffic.log` so you can scroll back without
losing earlier verdicts.

## What this script doesn't do

- Doesn't modify any openpenny code.
- Doesn't invent openpenny output, dashboards, or telemetry — read
  openpenny's own logs / CLI on the analysis box for verdicts.
- Doesn't duplicate the logic in `tools/traffic_generator/`. If
  `client.py` / `spoofed_client.py` ever grow new flags, update
  `tools/traffic_generator/run.sh` (the wrapper); this script only
  touches `run.sh`.

## Use only on networks you own

The spoofed modes forge source IPs and disable the receiver's
return-path checks. Run them only on a lab segment you control. The
defaults point at RFC 5737 documentation space precisely so an
unconfigured run can't escape into production.
