# Scenario 2 — spoofed (forged source IP)

Scapy-injected packets from **reeves1** with a **forged source IP**
(RFC 5737 default `198.51.100.10`), destined for **reeves3**. Penny on
**reeves2** sees no real TCP behaviour on the forward path; the aggregate
`forged_src → reeves3` decides **not closed-loop**.

## Topology

```
                    forward: spoofed packets, forged src
                    (penny observes this direction only)
          ───────────────────────────────────────────────▶
 ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
 │   reeves1   │────│   reeves2   │────│   reeves3   │
 │   sender    │    │    penny    │    │ no listener │
 │ scapy inject│    │ forward-only│    │ packets die │
 │ src=forged  │    │             │    │ here        │
 │ dst=reeves3 │    │             │    │             │
 └─────────────┘    └─────────────┘    └─────────────┘

         no reverse path: forged src can't respond
```

## Run it

```bash
# reeves3 — nothing to start (packets land and die)
# reeves2 — penny in active mode against the spoofed prefix
# reeves1
sudo -v                              # cache sudo for scapy
cd demo
SPOOFED_DST_IP=<reeves3-ip> \
SPOOFED_IFACE=<egress-iface> \
./demo_traffic.sh spoofed
```

## Expected

On the penny pane: `aggregates_decision_complete=1` for the
`forged_src → reeves3` aggregate, verdict **not closed-loop**. Constituent
flows resolve to `FINISHED_NOT_CLOSED_LOOP`. The test ends; the script
keeps injecting for the rest of `DURATION_SECONDS`.

Common overrides: `SPOOFED_IFACE`, `SPOOFED_SRC_IP`, `SPOOFED_DST_IP`,
`PACKET_RATE`. See `demo/README.md` for the full list.
