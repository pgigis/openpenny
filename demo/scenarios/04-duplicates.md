# Scenario 4 — duplicates (duplicate-heavy spoofed flow)

Scapy-injected spoofed flow from **reeves1** with a high duplicate
probability (default `0.5`), destined for **reeves3**. Lots of identical
seq/ack packets cross **reeves2** (penny); the aggregate exits via the
**duplicate-exceeded** path rather than the closed-loop check.

## Topology

```
                forward: spoofed flow + heavy duplicates
                (same seq/ack, repeated)
          ───────────────────────────────────────────────▶
 ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
 │   reeves1   │────│   reeves2   │────│   reeves3   │
 │   sender    │    │    penny    │    │ no listener │
 │ scapy inject│    │ duplicate-  │    │ packets die │
 │ dup-prob 0.5│    │ heavy traf. │    │ here        │
 └─────────────┘    └─────────────┘    └─────────────┘
                          │
                          ▼
                aggregate duplicate fraction
                exceeds threshold → "duplicate exceeded"
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
DUPLICATE_RATE=0.5 \
./demo_traffic.sh duplicates
```

## Expected

On the penny pane: `aggregates_decision_complete=1` for the
`forged_src → reeves3` aggregate, this time via the duplicate path.
Constituent flows resolve to `FINISHED_DUPLICATE_EXCEEDED`. The test ends
for that aggregate; injection continues for the rest of `DURATION_SECONDS`.

Common overrides: `DUPLICATE_RATE` (0.0–1.0), `PACKET_RATE`,
`SPOOFED_IFACE`. See `demo/README.md`.
