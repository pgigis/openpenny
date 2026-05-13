# Scenario 3 — mixed (legit + spoofed, concurrent)

Both **legitimate iperf3** and a **spoofed flow** from **reeves1** toward
**reeves3**, on the same wire, started a few seconds apart. They form two
separate aggregates at **reeves2** (penny), each reaching its own
decision.

## Topology

```
                forward: legit iperf3  +  spoofed (forged src)
          ───────────────────────────────────────────────▶
 ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
 │   reeves1   │────│   reeves2   │────│   reeves3   │
 │   sender    │    │    penny    │    │  iperf3 -s  │
 │ iperf3 -c + │    │ two aggreg. │    │ + spoofed   │
 │ scapy spoof │    │ in parallel │    │ pkts die    │
 └─────────────┘    └─────────────┘    └─────────────┘
                          │
                          ▼
        aggregate reeves1     → reeves3  →  legitimate closed-loop
        aggregate forged_src  → reeves3  →  not closed-loop
```

## Run it

```bash
# reeves3 (start once, leave running)
iperf3 -s -p 5201

# reeves2 — penny in active mode against both prefixes
# reeves1
sudo -v                              # cache sudo for scapy
cd demo
SPOOFED_DST_IP=<reeves3-ip> \
SPOOFED_IFACE=<egress-iface> \
IPERF_SERVER=<reeves3> \
./demo_traffic.sh mixed
```

## Expected

On the penny pane: two `aggregates_decision_complete=1` events for two
distinct src→dst aggregates. The legit aggregate (`reeves1 → reeves3`)
fires first with **legitimate closed-loop**; the spoofed aggregate
(`forged_src → reeves3`) fires shortly after with **not closed-loop**.

Common overrides: `MIXED_STAGGER_SECS` (gap between legit and spoofed
start), `IPERF_PARALLEL`, `PACKET_RATE`. See `demo/README.md`.
