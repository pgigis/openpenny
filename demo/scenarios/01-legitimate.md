# Scenario 1 — legitimate (16-way iperf3)

16 parallel TCP streams from **reeves1** → **reeves3**. Penny on
**reeves2** should call the aggregate **legitimate closed-loop** within a
few seconds and end the test for that aggregate. iperf3 keeps saturating
the link for the full duration.

## Topology

```
                      forward: 16 parallel TCP streams
                      (penny observes this direction only)
          ───────────────────────────────────────────────▶
 ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
 │   reeves1   │────│   reeves2   │────│   reeves3   │
 │   sender    │    │    penny    │    │   receiver  │
 │ iperf3 -c   │    │ forward-only│    │ iperf3 -s   │
 │ -P 16 -t 30 │    │             │    │ -p 5201     │
 └─────────────┘    └─────────────┘    └─────────────┘
                                              │
        reverse ACKs (out of scope)           │
          ◀── ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
```

## Run it

```bash
# reeves3 (start once, leave running)
iperf3 -s -p 5201

# reeves2 — penny in active mode against the reeves1 aggregate
# (see tools/traffic_generator/README.md § Using with openpenny CLI)

# reeves1
cd demo
./demo_traffic.sh legitimate
```

## Expected

On the penny pane: `aggregates_decision_state` flips to `completed`,
`aggregates_decision_complete=1`, aggregate verdict is **legitimate
closed-loop**. Fires within a few seconds; iperf3 continues to saturate
for the rest of `-t 30`. That contrast is the point.

Common overrides: `IPERF_SERVER`, `IPERF_PORT`, `IPERF_PARALLEL`,
`IPERF_DURATION`. See `demo/README.md` for the full list.
