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

## Run it (CLI)

```bash
# reeves3 (start once, leave running)
iperf3 -s -p 5201

# reeves2 — penny
sudo ./build/openpenny_cli \
  -c examples/configs/config_default.yaml \
  --source xdp --iface ens5f0np0 --queues 1

# reeves1
cd demo
./demo_traffic.sh legitimate
```

## Run it (gRPC)

Replace the CLI invocation on reeves2 with the daemon plus a one-shot
client:

```bash
# reeves2
sudo ./build/pennyd \
  --config examples/configs/config_default.yaml \
  --listen 0.0.0.0:50051 \
  --worker-bin ./build/penny_worker

# reeves2 (separately)
python3 demo/scenarios/grpc/demo_call.py
```

## Expected

On the penny pane: `aggregates_decision_state` flips to `completed`,
`aggregates_decision_complete=1`, aggregate verdict is **legitimate
closed-loop**. Fires within a few seconds; iperf3 continues to saturate
for the rest of `-t 30`. That contrast is the point.

Common overrides: `IPERF_SERVER`, `IPERF_PORT`, `IPERF_PARALLEL`,
`IPERF_DURATION`. See `demo/README.md` for the full list.
