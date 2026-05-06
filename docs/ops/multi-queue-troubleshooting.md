# Multi-queue AF_XDP troubleshooting

Multi-queue AF_XDP (`--queues N` with N > 1) needs a few host-level
settings to work well. Use this page when running with fan-out, or
when you see `processed=0` in the summary while the kernel
`[xdp_counters]` line shows non-zero `xsk_hit`.

## Sizing rule of thumb

Match `--queues` to the number of active TCP flows you expect, not to
your core count. RSS hashes each flow to one queue, so spawning more
workers than active flows wastes CPU on busy-poll spinners that never
see traffic. For a single-stream test (`iperf3 -P 1`) use
`--queues 1`; for `iperf3 -P 8` use `--queues 8`. Configure RSS to
steer to exactly the served queues (see section 4 below).

The symptom looks like this:

```
[xdp_counters] seen=5616416 ipv4=5616394 match=5616355 nomatch=1
               redirect=5606877 xsk_hit=5606877 xsk_miss=9478
               queue_mismatch=0 pass=23 ssh_pass=38
[xdp_userspace] rx=0 decode_fail=0 peek_zero=165256639 poll_calls=165256669
               (kernel xsk_hit=5606877)
```

`xsk_hit` is incremented **before** `bpf_redirect_map` runs in the BPF
program — it only proves a socket was registered at `xsks_map[qid]`.
The actual redirect into the AF_XDP socket's RX ring can still fail
silently inside the kernel, and that's exactly what this symptom is.

## What to check, in order

### 1. Wrong-queue bind (fail-fast)

After every successful `xsk_socket__create()`, OpenPenny calls
`getsockname()` to ask the kernel which queue the socket is actually
bound to. If the kernel reports a different queue id than the one we
asked for, the worker now refuses to start and prints:

```
[xdp_bind] queue=N: SOCKET BOUND TO WRONG QUEUE! Asked for queue N but
kernel bound to queue M. Refusing to continue.
```

If you see this line, **stop here**. The bind layer (libxdp, libbpf,
or the kernel) is binding to a different queue than requested. This is
the cleanest possible explanation for "kernel xsk_hit but userspace
rx=0" — `bpf_redirect_map(xsks_map, N, ...)` will route the packet to
a socket bound to queue M ≠ N, the kernel rejects with `-EOPNOTSUPP`,
and the packet is silently dropped. Capture `uname -a`,
`ldconfig -p | grep xdp`, and the libxdp/libbpf versions and file an
issue.

### 2. Bind-mode heterogeneity

Re-run with `--log-level debug` and look for:

```
[xdp_bind] heterogeneous bind modes detected: 1 queue(s) in zerocopy, 62 in copy.
```

If you see this line, the kernel granted zerocopy on some queues and
silently downgraded others to copy. The attached XDP program runs in
DRV (zerocopy) mode, and redirects to copy-mode sockets are dropped by
the kernel without surfacing a counter.

Fix: ensure the driver has enough combined channels for every served
queue.

```bash
# Check current channel counts
ethtool -l <iface>

# Set combined channels to match --queues
sudo ethtool -L <iface> combined <queue_count>
```

For Mellanox ConnectX (mlx5), `combined` channels are the right knob.
For Intel ice/i40e the same command works.

### 3. RSS coverage

OpenPenny prints an `[rss_check]` line at startup. If RSS routes to
queues you aren't serving, packets land where there is no AF_XDP
socket and pass through to the kernel:

```
[rss_check] <iface>: RSS routes to queues {0,1,2,...,62} but OpenPenny
            only serves {0}. Approximately 62 of every 63 matched
            packets will hit xsk_miss.
```

Fix: restrict RSS to the served queues.

```bash
# Steer all matched traffic to queue 0 only
sudo ethtool -X <iface> weight 1 0 0 0 ...
```

### 4. Stale BPF pins

If `/sys/fs/bpf/openpenny_*` exists from a previous run (especially
after a crash or `kill -9`), OpenPenny prints:

```
[openpenny] note: pre-existing BPF pins detected under /sys/fs/bpf/openpenny_*.
```

Fix:

```bash
sudo python3 scripts/xdp_attach.py --iface <iface> --mode drv --detach
sudo rm -rf /sys/fs/bpf/openpenny*
```

### 5. Queue over-subscription

If you ask for more queues than the NIC has, the CLI clamps and warns:

```
[openpenny] warning: requested queues 0-62 exceed <iface>'s RX queue
            count (16). Clamping queue_count to 16 ...
```

If you see the clamp, the actual `--queues` used is the clamped value.

### 6. Use `--queues 1` with RSS as a known-good baseline

If a multi-queue run is misbehaving, fall back to single-queue + RSS
steered at one queue to confirm the rest of the pipeline is healthy:

```bash
# Steer matched traffic to queue 0
sudo ethtool -X <iface> weight 1 0 0 0 ...

# Run with one worker
sudo ./build/openpenny_cli --config examples/configs/config_default.yaml \
    --mode active --iface <iface> --queues 1
```

If this shows `processed > 0`, the kernel + AF_XDP stack works on
your machine. The multi-queue failure is then in the multi-queue
binding path itself.

## Useful kernel-side commands

```bash
# Programs attached to the netdev
sudo bpftool net show dev <iface>

# xsks_map contents (should have one entry per served queue)
sudo bpftool map dump pinned /sys/fs/bpf/openpenny_xsks

# Per-CPU XDP statistics from the netdev
sudo ethtool -S <iface> | grep -i xdp

# Channel configuration
sudo ethtool -l <iface>
sudo ethtool -x <iface>
```

## Known driver gotchas

- **mlx5** (Mellanox ConnectX): AF_XDP zerocopy requires combined
  channels equal to (or greater than) the number of queues you want to
  serve. The default channel count is often the number of CPUs.
- **i40e / ice** (Intel): zerocopy supported; same combined-channel
  rule.
- **virtio-net**: no zerocopy; copy mode only. With multi-queue this
  will produce the heterogeneous-bind warning above.
- **Generic / SKB mode** (`--xdp-mode generic`): copy mode for all
  queues; not affected by the bind-mode mismatch but slower.
