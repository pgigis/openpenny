# Configuration Examples

Copy-paste YAML for common setups. Two ideas to know:

- **Traffic policy** — which traffic OpenPenny touches.
- **Runtime policy** — what OpenPenny does with that traffic (active or
  passive, with thresholds).

Platform settings (interface, backend, queues) are kept separate so that
daily policy changes don't disturb host setup.

## Watch HTTP traffic, no drops

```yaml
traffic_policy:
  default: exclude
  rules:
    - name: observe-http
      decision: include
      protocol: tcp
      dst_port: 80

runtime_policy:
  mode: passive
  thresholds:
    passive_min_flows_to_finish: 10
    passive_max_parallel_flows: 10
    passive_max_execution_time_seconds: 150
```

Only TCP/80 flows are observed. Everything else is left alone.

## Active Penny test on HTTPS

```yaml
traffic_policy:
  default: exclude
  rules:
    - name: active-https
      decision: include
      protocol: tcp
      dst_port: 443

runtime_policy:
  mode: active
  thresholds:
    packet_drop_probability: 0.05
    max_duplicate_ratio: 0.15
    max_reordering_ratio: 0.8
    retransmission_observation_miss_rate: 0.05
    retransmission_timeout_multiplier: 3.0
    max_packet_drops_per_flow: 6
    max_packet_drops_global_aggregate: 12
    stop_after_individual_flows: 10
```

OpenPenny will drop a few packets per HTTPS flow and stop after 10 flows
have produced an outcome.

## Include a subnet but exclude SSH

```yaml
traffic_policy:
  default: exclude
  rules:
    - name: exclude-ssh
      priority: 10
      decision: exclude
      protocol: tcp
      dst_port: 22

    - name: include-service-subnet
      priority: 20
      decision: include
      src_prefix: 10.42.0.0/16
      protocol: tcp
```

Lower priority numbers are checked first, so SSH is excluded before the
broader include rule kicks in. Use `/32` for a single host.

## Keep SSH safe in active mode

```yaml
traffic_policy:
  default: include
  rules:
    - name: management-ssh
      priority: 1
      decision: exclude
      protocol: tcp
      dst_port: 22

runtime_policy:
  mode: active
  safety:
    allow_ssh_bypass: true
```

`allow_ssh_bypass: true` is a belt-and-braces flag: even if a rule slips,
SSH is never touched.

## Egress: where matched packets go

```yaml
egress:
  kind: tun           # one of: none, tun, raw_socket, raw_nic
  device: xdp-tun
  tun:
    multi_queue: true
    mtu: 9000
    txqlen: 10000
    bring_up: true
    rp_filter_loose: true   # set rp_filter=2 on the TUN at open time
```

| `kind`       | What it does                                                                          |
| ------------ | ------------------------------------------------------------------------------------- |
| `none`       | Drop matched packets after counting them. Good for measurement-only runs.             |
| `tun`        | Reinject packets into a TUN device (`device:`). The `tun.*` block applies here only.  |
| `raw_socket` | Send via `IPPROTO_RAW`. The kernel routes the packet and resolves the next-hop MAC.   |
| `raw_nic`    | Replay the original Ethernet frame via `AF_PACKET` bound to `device`, bypassing routing and neighbour resolution. |

`tun.rp_filter_loose: true` is usually needed: redirected packets keep
their original source IP, and the return route lives on the physical NIC,
so strict reverse-path filtering (`rp_filter=1`) silently drops them.
Setting `rp_filter=2` (loose) accepts them. Set it to `false` only if you
manage `rp_filter` yourself.

## Platform (host-specific)

Keep this in its own file so it doesn't change when policy does.

```yaml
platform:
  backend: af_xdp           # af_xdp (default), af_packet_mirror, dpdk
  ingress_mode: auto        # auto (default), copy, redirect
  interface: ens5f0np0
  queue: 0
  queue_count: 1
  worker_cpus: [0]
  xdp:
    drv_mode: true
    zerocopy: true
    require_zerocopy: true
    attach_program: true
    detach_on_close: true
    frame_size: 2048
    num_frames: 65536
    rx_ring: 4096
    batch: 512
    poll_timeout_ms: 0      # 0 = busy-poll (default); >0 = blocking poll
    bpf_object: xdp_redirect_openpenny.o
    bpf_program: xdp_redirect_openpenny
```

`worker_cpus` pins each queue worker to a CPU. With `queue_count: 1` the
default is one worker on one CPU.

### Copy vs redirect

Two ways to get packets into OpenPenny:

- `copy` — tap the interface via `AF_PACKET`. The kernel keeps delivering
  every packet to the real application; OpenPenny gets a copy. Safe for
  passive runs.
- `redirect` — the XDP program pulls matched packets out of the kernel
  into an AF_XDP socket. Required for active mode (we need to remove the
  packet before the app sees it).
- `auto` — passive → `copy`, active → `redirect`.

In `auto`, choosing `backend: af_xdp` with `mode: passive` is fine —
OpenPenny transparently switches to the `af_packet_mirror` backend
because redirect isn't needed.

## Splitting the config

You can keep policy and platform in separate files and pull them in from a
root config:

```yaml
log:
  mode: console
  level: info

includes:
  traffic_policy: policies/traffic_default.yaml
  runtime_policy: policies/runtime_active.yaml
  platform: platform/af_xdp.yaml
  egress: platform/egress_tun.yaml
  grpc: platform/grpc.yaml
```

Each include points to a smaller YAML with just that section. Includes
resolve relative to the root file. Anything written inline in the root
overrides the included file — handy for host-specific tweaks.
