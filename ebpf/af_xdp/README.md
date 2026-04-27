# OpenPenny AF_XDP eBPF Program

This directory contains the XDP/eBPF program used by the OpenPenny AF_XDP
runtime. The CLI, daemon, and worker load `xdp_redirect_openpenny.o`, attach it
to the configured interface, then program its maps at runtime.

Files:

- `xdp_redirect_openpenny.c` - kernel-side XDP program.
- `Makefile` - builds only `xdp_redirect_openpenny.o`.

Standalone AF_XDP diagnostic helpers, including `xsk_print_forward`, live in
`../../tools/af_xdp/`.

## Build

From the repository root:

```bash
cmake --build build --target xdp_bpf
# or:
make -C ebpf/af_xdp xdp_redirect_openpenny.o
```

The CLI also attempts this build automatically if the object is missing.

## Runtime Maps

OpenPenny programs three maps after loading the object:

- `conf` - one match rule at key 0.
- `settings` - rule count, safety flags, default action, and default queue id.
- `xsks_map` - queue id to AF_XDP socket fd.

On initial attach OpenPenny writes pass-only defaults before redirect rules are
published, so the default startup behavior is `XDP_PASS`.

The `counters` map also records whether a redirect found a live `xsks_map`
entry:

- `queue_mismatch` - the redirect target queue did not match the packet's RX
  queue, so XDP passed the packet instead of attempting an invalid AF_XDP
  cross-queue redirect.
- `xsk_hit` - the target queue had an AF_XDP socket entry at XDP time.
- `xsk_miss` - no AF_XDP socket entry existed for the target queue, so traffic
  fell back to `XDP_PASS`.

When a rule redirects without an explicit target queue, the XDP program uses
the packet's RX queue id. That lets OpenPenny open AF_XDP sockets on multiple
queues and rely on NIC RSS to split matching traffic across them.

## Match Rules

The AF_XDP eBPF path currently supports one runtime rule. That rule matches
optional 5-tuple fields:

- `src_ip` as a CIDR prefix, for example `10.0.0.0/24`.
- `dst_ip` as a CIDR prefix, for example `192.0.2.20/32`.
- `protocol`, usually `tcp`, `udp`, or `icmp`.
- `src_port`.
- `dst_port`.

Any omitted field is a wildcard. A single IP is represented as `/32`; config
parsing also treats a bare IPv4 address as `/32`.

Example:

```yaml
input_sources:
  traffic_match:
    default_action: pass
    rules:
      - label: web-slice
        src_ip: 10.0.0.0/24
        dst_ip: 192.0.2.20/32
        protocol: tcp
        dst_port: 443
        action: redirect
```

The userspace encoder for these rules is
`src/ingress/af_xdp/XdpRuleController.cpp`; keep its BPF struct layout in sync
with `xdp_redirect_openpenny.c`.
