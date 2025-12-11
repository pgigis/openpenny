# AF_XDP Zero-Copy Sampler — Print & Re-inject (Rocky-friendly)

Divert packets whose **source IPv4** matches a prefix into userspace via **AF_XDP (zero-copy)**, print a summary (and optional hexdump), then **TX them back** out the same NIC/queue. Non-matching traffic continues normally.

Repo files:
- `xdp_redirect_kern.c` — XDP program that redirects matching packets to an AF_XDP socket via `xsks_map` (per RX queue).
- `xsk_print_forward.cpp` — userspace C++ app: zero-copy RX → print → optional TX back.
- `Makefile` — builds both.
- `.gitignore` — ignores build artifacts.

> Want a *copy* while the original still flows? Use the ring-buffer sampler instead of AF_XDP.

---

## 0) Requirements (Rocky Linux 9)

Enable CRB (for `libbpf-devel`) and install tools:

```bash
sudo dnf config-manager --set-enabled crb || true
sudo dnf -y install clang llvm gcc g++ make pkgconf-pkg-config   elfutils-libelf-devel libbpf libbpf-devel bpftool ethtool
```

**NIC/driver:** needs native XDP + AF_XDP zero-copy support (e.g., `ice`, `ixgbe`, `i40e`, `mlx5`, `ena`).

```bash
IF=ens5f1np1   # set your interface
ethtool -i $IF
```

---

## 1) Build

```bash
make
```

Outputs:
- `xdp_redirect_kern.o`
- `xsk_print_forward`

---

## 2) One-time NIC prep (lab/testing)

```bash
IF=ens5f1np1  # change to your NIC
# Turn off offloads that interfere with predictable testing
sudo ethtool -K $IF gro off lro off gso off tso off rxvlan off txvlan off
# Ensure enough RX/TX queues (optional)
sudo ethtool -L $IF combined 4
sudo ip link set dev $IF up
```

---

## 3) Attach XDP (driver/native preferred)

> Correct iproute2 syntax uses `xdpdrv` (native) or `xdpgeneric` (skb). **Do not** use `flags drv`.

```bash
IF=ens5f1np1

# Native / driver mode (preferred for AF_XDP zero-copy)
sudo ip link set dev "$IF" xdpdrv obj xdp_redirect_kern.o sec xdp

# If that fails, try generic mode (will *not* be zero-copy):
sudo ip link set dev "$IF" xdpgeneric obj xdp_redirect_kern.o sec xdp
```

Verify attachment:
```bash
ip -details link show dev "$IF" | sed -n '/xdp/,+6p'
sudo bpftool prog show | grep -A2 xdp_redirect
```

Detach:
```bash
sudo ip link set dev "$IF" xdp off
```

---

## 4) Run userspace (zero-copy RX → print → TX back)

Pick a queue (e.g., `0`) and a source prefix (e.g., `192.168.41.0/24`):

```bash
IF=ens5f1np1
sudo ./xsk_print_forward   --if $IF --queue 0   --prefix 192.168.41.0 --mask 24   --hexdump 64          # optional: hex first 64 bytes
```

Behavior:
- Matching packets are delivered **zero-copy** to userspace.
- The app prints one line per packet and, by default, **TXes them back** on the same NIC/queue.

Useful flags:
- `--no-tx` — only print (drop instead of re-inject)
- `--batch N` — RX/TX batch size (default 64)
- `--hexdump B` — hex dump first `B` bytes

Stop with `Ctrl-C`.

---

## 5) Quick smoke test

From a host on the same L2/L3, send traffic **from** the matching prefix:

```bash
# Receiver anywhere reachable:
iperf3 -s

# Sender with source in 192.168.41.0/24 towards the receiver:
iperf3 -c <RECEIVER_IP> -t 5
```

You should see prints in `xsk_print_forward`. With `--no-tx`, the traffic won’t reach the receiver (AF_XDP consumes it).

---

## 6) Confirm zero-copy

```bash
# Driver stats often expose xdp/xsk/zc counters (driver-specific)
sudo ethtool -S $IF | egrep -i 'xdp|xsk|zc|af_xdp'
# General sanity:
sudo bpftool map show | grep -A3 xsks_map
```

If you’re in `xdpgeneric` mode, you’re not zero-copy. Re-attach with `xdpdrv` if your NIC supports it.

---

## 7) Common pitfalls & fixes

- **No packets in userspace**
  - XDP not attached: `ip -details link show $IF | sed -n '/xdp/,+6p'`
  - Wrong RX queue: try another `--queue` or steer flows (RSS/ethtool).
  - Another AF_XDP socket owns that queue.

- **Not zero-copy**
  - Driver doesn’t support ZC; you’re in copy mode. Use `xdpdrv` and a supported NIC.

- **Packets never reach destination**
  - Expected if using `--no-tx`. AF_XDP consumes frames unless you TX them back.

- **Performance**
  - Increase UMEM frames and batches in the app; pin CPU to the queue; disable deep C-states; isolate cores.

---

## 8) Cleanup

```bash
sudo ip link set dev $IF xdp off
sudo ethtool -K $IF gro on lro on gso on tso on rxvlan on txvlan on
```

---

## 9) Handy one-liners

```bash
# Build
make

# Attach native
IF=ens5f1np1
sudo ip link set dev "$IF" xdpdrv obj xdp_redirect_kern.o sec xdp

# Run userspace
sudo ./xsk_print_forward --if "$IF" --queue 0 --prefix 192.168.41.0 --mask 24 --hexdump 64

# Detach
sudo ip link set dev "$IF" xdp off
```

---

## 10) Notes & Safety

- Re-injecting (`TX`) can create loops if you bridge/route elsewhere. Use an isolated test link or know your path.
- To redirect to a **different** interface, use a **devmap** and `bpf_redirect_map()` (outside the scope of this AF_XDP sample).

---

## 11) File References

- `xdp_redirect_kern.c` — loads prefix/mask from a config map and redirects matching IPv4 sources to `xsks_map[rx_queue_index]`.
- `xsk_print_forward.cpp` — binds an AF_XDP socket to the selected interface/queue, receives frames zero-copy, prints summaries/hexdumps, and TXes them back.

Happy hacking!
