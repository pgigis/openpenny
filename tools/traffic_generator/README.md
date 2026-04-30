# Traffic Generator

Lab tooling for poking at openpenny: a tiny TCP echo pair, a Scapy-based
spoofed-flow injector, and a mixed (iperf3 + spoofed) driver. Scripts can be
called directly, but the `run.sh` wrapper and the `Makefile` cover the common
cases without having to remember every flag.

## Files at a glance

| File | What it does |
| --- | --- |
| `server.py` | Listens on host/port and prints received bytes. |
| `client.py` | Connects to a server and sends a line every second. |
| `spoofed_client.py` | Crafts TCP flows (SYN → DATA → FIN) with Scapy. Supports L2 (`sendp()`) and L3-routed (`IP_HDRINCL`) modes, with pacing, jitter, duplication, and now a `--preflight` diagnostic mode. |
| `mixed_traffic.py` | Runs iperf3 plus spoofed flows in parallel. |
| `preflight.py` | Read-only diagnostics: rp_filter, route lookup, ARP, firewall rules, common foot-guns. Importable or runnable on its own. |
| `run.sh` | Friendly wrapper with subcommands and a single source of truth for the venv + sudo. |
| `Makefile` | `make spoof IFACE=… DEST_IP=… SRC_IP=…` style shortcuts. |

## Install

```bash
./run.sh install         # creates ./.venv and installs scapy
# or
make install
```

Anything that needs raw sockets (`spoofed_client.py`, `preflight.py`) re-execs
itself under `sudo` with the venv's Python so Scapy stays importable.

## Quick start

```bash
# Terminal 1: catch payloads
./run.sh server 9000

# Terminal 2: simple TCP client (no spoofing)
./run.sh client 127.0.0.1 9000

# Terminal 3: 1 spoofed flow, routed via the kernel, with built-in preflight
./run.sh spoof ens5f0np0 192.0.2.10 9000 198.51.100.10
```

Extra flags after the positional arguments are forwarded to the underlying
Python script:

```bash
./run.sh spoof ens5f0np0 192.168.43.3 5201 198.51.100.10 \
    --flows 10 --count 150 --payload-size 64 --debug
```

## Make targets

```bash
make doctor   IFACE=ens5f0np0 DEST_IP=192.168.43.3 SRC_IP=198.51.100.10
make spoof    IFACE=ens5f0np0 DEST_IP=192.168.43.3 DEST_PORT=5201 SRC_IP=198.51.100.10 \
              FLOWS=10 COUNT=150 PAYLOAD=64
make spoof-l2 IFACE=ens5f0np0 DST_MAC=aa:bb:cc:dd:ee:ff \
              DEST_IP=192.0.2.10 DEST_PORT=9000 SRC_IP=198.51.100.10
make mixed    IFACE=ens5f0np0 IPERF_SERVER=192.0.2.20 \
              DEST_IP=198.51.100.20 SRC_IP=198.51.100.10
```

## Calling the Python scripts directly

The wrapper just invokes these — the underlying CLI hasn't changed.

L2 inject (default, fastest path):

```bash
sudo python3 spoofed_client.py \
    --iface ens5f0np0 --dst-mac ff:ff:ff:ff:ff:ff \
    --dest-ip 192.0.2.10 --dest-port 9000 \
    --src-ip 198.51.100.10 \
    --flows 3 --count 20 --payload-size 64 --preflight
```

Routed mode (kernel decides the next hop, applies its own filters):

```bash
sudo python3 spoofed_client.py \
    --iface ens5f0np0 --routed \
    --dest-ip 192.168.43.3 --dest-port 5201 \
    --src-ip 198.51.100.10 \
    --flows 10 --count 150 --payload-size 64 --preflight
```

Diagnose-only (no traffic generated):

```bash
sudo python3 preflight.py --iface ens5f0np0 \
    --dest-ip 192.168.43.3 --src-ip 198.51.100.10 --routed
# or:
sudo python3 spoofed_client.py ... --preflight-only
```

## Mixed traffic (iperf + spoofed)

```bash
python3 mixed_traffic.py \
    --iface ens5f0np0 --dst-mac ff:ff:ff:ff:ff:ff \
    --iperf-server 192.0.2.20 --iperf-port 5201 \
    --iperf-parallel 4 --iperf-duration 30 \
    --spoof-dest-ip 198.51.100.20 --spoof-dest-port 9000 \
    --spoof-src-ip 198.51.100.10 \
    --spoof-flows 2 --spoof-count 15 --spoof-payload 64 \
    --spoof-interval 0.02 --spoof-jitter 0.01 --spoof-dup-prob 0.1
```

## Troubleshooting: spoofed traffic never arrives

If a command like

```bash
sudo python3 spoofed_client.py \
    --iface ens5f0np0 --routed \
    --dest-ip 192.168.43.3 --dest-port 5201 \
    --src-ip 198.51.100.10 \
    --flows 10 --count 150 --payload-size 64
```

returns success on the sender but the receiver application sees nothing,
the packet is being dropped somewhere along the path. Run

```bash
sudo python3 preflight.py --iface ens5f0np0 \
    --dest-ip 192.168.43.3 --src-ip 198.51.100.10 --routed
```

then walk through the checklist below. The first three causes account for
the vast majority of "spoofed traffic disappears" reports.

### 1. Reverse-path filter on the receiver (most common)

Linux's `rp_filter` drops incoming packets whose source IP is not reachable
through the arrival interface. With `--src-ip 198.51.100.10` (TEST-NET-2) the
receiver has no return route, so strict mode silently drops every packet on
arrival. Confirm on the **receiver**:

```bash
sysctl net.ipv4.conf.all.rp_filter \
       net.ipv4.conf.default.rp_filter \
       net.ipv4.conf.<iface>.rp_filter
```

Fix one of two ways:

```bash
# (a) loose mode: accept the packet if any interface has a route back
sudo sysctl -w net.ipv4.conf.all.rp_filter=2
sudo sysctl -w net.ipv4.conf.<iface>.rp_filter=2

# (b) install a return route and keep strict mode
sudo ip route add 198.51.100.0/24 dev <iface>
```

To prove the packet is at least making it onto the wire, run on the receiver:

```bash
sudo tcpdump -ni <iface> "src host 198.51.100.10 and dst host 192.168.43.3"
```

If `tcpdump` shows the packets but the application doesn't, you're hitting
rp_filter (or a netfilter rule — see below).

### 2. Reverse-path filter / OUTPUT chain on the sender

The sender can drop its own egress. Same check on the sending host:

```bash
sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.<iface>.rp_filter
sudo nft list ruleset           # or: sudo iptables -S OUTPUT
```

If the OUTPUT chain has DROP/REJECT rules that match `198.51.100.0/24` (e.g.
firewalld's "drop bogons" zone), the packet never leaves the host. Counter
to verify:

```bash
sudo iptables -nvL OUTPUT     # watch the pkts/bytes columns increment
```

### 3. BCP38 / source-address validation on the upstream router

Most production gateways drop packets whose source isn't in the prefix the
sender belongs to. There's nothing you can do from the sender — either use
a source IP that's actually allocated to the lab, or run sender and receiver
on the same L2 segment so the gateway is bypassed.

### 4. ARP/neighbour resolution dropped the first packet

With `--routed`, the kernel triggers ARP for the next hop on the first
packet. While ARP resolves the kernel queues 1–2 packets and discards the
rest. If your flow has `--count 150` but the first ~5 packets disappear,
this is why. Pre-warm the neighbour:

```bash
ping -c 1 -I <iface> <next-hop-ip>
```

`preflight.py` warns when it can't find a `REACHABLE`/`STALE` entry for the
next hop.

### 5. Receiver listens but the segment is invalid

Even if the packet reaches the application's interface, the kernel only
hands it to a TCP socket if:

- the destination MAC is unicast to that NIC (broadcast TCP frames are
  ignored — see `--dst-mac` warnings below), and
- the TCP checksum is valid, and
- a socket is actually `LISTEN`ing on `dest_port`, and
- the segment isn't blocked by `nftables INPUT` (e.g. `conntrack invalid`).

A quick `ss -ltn 'sport = :5201'` on the receiver tells you whether anything
is listening, and `nstat -az TcpExt | grep -i invalid` reveals
checksum/conntrack drops.

### 6. L2-mode foot-gun: broadcast destination MAC

`--dst-mac ff:ff:ff:ff:ff:ff` (the script's default) is fine for forcing
packets onto a wire so an XDP program can intercept them, but a vanilla
Linux receiver will drop them — TCP only accepts unicast frames. If you
want the destination's TCP stack to actually see the packet, set the real
MAC:

```bash
ip neigh show <receiver-ip>      # find its MAC
./run.sh spoof-l2 ens5f0np0 aa:bb:cc:dd:ee:ff 192.0.2.10 9000 198.51.100.10
```

### 7. NIC features eating the packet

A few NIC quirks worth knowing:

- LRO/GRO can coalesce DUP-ACKs and identical SEQ frames; if the
  duplication test feels broken, try `ethtool -K <iface> gro off lro off`.
- Some drivers (mlx5, ena) refuse to transmit Ethernet frames whose source
  MAC is not the device's own. Leave the source MAC unset (Scapy fills in
  the device MAC) or set it explicitly to the device MAC.
- Hardware TSO won't kick in for raw socket traffic, but a few drivers
  reject odd-length frames; use a payload size ≥ 14 to be safe.

### Confirming what actually leaves the host

Whatever the suspicion, the cheapest signal is a packet capture on both
ends:

```bash
# Sender
sudo tcpdump -ni <iface> "host 198.51.100.10" -w /tmp/sender.pcap
# Receiver
sudo tcpdump -ni <iface> "host 198.51.100.10" -w /tmp/receiver.pcap
```

If the sender pcap shows the flow but the receiver pcap doesn't, blame the
network (BCP38, switch ACLs, MAC filtering). If both pcaps show the flow
but the application is silent, blame the receiver's stack (rp_filter,
firewall, no listener, invalid checksum).

## Using with openpenny CLI

```bash
# Receiver: capture payloads
python3 server.py --host 0.0.0.0 --port 9000

# openpenny in active mode on the receiver
sudo ./build/openpenny_cli \
    --config examples/configs/config_default.yaml \
    --mode active \
    --prefix 198.51.100.0 --mask-bits 24 \
    --iface ens5f0np0 --queue 0 --tun xdp-tun

# Sender: spoofed traffic toward the receiver
./run.sh spoof ens5f0np0 198.51.100.20 9000 198.51.100.10 --flows 2 --count 15
```

Watch openpenny logs for drops/duplicates/retransmissions and the server
output for received payloads. Adjust `--prefix`/`--mask-bits` to filter to
your spoofed subnet.

## Requirements

- Python 3.8+
- `scapy` (installed via `./run.sh install` or `pip install -r requirements.txt`)
- `iperf3` for `mixed_traffic.py`
- Root / `CAP_NET_RAW` for anything that opens raw sockets
- Linux iproute2 (`ip`, `nft`/`iptables`) for the preflight checks
