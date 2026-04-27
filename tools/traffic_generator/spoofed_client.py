#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause

"""Send crafted TCP packets that form minimal, increasing sequence number flows.

This version supports multiple concurrent spoofed flows, asynchronous sending,
and several tunable options for shaping and duplicating packets.

Each flow has the structure:
    SYN -> N × DATA (PSH,ACK) -> FIN

Packets are injected at layer 2 using sendp(), with an explicit destination
MAC address. This avoids ARP lookups and routing-dependent behaviour, which
can introduce large delays in lab or spoofed setups.

When --interval and --interval-jitter are both 0, each flow builds a full
packet train and sends it in a single sendp() call for maximum throughput.
"""

import argparse
import asyncio
import os
import random
import sys
from dataclasses import dataclass
from typing import List, Optional

from scapy.all import IP, TCP, Raw, Ether, sendp  # type: ignore


@dataclass
class FlowParams:
    """Per-flow parameters derived from CLI options."""
    flow_id: int
    src_ip: Optional[str]
    src_port: int
    dest_ip: str
    dest_port: int
    payload: bytes
    data_packets: int
    initial_seq: int
    initial_ack: int

    # Cached Scapy layers to avoid rebuilding them per packet.
    ip_layer: Optional[IP] = None
    payload_layer: Optional[Raw] = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Generate one or more spoofed TCP flows with predictable sequence "
            "number growth, optionally with random duplicates."
        )
    )

    # Target destination for the IPv4 flow.
    parser.add_argument("--dest-ip", required=True, help="Destination IPv4 address.")
    parser.add_argument("--dest-port", type=int, required=True, help="Destination TCP port.")

    # Spoofed source attributes.
    parser.add_argument(
        "--src-ip",
        default=None,
        help="Spoofed source IPv4 address (default: use the host's outbound address).",
    )
    parser.add_argument(
        "--src-port",
        type=int,
        default=None,
        help=(
            "Base TCP source port. If not set, a random high port is chosen "
            "per flow."
        ),
    )
    parser.add_argument(
        "--increment-src-port",
        action="store_true",
        help=(
            "When used with --src-port, each flow uses src-port + flow_id as the "
            "source port, instead of reusing the same port."
        ),
    )

    # Flow multiplicity and shape.
    parser.add_argument(
        "--flows",
        type=int,
        default=1,
        help="Number of independent spoofed flows to generate in parallel (default: 1).",
    )
    parser.add_argument(
        "--count",
        type=int,
        required=True,
        help="Number of data packets to send after the SYN for each flow.",
    )
    parser.add_argument(
        "--payload-size",
        type=int,
        default=48,
        help="Size of the Raw payload (bytes) in each data packet.",
    )

    # Timing and pacing.
    parser.add_argument(
        "--interval",
        type=float,
        default=0.0,
        help="Base delay between packets within a flow, in seconds (default: no pacing).",
    )
    parser.add_argument(
        "--interval-jitter",
        type=float,
        default=0.0,
        help=(
            "Maximum absolute jitter to add to --interval per packet (uniform in "
            "[-jitter, +jitter]). Useful for avoiding perfectly periodic trains."
        ),
    )
    parser.add_argument(
        "--flow-start-interval",
        type=float,
        default=0.0,
        help=(
            "Stagger start time between consecutive flows in seconds "
            "(flow i starts at i * flow-start-interval)."
        ),
    )

    # Link-layer parameters.
    parser.add_argument(
        "--iface",
        required=True,
        help="Egress interface to inject packets from (e.g., ens5f1np1).",
    )
    parser.add_argument(
        "--dst-mac",
        default="ff:ff:ff:ff:ff:ff",
        help="Destination MAC address for the Ethernet header (default: broadcast).",
    )

    # Random duplication / randomness controls.
    parser.add_argument(
        "--duplication-prob",
        type=float,
        default=0.0,
        help=(
            "Probability in [0.0, 1.0] that a DATA packet will be immediately "
            "duplicated (same SEQ, same payload). Default: 0.0 (no duplicates)."
        ),
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional PRNG seed for reproducible flows and duplication patterns.",
    )

    # Debug output control.
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print a one-line summary for each crafted packet.",
    )

    return parser.parse_args()


def clamp_args(args: argparse.Namespace) -> None:
    """Clamp configuration values to safe ranges in-place."""
    if args.flows < 1:
        print("[spoofed_client] --flows must be >= 1, clamping to 1", file=sys.stderr)
        args.flows = 1

    if args.count < 0:
        print("[spoofed_client] --count must be >= 0, clamping to 0", file=sys.stderr)
        args.count = 0

    if args.payload_size < 0:
        print("[spoofed_client] --payload-size must be >= 0, clamping to 0", file=sys.stderr)
        args.payload_size = 0

    if args.interval < 0.0:
        print("[spoofed_client] --interval must be >= 0, clamping to 0.0", file=sys.stderr)
        args.interval = 0.0

    if args.interval_jitter < 0.0:
        print(
            "[spoofed_client] --interval-jitter must be >= 0, clamping to 0.0",
            file=sys.stderr,
        )
        args.interval_jitter = 0.0

    if args.flow_start_interval < 0.0:
        print(
            "[spoofed_client] --flow-start-interval must be >= 0, clamping to 0.0",
            file=sys.stderr,
        )
        args.flow_start_interval = 0.0

    if not (0.0 <= args.duplication_prob <= 1.0):
        print(
            "[spoofed_client] --duplication-prob must be in [0.0, 1.0], clamping to range",
            file=sys.stderr,
        )
        args.duplication_prob = min(max(args.duplication_prob, 0.0), 1.0)


def build_flow_params_list(args: argparse.Namespace, rng: random.Random) -> List[FlowParams]:
    """Derive per-flow parameters from command-line arguments and cache per-flow layers."""
    payload = b"X" * args.payload_size
    flow_params: List[FlowParams] = []

    for flow_id in range(args.flows):
        # Choose source port: explicit base or random ephemeral-like port per flow.
        if args.src_port is not None:
            if args.increment_src_port:
                sport = args.src_port + flow_id
            else:
                sport = args.src_port
        else:
            sport = rng.randint(1024, 65535)

        # Random initial sequence and acknowledgement numbers per flow.
        seq_base = rng.randint(0, 2**32 - 1)
        ack_base = rng.randint(0, 2**32 - 1)

        # Prebuild IP and payload layers for this flow to avoid recreating them.
        ip_layer = IP(dst=args.dest_ip)
        if args.src_ip:
            ip_layer.src = args.src_ip

        payload_layer = Raw(payload)

        params = FlowParams(
            flow_id=flow_id,
            src_ip=args.src_ip,
            src_port=sport,
            dest_ip=args.dest_ip,
            dest_port=args.dest_port,
            payload=payload,
            data_packets=args.count,
            initial_seq=seq_base,
            initial_ack=ack_base,
            ip_layer=ip_layer,
            payload_layer=payload_layer,
        )
        flow_params.append(params)

    return flow_params


def build_syn_packet(flow: FlowParams, eth_layer: Ether):
    """Create the SYN packet for a flow."""
    ip_layer = flow.ip_layer or IP(dst=flow.dest_ip, src=flow.src_ip)  # fallback if needed

    syn_tcp = TCP(
        sport=flow.src_port,
        dport=flow.dest_port,
        flags="S",
        seq=flow.initial_seq,
        window=64240,
    )
    syn_pkt = eth_layer / ip_layer / syn_tcp
    return syn_pkt


def build_data_packets(
    flow: FlowParams,
    eth_layer: Ether,
    rng: random.Random,
    duplication_prob: float,
):
    """Create the DATA packets (and optional duplicates) for a flow.

    The sequence number advances monotonically by len(payload) for each *original*
    data packet. Duplicates reuse the same SEQ and thus do not consume sequence space.
    """
    ip_layer = flow.ip_layer or IP(dst=flow.dest_ip, src=flow.src_ip)
    payload_layer = flow.payload_layer or Raw(flow.payload)

    packets: List = []

    # After the SYN, the next byte position in the sequence space is +1.
    seq = (flow.initial_seq + 1) & 0xFFFFFFFF

    # Base TCP header reused across packets; we only change 'seq'.
    base_tcp = TCP(
        sport=flow.src_port,
        dport=flow.dest_port,
        flags="PA",  # PSH + ACK
        ack=flow.initial_ack,
        window=64240,
    )

    for _ in range(flow.data_packets):
        tcp_layer = base_tcp.copy()
        tcp_layer.seq = seq

        pkt = eth_layer / ip_layer / tcp_layer / payload_layer
        packets.append(pkt)

        # Optionally enqueue a duplicate with the same SEQ and payload.
        if duplication_prob > 0.0 and rng.random() < duplication_prob:
            dup_tcp = tcp_layer  # same header, same seq
            dup_pkt = eth_layer / ip_layer / dup_tcp / payload_layer
            packets.append(dup_pkt)

        # Advance the sequence position by the number of payload bytes
        # (only originals advance SEQ).
        seq = (seq + len(flow.payload)) & 0xFFFFFFFF

    return packets, seq


def build_fin_packet(flow: FlowParams, eth_layer: Ether, final_seq: int):
    """Create the FIN packet for a flow.

    The FIN consumes one additional sequence number.
    """
    ip_layer = flow.ip_layer or IP(dst=flow.dest_ip, src=flow.src_ip)

    fin_tcp = TCP(
        sport=flow.src_port,
        dport=flow.dest_port,
        flags="FA",  # FIN + ACK
        seq=final_seq,
        ack=flow.initial_ack,
        window=64240,
    )
    fin_pkt = eth_layer / ip_layer / fin_tcp
    return fin_pkt


def build_full_flow_packets(
    flow: FlowParams,
    eth_layer: Ether,
    rng: random.Random,
    duplication_prob: float,
):
    """Build the full packet train (SYN, DATA [+dup], FIN) for a flow.

    Used when we want to blast packets as fast as possible with a single
    sendp() call (no per-packet pacing).
    """
    packets = []

    # SYN
    syn_pkt = build_syn_packet(flow, eth_layer)
    packets.append(syn_pkt)

    # DATA (+ optional duplicates)
    data_packets, final_seq_before_fin = build_data_packets(
        flow, eth_layer, rng, duplication_prob
    )
    packets.extend(data_packets)

    # FIN
    fin_seq = final_seq_before_fin & 0xFFFFFFFF
    fin_pkt = build_fin_packet(flow, eth_layer, fin_seq)
    packets.append(fin_pkt)

    return packets


async def send_flow(
    flow: FlowParams,
    eth_layer: Ether,
    iface: str,
    base_interval: float,
    interval_jitter: float,
    duplication_prob: float,
    start_delay: float,
    rng: random.Random,
    debug: bool,
) -> None:
    """Asynchronously send a single spoofed TCP flow.

    If base_interval == interval_jitter == 0, we build the entire packet
    train and send it in one sendp() call for maximum throughput.

    Otherwise, we fall back to the slower per-packet pacing loop.
    """
    # Independent RNG for this flow (still reproducible under --seed).
    flow_rng = random.Random(rng.random())

    if start_delay > 0.0:
        await asyncio.sleep(start_delay)

    eth = eth_layer  # For clarity / potential future per-flow customisation.

    # --- FAST PATH: no pacing, blast everything in one sendp() ---
    if base_interval == 0.0 and interval_jitter == 0.0:
        packets = build_full_flow_packets(flow, eth, flow_rng, duplication_prob)

        if debug:
            print(f"[DEBUG][flow={flow.flow_id}] sending {len(packets)} packets in one burst")
            for idx, pkt in enumerate(packets):
                tcp_layer = pkt.getlayer(TCP)
                seq = tcp_layer.seq if tcp_layer else 0
                flags = tcp_layer.flags if tcp_layer else 0
                print(
                    f"[DEBUG][flow={flow.flow_id}] PKT#{idx+1}: {pkt.summary()} "
                    f"(flags={flags}, seq={seq})"
                )

        # Single blocking sendp() in a background thread.
        await asyncio.to_thread(sendp, packets, iface=iface, verbose=0, inter=0)
        if debug:
            print(f"[DEBUG][flow={flow.flow_id}] Spoofed TCP flow completed (burst mode)")
        return

    # --- SLOW PATH: per-packet paced behaviour ---

    # 1. SYN
    syn_pkt = build_syn_packet(flow, eth)
    if debug:
        print(
            f"[DEBUG][flow={flow.flow_id}] SYN: {syn_pkt.summary()} "
            f"(seq={flow.initial_seq})"
        )
    await asyncio.to_thread(sendp, syn_pkt, iface=iface, verbose=0)

    # 2. DATA (+ optional duplicates)
    data_packets, final_seq_before_fin = build_data_packets(
        flow, eth, flow_rng, duplication_prob
    )

    for idx, pkt in enumerate(data_packets):
        if debug:
            # Note: duplicates appear as additional indices with the same SEQ.
            tcp_layer = pkt.getlayer(TCP)
            seq = tcp_layer.seq if tcp_layer else 0
            print(
                f"[DEBUG][flow={flow.flow_id}] DATA#{idx+1}: {pkt.summary()} "
                f"(seq={seq}, len={len(flow.payload)})"
            )

        await asyncio.to_thread(sendp, pkt, iface=iface, verbose=0)

        # Compute per-packet pacing with jitter.
        if base_interval > 0.0 or interval_jitter > 0.0:
            jitter = 0.0
            if interval_jitter > 0.0:
                jitter = flow_rng.uniform(-interval_jitter, interval_jitter)
            delay = max(0.0, base_interval + jitter)
            if delay > 0.0:
                await asyncio.sleep(delay)

    # 3. FIN
    fin_seq = final_seq_before_fin & 0xFFFFFFFF
    fin_pkt = build_fin_packet(flow, eth, fin_seq)
    if debug:
        print(
            f"[DEBUG][flow={flow.flow_id}] FIN: {fin_pkt.summary()} "
            f"(seq={fin_seq})"
        )
    await asyncio.to_thread(sendp, fin_pkt, iface=iface, verbose=0)

    if debug:
        print(f"[DEBUG][flow={flow.flow_id}] Spoofed TCP flow completed (paced mode)")


async def run_all_flows(
    flows: List[FlowParams],
    eth_layer: Ether,
    iface: str,
    base_interval: float,
    interval_jitter: float,
    duplication_prob: float,
    flow_start_interval: float,
    rng: random.Random,
    debug: bool,
) -> None:
    """Create and run asynchronous tasks for all flows in parallel."""
    tasks = []
    for flow in flows:
        start_delay = flow.flow_id * flow_start_interval
        tasks.append(
            asyncio.create_task(
                send_flow(
                    flow=flow,
                    eth_layer=eth_layer,
                    iface=iface,
                    base_interval=base_interval,
                    interval_jitter=interval_jitter,
                    duplication_prob=duplication_prob,
                    start_delay=start_delay,
                    rng=rng,
                    debug=debug,
                )
            )
        )

    if debug:
        print(
            f"[DEBUG] Starting {len(tasks)} flow task(s) on {iface} "
            f"(base_interval={base_interval}, jitter={interval_jitter}, "
            f"flow_start_interval={flow_start_interval})"
        )

    await asyncio.gather(*tasks)


def main() -> int:
    # Raw Ethernet injection requires root privileges.
    if os.geteuid() != 0:
        print("[spoofed_client] must run as root to send raw packets", file=sys.stderr)
        return 1

    args = parse_args()
    clamp_args(args)

    # Seeded RNG for reproducible behaviour when desired.
    rng = random.Random(args.seed)

    # Shared Ethernet header template. If you need per-flow MAC customisation,
    # move this into build_flow_params_list() or send_flow().
    eth_layer = Ether(dst=args.dst_mac)

    flows = build_flow_params_list(args, rng)

    if args.debug:
        for f in flows:
            print(
                f"[DEBUG] Flow {f.flow_id}: src={f.src_ip or '<auto>'}:{f.src_port} "
                f"-> dst={f.dest_ip}:{f.dest_port}, data_packets={f.data_packets}, "
                f"payload_size={len(f.payload)}, initial_seq={f.initial_seq}, "
                f"initial_ack={f.initial_ack}"
            )

    # Run all flows concurrently using asyncio.
    asyncio.run(
        run_all_flows(
            flows=flows,
            eth_layer=eth_layer,
            iface=args.iface,
            base_interval=args.interval,
            interval_jitter=args.interval_jitter,
            duplication_prob=args.duplication_prob,
            flow_start_interval=args.flow_start_interval,
            rng=rng,
            debug=args.debug,
        )
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
