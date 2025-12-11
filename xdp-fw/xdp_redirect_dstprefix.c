// SPDX-License-Identifier: GPL-2.0
// PREFIX-MATCH VERSION
// Redirect IPv4 packets whose *source address* matches conf.{prefix,mask}
// to the AF_XDP socket on conf.qid. TCP/22 (SSH) is always passed.
// VLAN (802.1Q/AD) supported. Non-IPv4 and non-matching IPv4 are XDP_PASS.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <stdbool.h>

char LICENSE[] SEC("license") = "GPL";

/* Per-program configuration.
 * The control-plane (CLI or helper) writes one entry per RX queue (key=queue_id).
 *  - prefix/mask are stored in HOST byte order to keep the update logic simple.
 *  - qid is optional; by default we redirect to the same queue we received on.
 */
struct cfg {
    __u32 prefix;  // source IPv4 prefix (host order)
    __u32 mask;    // source IPv4 mask   (host order)
    __u32 qid;     // RX queue index to redirect to
};

/* AF_XDP socket map: key = queue id, value = xsk fd */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

/* Config map keyed by queue id (fallback to key 0 if a specific queue entry is absent). */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct cfg);
} conf SEC(".maps");

/* Simple counters to aid debugging/visibility */
struct stats {
    __u64 seen;        // total frames that hit the program
    __u64 vlan;        // frames with ≥1 VLAN tag
    __u64 ipv4;        // frames identified as IPv4
    __u64 ssh_pass;    // IPv4 TCP/22 packets allowed to pass
    __u64 match;       // IPv4 dst matched prefix/mask
    __u64 nomatch;     // IPv4 dst did not match prefix/mask
    __u64 redirect;    // packets redirected to XSK
    __u64 pass;        // packets passed (fallback)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY); // Create fixed-sized array.
    __uint(max_entries, 1); // The array can take exactly one element.
    __type(key, __u32); // The key to fetch the first position, valid key values are from `0` to `max_entries-1` — so only `0` in this case.
    __type(value, struct stats); // Type struct stats
} counters SEC(".maps");

/* ---- helpers ---- */

/* Bounds check: returns true if [p, p+len) lies within [data, end). */
static __always_inline bool bounds_ok(void *p, void *end, __u64 len)
{
    return (void *)((char *)p + len) <= end;
}

/* Atomic increment (works from XDP). */
static __always_inline void bump(__u64 *ctr)
{
    __sync_fetch_and_add(ctr, 1);
}

/* Parse Ethernet header and peel up to two VLAN tags.
 * - *nh is advanced to the network payload. (to the IP header)
 * - Returns EtherType in HOST order on success, 0 on failure (bounds).
 */
static __always_inline __u16 parse_eth(void **nh, void *end, __u32 *vlan_hits)
{
    struct ethhdr *eth = (struct ethhdr *)(*nh);
    if (!bounds_ok(eth, end, sizeof(*eth)))
        return 0;

    __u16 proto = eth->h_proto;      // network order
    *nh = eth + 1;                   // advance past base Ethernet header

#pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {    // support up to QinQ (2 VLAN tags)
        if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
            // Minimal VLAN header view: [TCI][encap_proto]
            struct {
                __be16 tci;
                __be16 encap_proto;
            } *vh = (void *)(*nh);
            if (!bounds_ok(vh, end, sizeof(*vh)))
                return 0;
            proto = vh->encap_proto; // inner EtherType (network order)
            *nh = vh + 1;            // advance past VLAN tag
            (*vlan_hits)++;
        } else {
            break;
        }
    }

    return bpf_ntohs(proto);         // convert to host order for comparisons
}

/* ---- XDP entry ---- */

SEC("xdp")
int xdp_redirect_dstprefix(struct xdp_md *ctx)
{
    // Raw data pointers
    // Pointer to the start of the packet
    void *data = (void *)(long)ctx->data;
    // Pointer to the end of the packet
    void *end  = (void *)(long)ctx->data_end;

    const __u32 k0 = 0;
    struct stats *st = bpf_map_lookup_elem(&counters, &k0);
    if (st) bump(&st->seen);

    // Parse L2 (Ethernet + optional VLAN)
    void *nh = data; // nh stands for "next header pointer"
    __u32 vlan_hits = 0; // Count VLAN tags
    __u16 etype = parse_eth(&nh, end, &vlan_hits);
    if (!etype)                         // bounds error → pass
        goto pass;

    if (st && vlan_hits) bump(&st->vlan);

    // Only handle IPv4 frames
    if (etype != ETH_P_IP)
        goto pass;

    if (st) bump(&st->ipv4);

    // Safe access to IPv4 header
    struct iphdr *ip = nh;
    if (!bounds_ok(ip, end, sizeof(*ip)))
        goto pass;
    if (ip->ihl < 5)                    // minimal IPv4 header length check
        goto pass;

    // Exempt SSH (either src or dst TCP port 22) to avoid lockouts
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (void *)ip + ip->ihl * 4;
        if (!bounds_ok(th, end, sizeof(*th)))
            goto pass;
        if (th->source == bpf_htons(22) || th->dest == bpf_htons(22)) {
            if (st) bump(&st->ssh_pass);
            return XDP_PASS;
        }
    }

    // Load config for this RX queue (fallback to key 0 if unset)
    const __u32 rx_qid = ctx->rx_queue_index;
    struct cfg *c = bpf_map_lookup_elem(&conf, &rx_qid);
    if (!c) c = bpf_map_lookup_elem(&conf, &k0);
    if (!c) goto pass;

    // Convert packet source to host order so we can reuse the control-plane mask logic.
    __u32 saddr_host = bpf_ntohl(ip->saddr);

    // Apply mask and compare with configured prefix:
    //   match ⇔ (src & mask) == (prefix & mask)
    if ( (saddr_host & c->mask) == (c->prefix & c->mask) ) {
        if (st) {
            bump(&st->match);
            bump(&st->redirect);
        }
        bpf_printk("MATCH: saddr=%pI4 prefix=%pI4 mask=0x%x\n",
               &ip->saddr, &c->prefix, c->mask);
        // Redirect matching traffic to AF_XDP socket bound at key=rx_qid
        __u32 target_qid = c->qid ? c->qid : rx_qid;
        return bpf_redirect_map(&xsks_map, target_qid, 0);
    } else {
        if (st) bump(&st->nomatch);
        goto pass;
    }

pass:
    if (st) bump(&st->pass);
    return XDP_PASS;
}
