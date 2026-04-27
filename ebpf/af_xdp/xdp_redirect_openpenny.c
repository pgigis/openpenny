// SPDX-License-Identifier: GPL-2.0
// The OpenPenny application writes generic match rules into "conf" and runtime behavior
// into "settings". Any packets matching the rules are redirected to AF_XDP via "xsks_map".

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <stdbool.h>

char LICENSE[] SEC("license") = "GPL";

/* Single runtime rule. This must stay in sync with XdpRuleController.h. */
#define MAX_RULES 1

/* Values mirrored from openpenny::net::TrafficRuleAction. */
#define ACTION_PASS 0
#define ACTION_REDIRECT_XSK 1
#define ACTION_DROP 2

/* Runtime settings flags programmed by userspace. */
/* Safety mechanism to avoid locking out SSH access during XDP testing. */
#define FLAG_ALLOW_SSH_BYPASS (1U << 0)

/* Per-rule 5-tuple field mask. If a bit is clear, that field is a wildcard. */
#define MATCH_SRC_IP (1U << 0)
#define MATCH_DST_IP (1U << 1)
#define MATCH_IP_PROTO (1U << 2)
#define MATCH_SRC_PORT (1U << 3)
#define MATCH_DST_PORT (1U << 4)

/* One traffic-selection rule as seen by the kernel program.
 * Userspace writes these into the `conf` map at startup and on rule updates.
 */
struct match_rule {
    __u32 enabled;      // whether the rule is active
    __u32 match_fields; // MATCH_* bitmask selecting which 5-tuple fields to test
    __u32 src_prefix;   // host order; source IPv4 prefix when MATCH_SRC_IP is set
    __u32 src_mask;     // host order; source IPv4 mask when MATCH_SRC_IP is set
    __u32 dst_prefix;   // host order; destination IPv4 prefix when MATCH_DST_IP is set
    __u32 dst_mask;     // host order; destination IPv4 mask when MATCH_DST_IP is set
    __u32 ip_proto;     // IPPROTO_* when MATCH_IP_PROTO is set
    __u32 src_port;     // host order source port when MATCH_SRC_PORT is set
    __u32 dst_port;     // host order destination port when MATCH_DST_PORT is set
    __u32 action;       // pass, redirect, drop
    __u32 qid;          // queue id to redirect to
    __u32 use_qid;      // whether to use qid instead of the packet's RX queue
};

/* Global program settings. Key 0 stores the active rule count, safety flags,
 * default action, and default AF_XDP queue for rules without an explicit target.
 */
struct xdp_settings {
    __u32 rule_count;
    __u32 flags;
    __u32 default_action;
    __u32 default_qid;
};

/* AF_XDP socket map: key = queue id, value = AF_XDP socket fd.
 * XdpReader creates one AF_XDP socket per queue and writes its fd here.
 * bpf_redirect_map(&xsks_map, qid, 0) is the handoff into userspace.
 */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

/* Single packet-matching rule map. Key 0 is active when settings.rule_count > 0. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_RULES);
    __type(key, __u32);
    __type(value, struct match_rule);
} conf SEC(".maps");

/* Single settings entry. Userspace updates key 0 before AF_XDP polling starts. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_settings);
} settings SEC(".maps");

/* Debug/visibility counters. These are not required for packet forwarding; they
 * let operators verify that packets hit the program and how rules behaved.
 */
struct stats {
    __u64 seen;
    __u64 vlan;
    __u64 ipv4;
    __u64 ssh_pass;
    __u64 match;
    __u64 nomatch;
    __u64 queue_mismatch;
    __u64 xsk_hit;
    __u64 xsk_miss;
    __u64 redirect;
    __u64 pass;
};

/* One global stats entry at key 0. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
} counters SEC(".maps");

/* Helper function to check whether reading len bytes from pointer p stays inside the packet.
 * We use __always_inline to optimise against the extra function call.
 * Every packet dereference must be proven safe to pass the verifier.
 */
static __always_inline bool bounds_ok(void *p, void *end, __u64 len)
{
    /* Every packet access must be verifier-proven inside [data, data_end). */
    return (void *)((char *)p + len) <= end;
}

static __always_inline void bump(__u64 *ctr)
{
    /* XDP programs can run concurrently on multiple CPUs, so counters use
     * atomic increments. These are observability-only and not on the decision path.
     */
    __sync_fetch_and_add(ctr, 1);
}

/* Function to parse the ethernet packet header including up to two encapsulated VLAN tags
 * IMPORTANT! If traffic uses VLAN tags > 2, modify accordingly.
 */
static __always_inline __u16 parse_eth(void **nh, void *end, __u32 *vlan_hits)
{
    /* Stage 1: parse Ethernet and advance *nh to the L3 header. */
    struct ethhdr *eth = (struct ethhdr *)(*nh);
    if (!bounds_ok(eth, end, sizeof(*eth)))
        return 0;
    // Load the EtherType to proto and advance *nh to the byte after the Ethernet header
    __u16 proto = eth->h_proto;
    *nh = eth + 1;

// Unroll the loop to pass the verifier
#pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {
        /* Peel up to two VLAN tags, enough for normal 802.1Q and QinQ. */
        if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
            struct {
                __be16 tci;
                __be16 encap_proto;
            } *vh = (void *)(*nh);

            if (!bounds_ok(vh, end, sizeof(*vh)))
                return 0;

            proto = vh->encap_proto;
            *nh = vh + 1;
            (*vlan_hits)++;
        } else {
            // If not VLAN protocol.
            break;
        }
    }

    return bpf_ntohs(proto);
}

/* Function to check if a single rule matches the current packet */
static __always_inline bool rule_matches(struct match_rule *rule,
                                         struct iphdr *ip,
                                         __u16 sport,
                                         __u16 dport,
                                         bool have_ports)
{
    /* Stage 4: evaluate one rule. Unset MATCH_* bits are wildcards. */
    if (!rule || !rule->enabled)
        return false;

    if ((rule->match_fields & MATCH_IP_PROTO) && rule->ip_proto != ip->protocol)
        return false;

    if ((rule->match_fields & MATCH_SRC_PORT) && (!have_ports || sport != rule->src_port))
        return false;

    if ((rule->match_fields & MATCH_DST_PORT) && (!have_ports || dport != rule->dst_port))
        return false;

    /* IP addresses in struct iphdr are network order; rule values are host order. */
    __u32 saddr = bpf_ntohl(ip->saddr);
    if ((rule->match_fields & MATCH_SRC_IP) &&
        ((saddr & rule->src_mask) != (rule->src_prefix & rule->src_mask)))
        return false;

    __u32 daddr = bpf_ntohl(ip->daddr);
    if ((rule->match_fields & MATCH_DST_IP) &&
        ((daddr & rule->dst_mask) != (rule->dst_prefix & rule->dst_mask)))
        return false;

    return true;
}

static __always_inline int apply_action(__u32 action,
                                        __u32 qid,
                                        __u32 rx_qid,
                                        struct stats *st)
{
    /* Stage 5: convert a matching rule/default action into an XDP verdict. */
    if (action == ACTION_DROP)
        return XDP_DROP;

    if (action == ACTION_REDIRECT_XSK) {
        /* AF_XDP sockets can only receive packets redirected from the same
         * netdev queue they are bound to. Cross-queue redirects are not valid.
         */
        if (qid != rx_qid) {
            if (st) bump(&st->queue_mismatch);
            return XDP_PASS;
        }
        /* XSKMAP lookup support from userspace tools is limited, so keep an
         * explicit kernel-side signal of whether a socket entry existed for
         * this queue before attempting redirect.
         */
        if (bpf_map_lookup_elem(&xsks_map, &qid)) {
            if (st) {
                bump(&st->xsk_hit);
                bump(&st->redirect);
            }
            return bpf_redirect_map(&xsks_map, qid, XDP_PASS);
        }
        if (st) bump(&st->xsk_miss);
        /* This is the AF_XDP handoff. The qid must have an AF_XDP socket fd
         * installed in xsks_map by XdpReader, otherwise redirect fails.
         */
        return XDP_PASS;
    }

    if (st) bump(&st->pass);
    return XDP_PASS;
}

SEC("xdp")
int xdp_redirect_openpenny(struct xdp_md *ctx)
{
    /* Entry point called by the kernel for every packet arriving at the XDP hook. */
    __u32 rx_qid = ctx->rx_queue_index;
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

    /* Stage 0: observability. Missing stats map should never block traffic. */
    const __u32 k0 = 0;
    struct stats *st = bpf_map_lookup_elem(&counters, &k0);
    if (st) bump(&st->seen);

    /* Stage 1: parse L2 and optional VLAN tags. Non-parseable frames pass. */
    void *nh = data;
    __u32 vlan_hits = 0;
    __u16 etype = parse_eth(&nh, end, &vlan_hits);
    if (!etype)
        goto pass;

    if (st && vlan_hits) bump(&st->vlan);

    /* Stage 2: this program only applies rules to IPv4. Everything else passes. */
    if (etype != ETH_P_IP)
        goto pass;

    if (st) bump(&st->ipv4);

    /* Stage 2 continued: validate IPv4 header and account for IPv4 options. */
    struct iphdr *ip = nh;
    if (!bounds_ok(ip, end, sizeof(*ip)))
        goto pass;
    if (ip->ihl < 5)
        goto pass;

    void *l4 = (void *)ip + ip->ihl * 4;
    __u16 sport = 0;
    __u16 dport = 0;
    bool have_ports = false;

    /* Stage 3: parse TCP/UDP ports when present. Rules can still match by IP
     * or protocol for packets without ports.
     */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *th = l4;
        if (!bounds_ok(th, end, sizeof(*th)))
            goto pass;
        sport = bpf_ntohs(th->source);
        dport = bpf_ntohs(th->dest);
        have_ports = true;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *uh = l4;
        if (!bounds_ok(uh, end, sizeof(*uh)))
            goto pass;
        sport = bpf_ntohs(uh->source);
        dport = bpf_ntohs(uh->dest);
        have_ports = true;
    }

    /* Stage 4 setup: load runtime settings. If userspace has not programmed
     * settings yet, pass traffic rather than disrupting the interface.
     */
    struct xdp_settings *cfg = bpf_map_lookup_elem(&settings, &k0);
    if (!cfg)
        goto pass;

    /* Safety bypass to avoid locking operators out while testing XDP attach. */
    if ((cfg->flags & FLAG_ALLOW_SSH_BYPASS) &&
        ip->protocol == IPPROTO_TCP &&
        (sport == 22 || dport == 22)) {
        if (st) bump(&st->ssh_pass);
        return XDP_PASS;
    }

    /* Stage 4: evaluate the single programmed rule. */
    if (cfg->rule_count > 0) {
        struct match_rule *rule = bpf_map_lookup_elem(&conf, &k0);
        if (rule_matches(rule, ip, sport, dport, have_ports)) {
            if (st) bump(&st->match);
            __u32 target_qid = rule->use_qid ? rule->qid : rx_qid;
            return apply_action(rule->action, target_qid, rx_qid, st);
        }
    }

    /* No rule matched. Apply the configured fallback policy, usually XDP_PASS. */
    if (st) bump(&st->nomatch);
    return apply_action(cfg->default_action, rx_qid, rx_qid, st);

pass:
    /* Conservative fallback for unsupported traffic or malformed/truncated frames. */
    if (st) bump(&st->pass);
    return XDP_PASS;
}
