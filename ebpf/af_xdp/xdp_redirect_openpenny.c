// SPDX-License-Identifier: GPL-2.0
// The OpenPenny application writes generic match rules into "conf" and runtime behavior
// into "settings". Any packets matching the rules are redirected to AF_XDP via "xsks_map".
//
// Throughput notes (kept here so future edits don't quietly undo the wins):
//   * `counters` is BPF_MAP_TYPE_PERCPU_ARRAY so every CPU bumps its own cache
//     line. Userspace sums across CPUs at read time. NEVER add an atomic
//     (__sync_fetch_and_add / __atomic_*) here; per-CPU storage makes plain
//     `++` correct and the atomic would put a `lock add` back on the hot path.
//   * `match_rule` stores src/dst IPv4 and port fields in NETWORK byte order so
//     the per-packet `bpf_ntohl` / `bpf_ntohs` cost disappears. Userspace
//     (XdpRuleController.cpp) is responsible for the host->network conversion
//     once at rule-write time. If you change the wire format, change both.
//   * The XSK redirect path uses `bpf_redirect_map(&xsks_map, qid, XDP_PASS)`
//     directly, relying on the fallback-action flag instead of doing a separate
//     `bpf_map_lookup_elem(&xsks_map, &qid)` first. The xsk_hit/xsk_miss
//     distinction is recovered from the return value.

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

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

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
 *
 * THROUGHPUT-CRITICAL CONTRACT: src/dst IPv4 and src/dst ports are stored in
 * NETWORK byte order so the per-packet hot path can compare directly against
 * the in-packet fields without calling bpf_ntohl/bpf_ntohs. Userspace must
 * htonl()/htons() these before bpf_map_update_elem. The wire layout (12x u32)
 * is unchanged.
 */
struct match_rule {
    __u32 enabled;      // whether the rule is active
    __u32 match_fields; // MATCH_* bitmask selecting which 5-tuple fields to test
    __u32 src_prefix;   // NETWORK order; source IPv4 prefix when MATCH_SRC_IP is set
    __u32 src_mask;     // NETWORK order; source IPv4 mask when MATCH_SRC_IP is set
    __u32 dst_prefix;   // NETWORK order; destination IPv4 prefix when MATCH_DST_IP is set
    __u32 dst_mask;     // NETWORK order; destination IPv4 mask when MATCH_DST_IP is set
    __u32 ip_proto;     // IPPROTO_* when MATCH_IP_PROTO is set (single byte, no swap)
    __u32 src_port;     // NETWORK order source port (in low 16 bits) when MATCH_SRC_PORT is set
    __u32 dst_port;     // NETWORK order destination port (in low 16 bits) when MATCH_DST_PORT is set
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
 * bpf_redirect_map(&xsks_map, qid, XDP_PASS) is the handoff into userspace;
 * the XDP_PASS flag is the fallback action if no socket fd is installed.
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

/* One per-CPU stats entry at key 0. PERCPU_ARRAY removes the cache-line
 * bouncing the previous BPF_MAP_TYPE_ARRAY suffered from when XDP ran in
 * parallel on every NIC queue. Userspace must read nr_cpus values and sum.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
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

/* Function to parse the ethernet packet header including up to two encapsulated VLAN tags
 * IMPORTANT! If traffic uses VLAN tags > 2, modify accordingly.
 *
 * Returns the L3 EtherType in NETWORK byte order (caller compares against
 * bpf_htons(ETH_P_IP) so we avoid a per-packet bpf_ntohs). 0 means parse error.
 */
static __always_inline __be16 parse_eth(void **nh, void *end, __u32 *vlan_hits)
{
    /* Stage 1: parse Ethernet and advance *nh to the L3 header. */
    struct ethhdr *eth = (struct ethhdr *)(*nh);
    if (unlikely(!bounds_ok(eth, end, sizeof(*eth))))
        return 0;
    /* h_proto is __be16; keep it in network order, the caller knows. */
    __be16 proto = eth->h_proto;
    *nh = eth + 1;

    /* Fast-path the common case: no VLAN tags at all. The unrolled loop below
     * still runs for the rare 802.1Q frames; the branch here is essentially
     * free and lets the compiler skip the loop entirely on the hot path.
     */
    if (likely(proto != bpf_htons(ETH_P_8021Q) &&
               proto != bpf_htons(ETH_P_8021AD)))
        return proto;

// Unroll the loop to pass the verifier
#pragma clang loop unroll(full)
    for (int i = 0; i < 2; i++) {
        /* Peel up to two VLAN tags, enough for normal 802.1Q and QinQ. */
        if (proto == bpf_htons(ETH_P_8021Q) || proto == bpf_htons(ETH_P_8021AD)) {
            struct {
                __be16 tci;
                __be16 encap_proto;
            } *vh = (void *)(*nh);

            if (unlikely(!bounds_ok(vh, end, sizeof(*vh))))
                return 0;

            proto = vh->encap_proto;
            *nh = vh + 1;
            (*vlan_hits)++;
        } else {
            // If not VLAN protocol.
            break;
        }
    }

    return proto;
}

/* Function to check if a single rule matches the current packet.
 *
 * `sport_n` and `dport_n` are passed in NETWORK byte order (i.e. the raw
 * th->source / uh->source values) so we can compare directly against the
 * rule's pre-converted port fields.
 */
static __always_inline bool rule_matches(const struct match_rule *rule,
                                         const struct iphdr *ip,
                                         __be16 sport_n,
                                         __be16 dport_n,
                                         bool have_ports)
{
    /* Stage 4: evaluate one rule. Unset MATCH_* bits are wildcards. */
    if (unlikely(!rule) || !rule->enabled)
        return false;

    const __u32 mf = rule->match_fields;

    if ((mf & MATCH_IP_PROTO) && rule->ip_proto != ip->protocol)
        return false;

    /* Ports: rule->src_port / dst_port are stored in network byte order in the
     * low 16 bits, so a direct compare is correct.
     */
    if ((mf & MATCH_SRC_PORT) && (!have_ports || sport_n != (__be16)rule->src_port))
        return false;

    if ((mf & MATCH_DST_PORT) && (!have_ports || dport_n != (__be16)rule->dst_port))
        return false;

    /* IP addresses in struct iphdr are network order; rule values are too,
     * so we can mask & compare without any byte swap.
     */
    if ((mf & MATCH_SRC_IP) &&
        ((ip->saddr & rule->src_mask) != (rule->src_prefix & rule->src_mask)))
        return false;

    if ((mf & MATCH_DST_IP) &&
        ((ip->daddr & rule->dst_mask) != (rule->dst_prefix & rule->dst_mask)))
        return false;

    return true;
}

/* Try the AF_XDP redirect for `qid`. Updates xsk_hit/xsk_miss/redirect on `st`
 * based on the outcome inferred from bpf_redirect_map's return value.
 *
 * Importantly: we no longer do a separate bpf_map_lookup_elem on xsks_map first
 * — bpf_redirect_map does that lookup internally, and with the XDP_PASS flag
 * it returns XDP_PASS instead of an error when the entry is missing. That
 * halves the number of map lookups on the redirect path.
 */
static __always_inline int xsk_redirect(__u32 qid, struct stats *st)
{
    int ret = bpf_redirect_map(&xsks_map, qid, XDP_PASS);
    if (likely(ret == XDP_REDIRECT)) {
        st->xsk_hit++;
        st->redirect++;
    } else {
        /* Either no socket installed for `qid`, or the redirect was rejected.
         * Either way we fall through to XDP_PASS so the packet still reaches
         * the kernel stack.
         */
        st->xsk_miss++;
    }
    return ret;
}

static __always_inline int apply_action(__u32 action,
                                        __u32 qid,
                                        __u32 rx_qid,
                                        struct stats *st)
{
    /* Stage 5: convert a matching rule/default action into an XDP verdict.
     * Order of the if-chain mirrors expected hit-rate: REDIRECT first so the
     * data-plane case has the shortest branch chain.
     */
    if (likely(action == ACTION_REDIRECT_XSK)) {
        /* AF_XDP sockets can only receive packets redirected from the same
         * netdev queue they are bound to. Cross-queue redirects are not valid.
         */
        if (unlikely(qid != rx_qid)) {
            st->queue_mismatch++;
            return XDP_PASS;
        }
        return xsk_redirect(qid, st);
    }

    if (action == ACTION_DROP)
        return XDP_DROP;

    st->pass++;
    return XDP_PASS;
}

SEC("xdp")
int xdp_redirect_openpenny(struct xdp_md *ctx)
{
    /* Entry point called by the kernel for every packet arriving at the XDP hook. */
    __u32 rx_qid = ctx->rx_queue_index;
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

    /* Stage 0: observability. PERCPU_ARRAY lookup at key 0 cannot legitimately
     * fail, but the verifier still requires the NULL guard. Hint it as cold so
     * the compiler keeps the rare-failure path out of the hot instruction
     * stream.
     */
    const __u32 k0 = 0;
    struct stats *st = bpf_map_lookup_elem(&counters, &k0);
    if (unlikely(!st))
        return XDP_PASS;

    st->seen++;

    /* Stage 1: parse L2 and optional VLAN tags. Non-parseable frames pass. */
    void *nh = data;
    __u32 vlan_hits = 0;
    __be16 etype_n = parse_eth(&nh, end, &vlan_hits);
    if (unlikely(!etype_n)) {
        st->pass++;
        return XDP_PASS;
    }

    if (unlikely(vlan_hits))
        st->vlan++;

    /* Stage 2: this program only applies rules to IPv4. Everything else passes.
     * Compare in network byte order to skip the bpf_ntohs we used to do.
     */
    if (unlikely(etype_n != bpf_htons(ETH_P_IP))) {
        st->pass++;
        return XDP_PASS;
    }

    st->ipv4++;

    /* Stage 2 continued: validate IPv4 header and account for IPv4 options. */
    struct iphdr *ip = nh;
    if (unlikely(!bounds_ok(ip, end, sizeof(*ip)))) {
        st->pass++;
        return XDP_PASS;
    }
    if (unlikely(ip->ihl < 5)) {
        st->pass++;
        return XDP_PASS;
    }

    void *l4 = (void *)ip + ip->ihl * 4;
    __be16 sport_n = 0;
    __be16 dport_n = 0;
    bool have_ports = false;

    /* Stage 3: parse TCP/UDP ports when present. Rules can still match by IP
     * or protocol for packets without ports. We keep the values in network
     * byte order (no bpf_ntohs) since the rule's port fields are also stored
     * in network order — see match_rule contract.
     */
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *th = l4;
        if (unlikely(!bounds_ok(th, end, sizeof(*th)))) {
            st->pass++;
            return XDP_PASS;
        }
        sport_n = th->source;
        dport_n = th->dest;
        have_ports = true;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *uh = l4;
        if (unlikely(!bounds_ok(uh, end, sizeof(*uh)))) {
            st->pass++;
            return XDP_PASS;
        }
        sport_n = uh->source;
        dport_n = uh->dest;
        have_ports = true;
    }

    /* Stage 4 setup: load runtime settings. If userspace has not programmed
     * settings yet, pass traffic rather than disrupting the interface.
     */
    struct xdp_settings *cfg = bpf_map_lookup_elem(&settings, &k0);
    if (unlikely(!cfg)) {
        st->pass++;
        return XDP_PASS;
    }

    /* Safety bypass to avoid locking operators out while testing XDP attach.
     * Compare port 22 in network byte order (compile-time constant — free).
     */
    if (unlikely(cfg->flags & FLAG_ALLOW_SSH_BYPASS) &&
        ip->protocol == IPPROTO_TCP &&
        (sport_n == bpf_htons(22) || dport_n == bpf_htons(22))) {
        st->ssh_pass++;
        return XDP_PASS;
    }

    /* Stage 4: evaluate the single programmed rule. */
    if (likely(cfg->rule_count > 0)) {
        struct match_rule *rule = bpf_map_lookup_elem(&conf, &k0);
        if (rule_matches(rule, ip, sport_n, dport_n, have_ports)) {
            st->match++;
            __u32 target_qid = rule->use_qid ? rule->qid : rx_qid;
            return apply_action(rule->action, target_qid, rx_qid, st);
        }
    }

    /* No rule matched. Fast-path the common default-PASS case so we skip the
     * apply_action call entirely.
     */
    st->nomatch++;
    if (likely(cfg->default_action == ACTION_PASS)) {
        st->pass++;
        return XDP_PASS;
    }
    return apply_action(cfg->default_action, rx_qid, rx_qid, st);
}
