// SPDX-License-Identifier: BSD-2-Clause

#include "XdpRuleController.h"

#include "openpenny/log/Log.h"

#include <arpa/inet.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>

#ifdef OPENPENNY_WITH_LIBBPF
extern "C" {
#include <bpf/bpf.h>
}
#endif

namespace openpenny::xdp {
namespace {

constexpr std::uint32_t kFlagAllowSshBypass = 1u << 0;
constexpr std::uint32_t kMatchSrcIp = 1u << 0;
constexpr std::uint32_t kMatchDstIp = 1u << 1;
constexpr std::uint32_t kMatchIpProto = 1u << 2;
constexpr std::uint32_t kMatchSrcPort = 1u << 3;
constexpr std::uint32_t kMatchDstPort = 1u << 4;

// THROUGHPUT-CRITICAL CONTRACT (mirror of `struct match_rule` in
// ebpf/af_xdp/xdp_redirect_openpenny.c): src/dst IPv4 prefix+mask and src/dst
// ports are stored in NETWORK byte order so the BPF hot path can compare
// directly against in-packet fields without per-packet bpf_ntohl/bpf_ntohs.
// We do the host->network conversion exactly once here, at rule-write time.
// If you change the on-the-wire field semantics, update the BPF program too.
struct BpfMatchRule {
    std::uint32_t enabled;
    std::uint32_t match_fields;
    std::uint32_t src_prefix;   // network byte order (htonl)
    std::uint32_t src_mask;     // network byte order (htonl)
    std::uint32_t dst_prefix;   // network byte order (htonl)
    std::uint32_t dst_mask;     // network byte order (htonl)
    std::uint32_t ip_proto;     // single byte; no swap
    std::uint32_t src_port;     // network byte order in low 16 bits (htons)
    std::uint32_t dst_port;     // network byte order in low 16 bits (htons)
    std::uint32_t action;
    std::uint32_t qid;
    std::uint32_t use_qid;
};

struct BpfSettings {
    std::uint32_t rule_count;
    std::uint32_t flags;
    std::uint32_t default_action;
    std::uint32_t default_qid;
};

static_assert(sizeof(BpfMatchRule) == kBpfMatchRuleValueSize);
static_assert(sizeof(BpfSettings) == kBpfSettingsValueSize);

std::uint32_t to_bpf_action(net::TrafficRuleAction action) {
    return static_cast<std::uint32_t>(action);
}

// Human-readable label for an action enum value as it appears in the
// BPF maps (PASS=0, REDIRECT=1, DROP=2). Keeps the operator-facing log
// lines from showing raw integers.
const char* action_label(std::uint32_t action) {
    switch (action) {
        case 0: return "PASS";
        case 1: return "REDIRECT";
        case 2: return "DROP";
        default: return "UNKNOWN";
    }
}

// Common L4 protocol names; the rest fall through to the numeric value.
const char* proto_label(std::uint32_t proto) {
    switch (proto) {
        case 1:  return "icmp";
        case 6:  return "tcp";
        case 17: return "udp";
        default: return nullptr;
    }
}

// Build a one-line human-readable description of the rule + settings as
// they are currently visible in the kernel BPF maps.
std::string describe_kernel_rule(const BpfMatchRule& rule,
                                 const BpfSettings& settings) {
    std::ostringstream oss;
    oss << "rule_count=" << settings.rule_count
        << " default=" << action_label(settings.default_action);
    if (settings.rule_count == 0 || !rule.enabled) {
        return oss.str();
    }
    oss << "; rule0:";
    bool first = true;
    auto add = [&](const char* tag, const std::string& value) {
        if (!first) oss << ",";
        oss << " " << tag << "=" << value;
        first = false;
    };
    if (rule.match_fields & kMatchIpProto) {
        const char* p = proto_label(rule.ip_proto);
        add("proto", p ? std::string(p)
                       : std::to_string(rule.ip_proto));
    }
    // Rule fields are stored in network byte order in the BPF map; convert
    // back to host order so the operator-facing log line keeps reading as a
    // normal port number / hex IP rather than a byte-swapped surprise.
    if (rule.match_fields & kMatchSrcPort)
        add("src_port", std::to_string(::ntohs(static_cast<std::uint16_t>(rule.src_port))));
    if (rule.match_fields & kMatchDstPort)
        add("dst_port", std::to_string(::ntohs(static_cast<std::uint16_t>(rule.dst_port))));
    if (rule.match_fields & kMatchSrcIp) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%08x/0x%08x",
                      ::ntohl(rule.src_prefix), ::ntohl(rule.src_mask));
        add("src", buf);
    }
    if (rule.match_fields & kMatchDstIp) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "0x%08x/0x%08x",
                      ::ntohl(rule.dst_prefix), ::ntohl(rule.dst_mask));
        add("dst", buf);
    }
    oss << " -> " << action_label(rule.action);
    return oss.str();
}

BpfMatchRule to_bpf_rule(const net::TrafficMatchRule& rule, unsigned /*queue*/) {
    BpfMatchRule out{};
    out.enabled = rule.enabled ? 1u : 0u;
    // IPs and ports are converted host->network here so the kernel BPF program
    // can compare them directly against in-packet fields (which are network
    // order) without paying for a per-packet byte swap. See contract note on
    // BpfMatchRule above.
    if (rule.src_ip) {
        out.match_fields |= kMatchSrcIp;
        out.src_prefix = ::htonl(rule.src_ip->prefix_host);
        out.src_mask = ::htonl(rule.src_ip->mask_host);
    }
    if (rule.dst_ip) {
        out.match_fields |= kMatchDstIp;
        out.dst_prefix = ::htonl(rule.dst_ip->prefix_host);
        out.dst_mask = ::htonl(rule.dst_ip->mask_host);
    }
    if (rule.ip_proto) {
        out.match_fields |= kMatchIpProto;
        out.ip_proto = static_cast<std::uint32_t>(*rule.ip_proto);
    }
    if (rule.src_port) {
        out.match_fields |= kMatchSrcPort;
        out.src_port = static_cast<std::uint32_t>(::htons(*rule.src_port));
    }
    if (rule.dst_port) {
        out.match_fields |= kMatchDstPort;
        out.dst_port = static_cast<std::uint32_t>(::htons(*rule.dst_port));
    }
    out.action = to_bpf_action(rule.action);
    out.qid = rule.target_queue;
    out.use_qid = rule.use_target_queue ? 1u : 0u;
    return out;
}

bool write_xdp_rule_maps(const XdpRuleMapFds& fds,
                         const net::TrafficMatchConfig& match_config,
                         unsigned queue,
                         net::TrafficRuleAction default_action,
                         bool allow_ssh_bypass) {
#ifndef OPENPENNY_WITH_LIBBPF
    (void)fds;
    (void)match_config;
    (void)queue;
    (void)default_action;
    (void)allow_ssh_bypass;
    TCPLOG_ERROR("Cannot program XDP match rules without libbpf support.");
    return false;
#else
    if (fds.rules_fd < 0 || fds.settings_fd < 0) {
        TCPLOG_ERROR("XDP rules/settings maps are not available.");
        return false;
    }

    if (match_config.rules.size() > kBpfMaxRules) {
        TCPLOG_ERROR("AF_XDP currently supports at most one traffic match rule; got %zu",
                     match_config.rules.size());
        return false;
    }

    // Pre-write announcement. Two distinct cases worth telling apart for
    // the operator: pass-only baseline vs live match rules.
    if (match_config.rules.empty()) {
        TCPLOG_INFO(
            "[openpenny] BPF baseline: installing pass-only defaults — "
            "XDP attached, traffic continues to flow normally; not yet "
            "redirecting to userspace");
    } else {
        TCPLOG_INFO(
            "[openpenny] BPF live rules: installing %zu match rule%s "
            "(default=%s)",
            match_config.rules.size(),
            match_config.rules.size() == 1 ? "" : "s",
            action_label(to_bpf_action(default_action)));
    }

    BpfMatchRule slot{};
    if (!match_config.rules.empty()) {
        slot = to_bpf_rule(match_config.rules.front(), queue);
    }

    const std::uint32_t rule_key = 0;
    if (bpf_map_update_elem(fds.rules_fd, &rule_key, &slot, BPF_ANY) != 0) {
        TCPLOG_ERROR("Failed to update XDP rule slot 0: %s", std::strerror(errno));
        return false;
    }

    BpfSettings settings{};
    settings.rule_count = static_cast<std::uint32_t>(match_config.rules.size());
    settings.flags = allow_ssh_bypass ? kFlagAllowSshBypass : 0u;
    settings.default_action = to_bpf_action(default_action);
    settings.default_qid = 0;

    const std::uint32_t settings_key = 0;
    if (bpf_map_update_elem(fds.settings_fd, &settings_key, &settings, BPF_ANY) != 0) {
        TCPLOG_ERROR("Failed to update XDP settings map: %s", std::strerror(errno));
        return false;
    }

    // Read the rule and settings BACK from the kernel and log what is now
    // live. The operator-facing INFO line is human-readable; the raw
    // bitfield dump goes to DEBUG for troubleshooting only.
    //
    // For the pass-only baseline path we deliberately stay quiet at INFO
    // (the "BPF baseline:" announcement above already conveyed what is
    // happening, and a readback line that says "rule_count=0" reads like
    // a bug to anyone not familiar with the code).
    BpfMatchRule live_rule{};
    BpfSettings live_settings{};
    const std::uint32_t k0 = 0;
    const bool rule_ok = (bpf_map_lookup_elem(fds.rules_fd, &k0, &live_rule) == 0);
    const bool settings_ok = (bpf_map_lookup_elem(fds.settings_fd, &k0, &live_settings) == 0);
    if (rule_ok && settings_ok) {
        if (!match_config.rules.empty()) {
            TCPLOG_INFO("[openpenny] BPF live rules confirmed in kernel: %s",
                        describe_kernel_rule(live_rule, live_settings).c_str());
        }
        // Always emit the raw values at DEBUG so the bitfields are
        // available without recompiling when troubleshooting weird
        // map-mismatch bugs.
        // Raw bitfield dump for map-mismatch debugging; ports/IPs are shown
        // exactly as they sit in the kernel map (network byte order, per the
        // BpfMatchRule contract above).
        TCPLOG_DEBUG(
            "[xdp_rule_live] rule_count=%u default_action=%u "
            "rule0: enabled=%u match_fields=0x%x ip_proto=%u "
            "src_port_be=%u dst_port_be=%u src_prefix_be=0x%08x/0x%08x "
            "dst_prefix_be=0x%08x/0x%08x action=%u qid=%u use_qid=%u",
            live_settings.rule_count,
            live_settings.default_action,
            live_rule.enabled,
            live_rule.match_fields,
            live_rule.ip_proto,
            live_rule.src_port,
            live_rule.dst_port,
            live_rule.src_prefix, live_rule.src_mask,
            live_rule.dst_prefix, live_rule.dst_mask,
            live_rule.action,
            live_rule.qid,
            live_rule.use_qid);
    } else {
        TCPLOG_WARN("[openpenny] BPF readback failed; cannot verify what "
                    "the kernel will match against (rule_lookup=%d "
                    "settings_lookup=%d)",
                    rule_ok ? 1 : 0, settings_ok ? 1 : 0);
    }

    return true;
#endif
}

} // namespace

bool program_xdp_match_rules(const XdpRuleMapFds& fds,
                             const net::TrafficMatchConfig& match_config,
                             unsigned queue,
                             bool drop_unmatched,
                             bool allow_ssh_bypass) {
    const auto default_action = drop_unmatched
        ? net::TrafficRuleAction::Drop
        : match_config.default_action;
    return write_xdp_rule_maps(fds, match_config, queue, default_action, allow_ssh_bypass);
}

bool program_xdp_pass_defaults(const XdpRuleMapFds& fds,
                               bool allow_ssh_bypass) {
    net::TrafficMatchConfig pass_only{};
    pass_only.default_action = net::TrafficRuleAction::Pass;
    return write_xdp_rule_maps(fds, pass_only, 0, net::TrafficRuleAction::Pass, allow_ssh_bypass);
}

} // namespace openpenny::xdp
