// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/net/TrafficMatch.h"

#include "openpenny/agg/Stats.h"
#include "openpenny/net/Packet.h"

#include <sstream>

namespace openpenny::net {
namespace {

std::string ip_to_string(std::uint32_t host) {
    std::ostringstream out;
    out << ((host >> 24) & 0xff) << '.'
        << ((host >> 16) & 0xff) << '.'
        << ((host >> 8) & 0xff) << '.'
        << (host & 0xff);
    return out.str();
}

int mask_bits(std::uint32_t mask) {
    int bits = 0;
    for (int i = 31; i >= 0; --i) {
        if ((mask & (1u << i)) == 0) break;
        ++bits;
    }
    return bits;
}

std::string prefix_to_string(const TrafficIpPrefix& prefix) {
    std::ostringstream out;
    out << ip_to_string(prefix.prefix_host) << '/' << mask_bits(prefix.mask_host);
    return out.str();
}

bool ip_matches(std::uint32_t value, const TrafficIpPrefix& prefix) {
    if (prefix.mask_host == 0) return true;
    return (value & prefix.mask_host) == (prefix.prefix_host & prefix.mask_host);
}

bool rule_matches_endpoints(const TrafficMatchRule& rule, const FlowKey& key) {
    if (rule.src_ip && !ip_matches(key.src, *rule.src_ip)) return false;
    if (rule.dst_ip && !ip_matches(key.dst, *rule.dst_ip)) return false;

    if (rule.src_port && key.sport != *rule.src_port) return false;
    if (rule.dst_port && key.dport != *rule.dst_port) return false;

    return true;
}

bool rule_matches_flow(const TrafficMatchRule& rule, const FlowKey& key) {
    if (!rule.enabled) return false;
    if (!rule_matches_endpoints(rule, key)) return false;
    if (rule.ip_proto && key.ip_proto != *rule.ip_proto) return false;
    return true;
}

bool rule_matches_packet(const TrafficMatchRule& rule, const PacketView& packet) {
    if (!rule.enabled) return false;
    if (!rule_matches_endpoints(rule, packet.flow)) return false;
    if (rule.ip_proto && packet.ip_proto != *rule.ip_proto) return false;
    return true;
}

bool action_accepts(TrafficRuleAction action) {
    return action == TrafficRuleAction::RedirectToUserspace;
}

const char* action_name(TrafficRuleAction action) {
    switch (action) {
    case TrafficRuleAction::Pass: return "pass";
    case TrafficRuleAction::RedirectToUserspace: return "redirect";
    case TrafficRuleAction::Drop: return "drop";
    }
    return "unknown";
}

} // namespace

bool traffic_matches_flow(const TrafficMatchConfig& config, const FlowKey& key) {
    if (config.rules.empty()) return true;
    for (const auto& rule : config.rules) {
        if (rule_matches_flow(rule, key)) {
            return action_accepts(rule.action);
        }
    }
    return action_accepts(config.default_action);
}

bool traffic_matches_packet(const TrafficMatchConfig& config, const PacketView& packet) {
    if (config.rules.empty()) return true;
    for (const auto& rule : config.rules) {
        if (rule_matches_packet(rule, packet)) {
            return action_accepts(rule.action);
        }
    }
    return action_accepts(config.default_action);
}

std::string describe_traffic_match(const TrafficMatchConfig& config) {
    if (config.rules.empty()) {
        return "accept all";
    }

    std::ostringstream out;
    out << config.rules.size() << " rule";
    if (config.rules.size() != 1) out << 's';
    out << " (default=" << action_name(config.default_action) << ")";

    for (std::size_t i = 0; i < config.rules.size(); ++i) {
        const auto& rule = config.rules[i];
        out << " [" << i << ":";
        if (!rule.label.empty()) out << rule.label << ',';
        out << "src=" << (rule.src_ip ? prefix_to_string(*rule.src_ip) : "any");
        out << ",dst=" << (rule.dst_ip ? prefix_to_string(*rule.dst_ip) : "any");
        if (rule.ip_proto) out << ",proto=" << static_cast<unsigned>(*rule.ip_proto);
        if (rule.src_port) out << ",sport=" << *rule.src_port;
        if (rule.dst_port) out << ",dport=" << *rule.dst_port;
        out << ",action=" << action_name(rule.action) << ']';
    }

    return out.str();
}

} // namespace openpenny::net
