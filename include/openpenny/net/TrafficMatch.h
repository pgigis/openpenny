// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace openpenny {

struct FlowKey;

namespace net {
struct PacketView;

enum class TrafficRuleAction : std::uint32_t {
    Pass = 0,
    RedirectToUserspace = 1,
    Drop = 2
};

struct TrafficIpPrefix {
    std::uint32_t prefix_host{0};
    std::uint32_t mask_host{0};
};

struct TrafficMatchRule {
    bool enabled{true};
    std::optional<TrafficIpPrefix> src_ip{};
    std::optional<TrafficIpPrefix> dst_ip{};
    std::optional<std::uint8_t> ip_proto{};
    std::optional<std::uint16_t> src_port{};
    std::optional<std::uint16_t> dst_port{};
    TrafficRuleAction action{TrafficRuleAction::RedirectToUserspace};
    unsigned target_queue{0};
    bool use_target_queue{false};
    std::string label{};
};

struct TrafficMatchConfig {
    std::vector<TrafficMatchRule> rules{};
    TrafficRuleAction default_action{TrafficRuleAction::Pass};

    bool empty() const noexcept { return rules.empty(); }
};

bool traffic_matches_flow(const TrafficMatchConfig& config, const FlowKey& key);
bool traffic_matches_packet(const TrafficMatchConfig& config, const PacketView& packet);

std::string describe_traffic_match(const TrafficMatchConfig& config);

} // namespace net
} // namespace openpenny
