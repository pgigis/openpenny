// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/control/PolicyJson.h"

#include "openpenny/net/TrafficMatch.h"

#include <cstdint>
#include <sstream>

namespace openpenny::control {
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

std::string prefix_to_string(const net::TrafficIpPrefix& prefix) {
    std::ostringstream out;
    out << ip_to_string(prefix.prefix_host) << '/' << mask_bits(prefix.mask_host);
    return out.str();
}

nlohmann::json threshold_json(const TestThresholds& t) {
    return {
        {"packet_drop_probability", t.packet_drop_probability},
        {"max_duplicate_ratio", t.max_duplicate_ratio},
        {"max_reordering_ratio", t.max_reordering_ratio},
        {"retransmission_observation_miss_rate", t.retransmission_observation_miss_rate},
        {"retransmission_timeout_in_seconds", t.retransmission_timeout_in_seconds},
        {"admission_grace_period_seconds", t.admission_grace_period_seconds},
        {"monitored_flow_idle_expiry_seconds", t.monitored_flow_idle_expiry_seconds},
        {"drop_state_seconds", t.drop_state_seconds},
        {"min_packet_drops_per_flow", t.min_packet_drops_per_flow},
        {"max_packet_drops_per_flow", t.max_packet_drops_per_flow},
        {"max_packet_drops_global_aggregate", t.max_packet_drops_global_aggregate},
        {"max_monitored_flows", t.max_monitored_flows},
        {"stop_after_individual_flows", t.stop_after_individual_flows},
        {"min_closed_loop_flows", t.min_closed_loop_flows},
        {"passive_min_flows_to_finish", t.passive_min_flows_to_finish},
        {"passive_max_parallel_flows", t.passive_max_parallel_flows},
        {"passive_max_execution_time_seconds", t.passive_max_execution_time_seconds}
    };
}

} // namespace

nlohmann::json traffic_policy_to_json(const TrafficPolicy& policy) {
    nlohmann::json rules = nlohmann::json::array();
    for (const auto& rule : policy.rules) {
        nlohmann::json item{
            {"enabled", rule.enabled},
            {"name", rule.name},
            {"priority", rule.priority},
            {"decision", to_string(rule.decision)}
        };
        if (rule.src_ip) item["src_prefix"] = prefix_to_string(*rule.src_ip);
        if (rule.dst_ip) item["dst_prefix"] = prefix_to_string(*rule.dst_ip);
        if (rule.ip_proto) item["protocol"] = *rule.ip_proto;
        if (rule.src_port) item["src_port"] = *rule.src_port;
        if (rule.dst_port) item["dst_port"] = *rule.dst_port;
        rules.push_back(std::move(item));
    }

    return {
        {"default", to_string(policy.default_decision)},
        {"rules", std::move(rules)}
    };
}

nlohmann::json runtime_policy_to_json(const RuntimePolicy& policy) {
    return {
        {"mode", to_string(policy.mode)},
        {"aggregates_enabled", policy.aggregates_enabled},
        {"safety", {{"allow_ssh_bypass", policy.safety.allow_ssh_bypass}}},
        {"thresholds", threshold_json(policy.thresholds)}
    };
}

nlohmann::json platform_config_to_json(const PlatformConfig& platform) {
    return {
        {"backend", to_string(platform.backend)},
        {"interface", platform.interface_name},
        {"queue", platform.queue},
        {"queue_count", platform.queue_count},
        {"worker_cpus", platform.worker_cpus},
        {"xdp", {
            {"drv_mode", platform.prefer_xdp_driver_mode},
            {"zerocopy", platform.request_zerocopy},
            {"require_zerocopy", platform.require_zerocopy},
            {"allow_skb_fallback", platform.allow_skb_fallback},
            {"allow_copy_fallback", platform.allow_copy_fallback},
            {"force_copy_mode", platform.force_copy_mode},
            {"attach_program", platform.attach_xdp_program},
            {"detach_on_close", platform.detach_xdp_on_close},
            {"pin_maps", platform.pin_maps},
            {"reuse_pins", platform.reuse_pins},
            {"update_dataplane_rules", platform.update_dataplane_rules},
            {"frame_size", platform.frame_size},
            {"num_frames", platform.num_frames},
            {"rx_ring", platform.rx_ring},
            {"batch", platform.batch},
            {"poll_timeout_ms", platform.poll_timeout_ms},
            {"bpf_object", platform.bpf_object},
            {"bpf_program", platform.bpf_program}
        }},
        {"dpdk", {{"burst", platform.dpdk_burst}}}
    };
}

nlohmann::json desired_config_to_json(const DesiredConfig& desired,
                                      bool include_platform_details) {
    nlohmann::json out{
        {"traffic_policy", traffic_policy_to_json(desired.traffic)},
        {"runtime_policy", runtime_policy_to_json(desired.runtime)}
    };
    if (include_platform_details) {
        out["platform"] = platform_config_to_json(desired.platform);
    }
    return out;
}

nlohmann::json effective_config_to_json(const EffectiveConfig& effective,
                                        bool include_platform_details) {
    nlohmann::json out{
        {"desired", desired_config_to_json(effective.desired, include_platform_details)},
        {"runtime", {
            {"mode", to_string(effective.runtime.mode)},
            {"summary", effective.runtime.summary}
        }},
        {"dataplane", {
            {"summary", effective.dataplane.summary},
            {"traffic_rule_count", effective.dataplane.traffic_match.rules.size()},
            {"traffic_match", net::describe_traffic_match(effective.dataplane.traffic_match)}
        }},
        {"warnings", effective.warnings}
    };
    if (include_platform_details) {
        out["dataplane"]["backend"] = to_string(effective.dataplane.backend);
        out["dataplane"]["interface"] = effective.dataplane.interface_name;
        out["dataplane"]["queue"] = effective.dataplane.queue;
        out["dataplane"]["queue_count"] = effective.dataplane.queue_count;
        out["platform"] = platform_config_to_json(effective.desired.platform);
    }
    return out;
}

} // namespace openpenny::control
