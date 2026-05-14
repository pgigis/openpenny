// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/control/Planner.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <utility>

namespace openpenny::control {
namespace {

net::TrafficRuleAction compile_decision(TrafficDecision decision) {
    return decision == TrafficDecision::Include
        ? net::TrafficRuleAction::RedirectToUserspace
        : net::TrafficRuleAction::Pass;
}

TrafficDecision decision_from_action(net::TrafficRuleAction action) {
    return action == net::TrafficRuleAction::RedirectToUserspace
        ? TrafficDecision::Include
        : TrafficDecision::Exclude;
}

RuntimeMode mode_from_legacy(const Config& cfg) {
    std::string mode = cfg.mode;
    std::transform(mode.begin(), mode.end(), mode.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (mode == "passive" || (cfg.passive.enabled && !cfg.active.enabled)) {
        return RuntimeMode::Passive;
    }
    return RuntimeMode::Active;
}

PlatformBackend backend_from_legacy(PacketInputBackend backend) {
    return backend == PacketInputBackend::Dpdk
        ? PlatformBackend::Dpdk
        : PlatformBackend::AfXdp;
}

PacketInputBackend legacy_backend(PlatformBackend backend) {
    return backend == PlatformBackend::Dpdk
        ? PacketInputBackend::Dpdk
        : PacketInputBackend::XdpAfXdp;
}

} // namespace

net::TrafficMatchConfig compile_traffic_policy(const TrafficPolicy& policy) {
    net::TrafficMatchConfig out{};
    out.default_action = compile_decision(policy.default_decision);

    auto rules = policy.rules;
    std::stable_sort(rules.begin(), rules.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.priority < rhs.priority;
    });

    for (const auto& rule : rules) {
        net::TrafficMatchRule compiled{};
        compiled.enabled = rule.enabled;
        compiled.label = rule.name;
        compiled.src_ip = rule.src_ip;
        compiled.dst_ip = rule.dst_ip;
        compiled.ip_proto = rule.ip_proto;
        compiled.src_port = rule.src_port;
        compiled.dst_port = rule.dst_port;
        compiled.action = compile_decision(rule.decision);
        out.rules.push_back(std::move(compiled));
    }

    if (out.rules.empty()) {
        net::TrafficMatchRule default_rule{};
        default_rule.label = "default-policy";
        default_rule.action = out.default_action;
        out.rules.push_back(std::move(default_rule));
    }

    return out;
}

CompiledRuntimeConfig compile_runtime_policy(const RuntimePolicy& policy) {
    CompiledRuntimeConfig out{};
    out.mode = policy.mode;
    out.thresholds = policy.thresholds;
    out.safety = policy.safety;
    out.summary = std::string("mode=") + to_string(policy.mode);
    return out;
}

CompiledDataplaneConfig compile_dataplane_config(const DesiredConfig& desired) {
    CompiledDataplaneConfig out{};
    out.backend = desired.platform.backend;
    out.interface_name = desired.platform.interface_name;
    out.queue = desired.platform.queue;
    out.queue_count = std::max(1u, desired.platform.queue_count);
    out.allow_ssh_bypass = desired.runtime.safety.allow_ssh_bypass;
    out.traffic_match = compile_traffic_policy(desired.traffic);

    if (out.backend == PlatformBackend::AfXdp && out.traffic_match.rules.size() > 1) {
        out.warnings.push_back("AF_XDP currently supports one compiled dataplane rule");
    }
    if (!desired.platform.worker_cpus.empty() &&
        desired.platform.worker_cpus.size() < out.queue_count) {
        out.warnings.push_back("worker_cpus has fewer entries than queue_count; remaining queues use CPU index fallback");
    }

    std::ostringstream summary;
    summary << "backend=" << to_string(out.backend)
            << " interface=" << out.interface_name
            << " queue=" << out.queue
            << " queue_count=" << out.queue_count
            << " traffic_rules=" << out.traffic_match.rules.size();
    out.summary = summary.str();
    return out;
}

EffectiveConfig compile_effective_config(const DesiredConfig& desired) {
    EffectiveConfig out{};
    out.desired = desired;
    out.dataplane = compile_dataplane_config(desired);
    out.runtime = compile_runtime_policy(desired.runtime);
    out.warnings = out.dataplane.warnings;
    return out;
}

DesiredConfig desired_from_legacy_config(const Config& cfg) {
    DesiredConfig desired{};

    desired.traffic.default_decision = decision_from_action(cfg.traffic_match.default_action);
    int priority = 0;
    for (const auto& rule : cfg.traffic_match.rules) {
        TrafficPolicyRule policy_rule{};
        policy_rule.enabled = rule.enabled;
        policy_rule.name = rule.label;
        policy_rule.priority = priority++;
        policy_rule.src_ip = rule.src_ip;
        policy_rule.dst_ip = rule.dst_ip;
        policy_rule.ip_proto = rule.ip_proto;
        policy_rule.src_port = rule.src_port;
        policy_rule.dst_port = rule.dst_port;
        policy_rule.decision = decision_from_action(rule.action);
        desired.traffic.rules.push_back(std::move(policy_rule));
    }

    desired.runtime.mode = mode_from_legacy(cfg);
    desired.runtime.safety.allow_ssh_bypass = cfg.xdp_runtime.allow_ssh_bypass;
    desired.runtime.aggregates_enabled = cfg.active.aggregates_enabled;
    desired.runtime.thresholds.packet_drop_probability = cfg.active.drop_probability;
    desired.runtime.thresholds.max_duplicate_ratio = cfg.active.max_duplicate_fraction;
    desired.runtime.thresholds.max_reordering_ratio = cfg.active.max_out_of_order_fraction;
    desired.runtime.thresholds.retransmission_observation_miss_rate =
        cfg.active.retransmission_miss_probability;
    desired.runtime.thresholds.retransmission_timeout_in_seconds = cfg.active.rtt_timeout_factor;
    desired.runtime.thresholds.admission_grace_period_seconds = cfg.active.flow_grace_period_seconds;
    desired.runtime.thresholds.monitored_flow_idle_expiry_seconds = cfg.active.flow_idle_timeout_seconds;
    desired.runtime.thresholds.drop_state_seconds = cfg.active.drop_state_seconds;
    desired.runtime.thresholds.min_packet_drops_per_flow = cfg.active.min_drops_per_flow;
    desired.runtime.thresholds.max_packet_drops_per_flow = cfg.active.max_drops_per_indiv_flow;
    desired.runtime.thresholds.max_packet_drops_global_aggregate = cfg.active.max_drops_aggregates;
    desired.runtime.thresholds.max_monitored_flows = cfg.active.max_tracked_flows;
    desired.runtime.thresholds.stop_after_individual_flows = cfg.active.stop_after_individual_flows;
    desired.runtime.thresholds.min_closed_loop_flows = cfg.active.min_closed_loop_flows;
    desired.runtime.thresholds.passive_min_flows_to_finish = cfg.passive.min_number_of_flows_to_finish;
    desired.runtime.thresholds.passive_max_parallel_flows = cfg.passive.max_parallel_flows;
    desired.runtime.thresholds.passive_max_execution_time_seconds =
        cfg.passive.max_execution_time_seconds;

    desired.platform.backend = backend_from_legacy(cfg.input.backend);
    desired.platform.interface_name = cfg.ifname;
    desired.platform.queue = cfg.queue;
    desired.platform.queue_count = cfg.queue_count;
    desired.platform.worker_cpus = cfg.worker_cpus;
    desired.platform.prefer_xdp_driver_mode = cfg.xdp_drv_mode;
    desired.platform.request_zerocopy = cfg.zerocopy;
    desired.platform.require_zerocopy = cfg.xdp_runtime.require_zerocopy;
    desired.platform.allow_skb_fallback = cfg.xdp_runtime.allow_skb_fallback;
    desired.platform.allow_copy_fallback = cfg.xdp_runtime.allow_copy_fallback;
    desired.platform.force_copy_mode = cfg.xdp_runtime.force_copy_mode;
    desired.platform.attach_xdp_program = cfg.xdp_runtime.attach_program;
    desired.platform.detach_xdp_on_close = cfg.xdp_runtime.detach_on_close;
    desired.platform.pin_maps = cfg.xdp_runtime.pin_maps;
    desired.platform.reuse_pins = cfg.xdp_runtime.reuse_pins;
    desired.platform.update_dataplane_rules = cfg.xdp_runtime.update_conf_map;
    desired.platform.frame_size = cfg.frame_size;
    desired.platform.num_frames = cfg.num_frames;
    desired.platform.rx_ring = cfg.rx_ring;
    desired.platform.batch = cfg.xdp_runtime.batch;
    desired.platform.poll_timeout_ms = cfg.xdp_runtime.poll_timeout_ms;
    desired.platform.dpdk_burst = cfg.dpdk.burst;
    desired.platform.bpf_object = cfg.xdp_runtime.bpf_object;
    desired.platform.bpf_program = cfg.xdp_runtime.bpf_program;

    return desired;
}

void apply_desired_config_to_legacy(Config& cfg, const DesiredConfig& desired) {
    cfg.traffic_match = compile_traffic_policy(desired.traffic);

    cfg.mode = to_string(desired.runtime.mode);
    cfg.active.enabled = desired.runtime.mode == RuntimeMode::Active;
    cfg.passive.enabled = desired.runtime.mode == RuntimeMode::Passive;
    cfg.xdp_runtime.allow_ssh_bypass = desired.runtime.safety.allow_ssh_bypass;
    cfg.active.aggregates_enabled = desired.runtime.aggregates_enabled;

    const auto& t = desired.runtime.thresholds;
    cfg.active.drop_probability = t.packet_drop_probability;
    cfg.active.max_duplicate_fraction = t.max_duplicate_ratio;
    cfg.active.max_out_of_order_fraction = t.max_reordering_ratio;
    cfg.active.retransmission_miss_probability = t.retransmission_observation_miss_rate;
    cfg.active.rtt_timeout_factor = t.retransmission_timeout_in_seconds;
    cfg.active.flow_grace_period_seconds = t.admission_grace_period_seconds;
    cfg.active.flow_idle_timeout_seconds = t.monitored_flow_idle_expiry_seconds;
    cfg.active.drop_state_seconds = t.drop_state_seconds;
    cfg.active.min_drops_per_flow = t.min_packet_drops_per_flow;
    cfg.active.max_drops_per_indiv_flow = t.max_packet_drops_per_flow;
    cfg.active.max_drops_aggregates = t.max_packet_drops_global_aggregate;
    cfg.active.max_tracked_flows = t.max_monitored_flows;
    cfg.active.stop_after_individual_flows = t.stop_after_individual_flows;
    cfg.active.min_closed_loop_flows = t.min_closed_loop_flows;
    cfg.passive.min_number_of_flows_to_finish = t.passive_min_flows_to_finish;
    cfg.passive.max_parallel_flows = t.passive_max_parallel_flows;
    cfg.passive.max_execution_time_seconds = t.passive_max_execution_time_seconds;

    cfg.input.backend = legacy_backend(desired.platform.backend);
    cfg.ifname = desired.platform.interface_name;
    cfg.queue = desired.platform.queue;
    cfg.queue_count = std::max(1u, desired.platform.queue_count);
    cfg.worker_cpus = desired.platform.worker_cpus;
    cfg.xdp_drv_mode = desired.platform.prefer_xdp_driver_mode;
    cfg.zerocopy = desired.platform.request_zerocopy;
    cfg.frame_size = desired.platform.frame_size;
    cfg.num_frames = desired.platform.num_frames;
    cfg.rx_ring = desired.platform.rx_ring;
    cfg.xdp_runtime.attach_program = desired.platform.attach_xdp_program;
    cfg.xdp_runtime.detach_on_close = desired.platform.detach_xdp_on_close;
    cfg.xdp_runtime.pin_maps = desired.platform.pin_maps;
    cfg.xdp_runtime.reuse_pins = desired.platform.reuse_pins;
    cfg.xdp_runtime.update_conf_map = desired.platform.update_dataplane_rules;
    cfg.xdp_runtime.require_zerocopy = desired.platform.require_zerocopy;
    cfg.xdp_runtime.allow_skb_fallback = desired.platform.allow_skb_fallback;
    cfg.xdp_runtime.allow_copy_fallback = desired.platform.allow_copy_fallback;
    cfg.xdp_runtime.force_copy_mode = desired.platform.force_copy_mode;
    cfg.xdp_runtime.batch = desired.platform.batch;
    cfg.xdp_runtime.poll_timeout_ms = desired.platform.poll_timeout_ms;
    cfg.xdp_runtime.bpf_object = desired.platform.bpf_object;
    cfg.xdp_runtime.bpf_program = desired.platform.bpf_program;
    cfg.dpdk.burst = desired.platform.dpdk_burst;
}

} // namespace openpenny::control
