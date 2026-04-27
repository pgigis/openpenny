// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/control/Planner.h"

#include <cassert>

int main() {
    openpenny::control::TrafficPolicy policy{};
    policy.default_decision = openpenny::control::TrafficDecision::Exclude;

    openpenny::control::TrafficPolicyRule include_rule{};
    include_rule.name = "https";
    include_rule.priority = 20;
    include_rule.dst_port = 443;
    include_rule.decision = openpenny::control::TrafficDecision::Include;

    openpenny::control::TrafficPolicyRule exclude_rule{};
    exclude_rule.name = "ssh";
    exclude_rule.priority = 10;
    exclude_rule.dst_port = 22;
    exclude_rule.decision = openpenny::control::TrafficDecision::Exclude;

    policy.rules.push_back(include_rule);
    policy.rules.push_back(exclude_rule);

    auto compiled = openpenny::control::compile_traffic_policy(policy);
    assert(compiled.rules.size() == 2);
    assert(compiled.rules[0].label == "ssh");
    assert(compiled.rules[0].action == openpenny::net::TrafficRuleAction::Pass);
    assert(compiled.rules[1].label == "https");
    assert(compiled.rules[1].action == openpenny::net::TrafficRuleAction::RedirectToUserspace);
    assert(compiled.default_action == openpenny::net::TrafficRuleAction::Pass);

    openpenny::control::TrafficPolicy five_tuple_policy{};
    openpenny::control::TrafficPolicyRule five_tuple_rule{};
    five_tuple_rule.name = "five-tuple";
    five_tuple_rule.src_ip = openpenny::net::TrafficIpPrefix{0x0a000000u, 0xff000000u};
    five_tuple_rule.dst_ip = openpenny::net::TrafficIpPrefix{0xcb007100u, 0xffffff00u};
    five_tuple_rule.ip_proto = 6;
    five_tuple_rule.src_port = 12345;
    five_tuple_rule.dst_port = 443;
    five_tuple_policy.rules.push_back(five_tuple_rule);

    auto five_tuple_compiled = openpenny::control::compile_traffic_policy(five_tuple_policy);
    assert(five_tuple_compiled.rules.size() == 1);
    assert(five_tuple_compiled.rules[0].src_ip.has_value());
    assert(five_tuple_compiled.rules[0].dst_ip.has_value());
    assert(five_tuple_compiled.rules[0].ip_proto == 6);
    assert(five_tuple_compiled.rules[0].src_port == 12345);
    assert(five_tuple_compiled.rules[0].dst_port == 443);

    openpenny::control::DesiredConfig desired{};
    desired.traffic = policy;
    desired.runtime.mode = openpenny::control::RuntimeMode::Passive;
    desired.runtime.safety.allow_ssh_bypass = false;
    desired.platform.backend = openpenny::control::PlatformBackend::AfXdp;
    desired.platform.interface_name = "eth0";
    desired.platform.queue = 0;
    desired.platform.queue_count = 2;
    desired.platform.worker_cpus = {4, 5};

    auto effective = openpenny::control::compile_effective_config(desired);
    assert(effective.runtime.mode == openpenny::control::RuntimeMode::Passive);
    assert(effective.dataplane.interface_name == "eth0");
    assert(effective.dataplane.queue_count == 2);
    assert(!effective.warnings.empty());

    openpenny::Config legacy{};
    legacy.input.backend = openpenny::PacketInputBackend::Dpdk;
    legacy.ifname = "0000:01:00.0";
    legacy.queue = 3;
    legacy.queue_count = 1;
    legacy.worker_cpus = {7};
    legacy.mode = "passive";
    legacy.passive.enabled = true;
    legacy.active.enabled = false;
    legacy.traffic_match = compiled;

    auto desired_from_legacy = openpenny::control::desired_from_legacy_config(legacy);
    assert(desired_from_legacy.platform.backend == openpenny::control::PlatformBackend::Dpdk);
    assert(desired_from_legacy.platform.interface_name == "0000:01:00.0");
    assert(desired_from_legacy.platform.queue == 3);
    assert(desired_from_legacy.platform.worker_cpus.size() == 1);
    assert(desired_from_legacy.platform.worker_cpus[0] == 7);
    assert(desired_from_legacy.runtime.mode == openpenny::control::RuntimeMode::Passive);
    assert(desired_from_legacy.traffic.rules.size() == 2);

    return 0;
}
