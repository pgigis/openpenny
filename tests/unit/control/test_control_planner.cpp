// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: the control-plane planner translates desired policy
// objects into the compiled artifacts the dataplane consumes.
//
// Four scenarios:
//   1. compile_traffic_policy() sorts rules by priority (lower first)
//      and translates Include/Exclude to RedirectToUserspace/Pass.
//   2. A full five-tuple rule survives compilation with every field
//      preserved.
//   3. compile_effective_config() produces an EffectiveConfig whose
//      runtime mode and dataplane fields mirror the inputs. Warnings
//      are non-empty because the example here pairs passive mode with
//      AfXdp redirect, which the planner flags.
//   4. desired_from_legacy_config() round-trips the legacy fields
//      (cfg.input.backend, cfg.ifname, cfg.queue, cfg.passive.enabled,
//      cfg.traffic_match) into the modern DesiredConfig.
//
// If this fails: policy edits via gRPC or YAML do not reach the
// dataplane in the expected shape.

#include "openpenny/control/Planner.h"

#include <cassert>
#include <iostream>

int main() {
    using namespace openpenny::control;
    using openpenny::net::TrafficIpPrefix;
    using openpenny::net::TrafficRuleAction;

    {
        std::cout << "scenario: rules sort by priority; Include/Exclude map to redirect/pass\n";
        TrafficPolicy policy{};
        policy.default_decision = TrafficDecision::Exclude;

        TrafficPolicyRule include_rule{};
        include_rule.name     = "https";
        include_rule.priority = 20;
        include_rule.dst_port = 443;
        include_rule.decision = TrafficDecision::Include;

        TrafficPolicyRule exclude_rule{};
        exclude_rule.name     = "ssh";
        exclude_rule.priority = 10;
        exclude_rule.dst_port = 22;
        exclude_rule.decision = TrafficDecision::Exclude;

        policy.rules.push_back(include_rule);
        policy.rules.push_back(exclude_rule);

        const auto compiled = compile_traffic_policy(policy);
        assert(compiled.rules.size()    == 2);
        assert(compiled.rules[0].label  == "ssh");                          // priority 10 sorts first
        assert(compiled.rules[0].action == TrafficRuleAction::Pass);
        assert(compiled.rules[1].label  == "https");
        assert(compiled.rules[1].action == TrafficRuleAction::RedirectToUserspace);
        assert(compiled.default_action  == TrafficRuleAction::Pass);
    }

    {
        std::cout << "scenario: a full five-tuple rule round-trips through compile\n";
        TrafficPolicy policy{};
        TrafficPolicyRule rule{};
        rule.name     = "five-tuple";
        rule.src_ip   = TrafficIpPrefix{0x0a000000u, 0xff000000u};
        rule.dst_ip   = TrafficIpPrefix{0xcb007100u, 0xffffff00u};
        rule.ip_proto = 6;
        rule.src_port = 12345;
        rule.dst_port = 443;
        policy.rules.push_back(rule);

        const auto compiled = compile_traffic_policy(policy);
        assert(compiled.rules.size() == 1);
        assert(compiled.rules[0].src_ip.has_value());
        assert(compiled.rules[0].dst_ip.has_value());
        assert(compiled.rules[0].ip_proto == 6);
        assert(compiled.rules[0].src_port == 12345);
        assert(compiled.rules[0].dst_port == 443);
    }

    {
        std::cout << "scenario: compile_effective_config mirrors desired into runtime + dataplane\n";

        // Build a small desired config and ensure the compiled effective
        // config reflects mode/interface/queues correctly. The mismatch
        // between passive mode and the AfXdp backend should emit a
        // warning rather than silently picking one.
        TrafficPolicy policy{};
        TrafficPolicyRule rule{};
        rule.name     = "https";
        rule.dst_port = 443;
        rule.decision = TrafficDecision::Include;
        policy.rules.push_back(rule);

        DesiredConfig desired{};
        desired.traffic                       = policy;
        desired.runtime.mode                  = RuntimeMode::Passive;
        desired.runtime.safety.allow_ssh_bypass = false;
        desired.platform.backend              = PlatformBackend::AfXdp;
        desired.platform.interface_name       = "eth0";
        desired.platform.queue                = 0;
        desired.platform.queue_count          = 2;
        desired.platform.worker_cpus          = {4, 5};

        const auto effective = compile_effective_config(desired);
        assert(effective.runtime.mode               == RuntimeMode::Passive);
        assert(effective.dataplane.interface_name   == "eth0");
        assert(effective.dataplane.queue_count      == 2);
        assert(!effective.warnings.empty());
    }

    {
        std::cout << "scenario: desired_from_legacy_config translates the legacy fields\n";
        openpenny::Config legacy{};
        legacy.input.backend   = openpenny::PacketInputBackend::Dpdk;
        legacy.ifname          = "0000:01:00.0";
        legacy.queue           = 3;
        legacy.queue_count     = 1;
        legacy.worker_cpus     = {7};
        legacy.mode            = "passive";
        legacy.passive.enabled = true;
        legacy.active.enabled  = false;

        // Plus the two compiled traffic rules from the first scenario.
        TrafficPolicy seed{};
        seed.default_decision = TrafficDecision::Exclude;
        TrafficPolicyRule https{};
        https.priority = 20;
        https.dst_port = 443;
        https.decision = TrafficDecision::Include;
        TrafficPolicyRule ssh{};
        ssh.priority = 10;
        ssh.dst_port = 22;
        ssh.decision = TrafficDecision::Exclude;
        seed.rules.push_back(https);
        seed.rules.push_back(ssh);
        legacy.traffic_match = compile_traffic_policy(seed);

        const auto desired = desired_from_legacy_config(legacy);
        assert(desired.platform.backend         == PlatformBackend::Dpdk);
        assert(desired.platform.interface_name  == "0000:01:00.0");
        assert(desired.platform.queue           == 3);
        assert(desired.platform.worker_cpus.size() == 1);
        assert(desired.platform.worker_cpus[0]  == 7);
        assert(desired.runtime.mode             == RuntimeMode::Passive);
        assert(desired.traffic.rules.size()     == 2);
    }

    return 0;
}
