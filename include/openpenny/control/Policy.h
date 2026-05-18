// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/net/TrafficMatch.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace openpenny::control {

enum class TrafficDecision {
    Include,
    Exclude
};

struct TrafficPolicyRule {
    bool enabled{true};
    std::string name{};
    int priority{0};
    std::optional<net::TrafficIpPrefix> src_ip{};
    std::optional<net::TrafficIpPrefix> dst_ip{};
    std::optional<std::uint8_t> ip_proto{};
    std::optional<std::uint16_t> src_port{};
    std::optional<std::uint16_t> dst_port{};
    TrafficDecision decision{TrafficDecision::Include};
};

struct TrafficPolicy {
    TrafficDecision default_decision{TrafficDecision::Exclude};
    std::vector<TrafficPolicyRule> rules{};
};

enum class RuntimeMode {
    Active,
    Passive
};

struct TestThresholds {
    double packet_drop_probability{0.0};
    double max_duplicate_ratio{0.15};
    double max_reordering_ratio{0.8};
    double retransmission_observation_miss_rate{0.05};
    double retransmission_timeout_in_seconds{3.0};
    double admission_grace_period_seconds{3.0};
    double monitored_flow_idle_expiry_seconds{0.0};
    double drop_state_seconds{0.0};
    int min_packet_drops_per_flow{0};
    int max_packet_drops_per_flow{0};
    int max_packet_drops_global_aggregate{0};
    std::size_t max_monitored_flows{0};
    std::size_t stop_after_individual_flows{0};
    // When >0, the active pipeline stops as soon as this many individual
    // flows have terminated with a per-flow CLOSED_LOOP decision.
    std::size_t min_closed_loop_flows{0};
    std::size_t passive_min_flows_to_finish{0};
    std::size_t passive_max_parallel_flows{5};
    double passive_max_execution_time_seconds{0.0};
};

struct SafetyPolicy {
    bool allow_ssh_bypass{true};
};

struct RuntimePolicy {
    RuntimeMode mode{RuntimeMode::Active};
    TestThresholds thresholds{};
    SafetyPolicy safety{};
    // When true, the active pipeline runs aggregate-level evaluation
    // (cross-flow drop snapshots, aggregate verdict, closed-loop wait).
    // When false, only per-flow heuristics are evaluated.
    bool aggregates_enabled{false};
};

enum class PlatformBackend {
    AfXdp,
    Dpdk
};

struct PlatformConfig {
    PlatformBackend backend{PlatformBackend::AfXdp};
    std::string interface_name{"CHANGE_ME"};
    unsigned queue{0};
    unsigned queue_count{1};
    std::vector<unsigned> worker_cpus{};
    bool prefer_xdp_driver_mode{true};
    bool request_zerocopy{true};
    bool require_zerocopy{true};
    bool allow_skb_fallback{false};
    bool allow_copy_fallback{false};
    bool force_copy_mode{false};
    bool attach_xdp_program{true};
    bool detach_xdp_on_close{true};
    bool pin_maps{true};
    bool reuse_pins{false};
    bool update_dataplane_rules{true};
    unsigned frame_size{2048};
    unsigned num_frames{65536};
    unsigned rx_ring{4096};
    unsigned batch{256};
    unsigned poll_timeout_ms{0};
    unsigned dpdk_burst{32};
    std::string bpf_object{"xdp_redirect_openpenny.o"};
    std::string bpf_program{"xdp_redirect_openpenny"};
};

struct DesiredConfig {
    TrafficPolicy traffic{};
    RuntimePolicy runtime{};
    PlatformConfig platform{};
};

struct CompiledDataplaneConfig {
    PlatformBackend backend{PlatformBackend::AfXdp};
    net::TrafficMatchConfig traffic_match{};
    std::string interface_name{};
    unsigned queue{0};
    unsigned queue_count{1};
    bool allow_ssh_bypass{true};
    std::vector<std::string> warnings{};
    std::string summary{};
};

struct CompiledRuntimeConfig {
    RuntimeMode mode{RuntimeMode::Active};
    TestThresholds thresholds{};
    SafetyPolicy safety{};
    std::string summary{};
};

struct EffectiveConfig {
    DesiredConfig desired{};
    CompiledDataplaneConfig dataplane{};
    CompiledRuntimeConfig runtime{};
    std::vector<std::string> warnings{};
};

const char* to_string(TrafficDecision decision) noexcept;
const char* to_string(RuntimeMode mode) noexcept;
const char* to_string(PlatformBackend backend) noexcept;

} // namespace openpenny::control
