// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/grpc/PennyService.h"

#include "openpenny/app/core/WorkerLauncher.h"
#include "openpenny/config/Config.h"
#include "openpenny/control/Planner.h"
#include "openpenny/control/PolicyJson.h"
#include "openpenny/log/Log.h"

#include <arpa/inet.h>
#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <yaml-cpp/yaml.h>
#include <grpcpp/grpcpp.h>
#include <cstdio>
#include <fstream>
#include <limits>
#include <optional>
#include <vector>
#include <regex>
#include <system_error>

namespace openpenny::grpc_service {

/**
 * @brief Construct a PennyServiceImpl with default configuration values and an optional
 *        configuration-path override.
 */
PennyServiceImpl::PennyServiceImpl(const Config& defaults, std::string config_path)
    : defaults_(defaults), config_path_(std::move(config_path)) {
    desired_config_ = defaults_.desired_config;
    effective_config_ = defaults_.effective_config.warnings.empty() &&
                                defaults_.effective_config.dataplane.summary.empty()
                            ? control::compile_effective_config(desired_config_)
                            : defaults_.effective_config;
}

/**
 * @brief Load the configuration from file if a path is provided.
 *        Falls back to the given default configuration.
 */
Config PennyServiceImpl::load_defaults() const {
    if (config_path_.empty()) return defaults_;
    auto loaded = Config::from_file(config_path_);
    if (loaded) return *loaded;
    return defaults_;
}

/**
 * @brief Construct pipeline options from the incoming gRPC request.
 *        Only fields explicitly provided by the client override defaults.
 */
PipelineOptions PennyServiceImpl::make_options(const openpenny::api::StartTestRequest& req) const {
    PipelineOptions opts{};

    // Note: prefix / mask / tun / forward_* fields no longer live on
    // PipelineOptions. They are handed to the worker subprocess via
    // WorkerLaunchConfig (prefix/mask) and Config::egress (TUN/raw sink),
    // both populated later in StartTest(). `opts` now only carries
    // per-run behaviour: mode, queue count, stats socket.

    // Pipeline mode (active/passive).
    if (req.has_mode() && req.mode() == "passive") {
        opts.mode = PipelineOptions::Mode::Passive;
    } else {
        opts.mode = PipelineOptions::Mode::Active;
    }

    // Stats UNIX socket path.
    if (req.has_stats_socket_path() && !req.stats_socket_path().empty()) {
        opts.stats_socket_path = req.stats_socket_path();
    }

    return opts;
}

namespace {

std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::uint32_t mask_from_bits(int bits) {
    if (bits <= 0) return 0;
    if (bits >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - bits);
}

std::string ip_to_string(std::uint32_t host) {
    return std::to_string((host >> 24) & 0xff) + "." +
           std::to_string((host >> 16) & 0xff) + "." +
           std::to_string((host >> 8) & 0xff) + "." +
           std::to_string(host & 0xff);
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
    return ip_to_string(prefix.prefix_host) + "/" + std::to_string(mask_bits(prefix.mask_host));
}

std::optional<net::TrafficIpPrefix> parse_prefix(const std::string& text) {
    if (text.empty()) return std::nullopt;

    const auto slash = text.find('/');
    const std::string ip_text = text.substr(0, slash);
    int bits = 32;
    if (slash != std::string::npos) {
        try {
            const auto bits_text = text.substr(slash + 1);
            std::size_t parsed_chars = 0;
            bits = std::stoi(bits_text, &parsed_chars);
            if (parsed_chars != bits_text.size()) return std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
        if (bits < 0 || bits > 32) return std::nullopt;
    }

    in_addr addr{};
    if (inet_pton(AF_INET, ip_text.c_str(), &addr) != 1) {
        return std::nullopt;
    }
    return net::TrafficIpPrefix{ntohl(addr.s_addr), mask_from_bits(bits)};
}

std::optional<std::uint8_t> parse_protocol(const std::string& value) {
    if (value.empty()) return std::nullopt;
    const auto normalised = lower_copy(value);
    if (normalised == "tcp") return 6;
    if (normalised == "udp") return 17;
    if (normalised == "icmp") return 1;
    try {
        std::size_t parsed_chars = 0;
        const int proto = std::stoi(normalised, &parsed_chars);
        if (parsed_chars == normalised.size() && proto >= 0 && proto <= 255) {
            return static_cast<std::uint8_t>(proto);
        }
    } catch (...) {}
    return std::nullopt;
}

api::TrafficDecision to_proto(control::TrafficDecision decision) {
    return decision == control::TrafficDecision::Include
        ? api::TRAFFIC_DECISION_INCLUDE
        : api::TRAFFIC_DECISION_EXCLUDE;
}

api::RuntimeMode to_proto(control::RuntimeMode mode) {
    return mode == control::RuntimeMode::Active
        ? api::RUNTIME_MODE_ACTIVE
        : api::RUNTIME_MODE_PASSIVE;
}

std::optional<control::TrafficDecision> traffic_decision_from_proto(api::TrafficDecision decision) {
    switch (decision) {
    case api::TRAFFIC_DECISION_INCLUDE:
        return control::TrafficDecision::Include;
    case api::TRAFFIC_DECISION_EXCLUDE:
        return control::TrafficDecision::Exclude;
    case api::TRAFFIC_DECISION_UNSPECIFIED:
    default:
        return std::nullopt;
    }
}

std::optional<control::RuntimeMode> runtime_mode_from_proto(api::RuntimeMode mode) {
    switch (mode) {
    case api::RUNTIME_MODE_ACTIVE:
        return control::RuntimeMode::Active;
    case api::RUNTIME_MODE_PASSIVE:
        return control::RuntimeMode::Passive;
    case api::RUNTIME_MODE_UNSPECIFIED:
    default:
        return std::nullopt;
    }
}

void fill_proto_traffic_policy(const control::TrafficPolicy& src,
                               api::TrafficPolicy* dst) {
    dst->Clear();
    dst->set_default_decision(to_proto(src.default_decision));
    for (const auto& rule : src.rules) {
        auto* item = dst->add_rules();
        item->set_enabled(rule.enabled);
        item->set_name(rule.name);
        item->set_priority(rule.priority);
        item->set_decision(to_proto(rule.decision));
        if (rule.src_ip) {
            item->set_src_prefix(prefix_to_string(*rule.src_ip));
        }
        if (rule.dst_ip) {
            item->set_dst_prefix(prefix_to_string(*rule.dst_ip));
        }
        if (rule.ip_proto) item->set_protocol(std::to_string(*rule.ip_proto));
        if (rule.src_port) item->set_src_port(*rule.src_port);
        if (rule.dst_port) item->set_dst_port(*rule.dst_port);
    }
}

void fill_proto_runtime_policy(const control::RuntimePolicy& src,
                               api::RuntimePolicy* dst) {
    dst->Clear();
    dst->set_mode(to_proto(src.mode));
    dst->mutable_safety()->set_allow_ssh_bypass(src.safety.allow_ssh_bypass);
    auto* thresholds = dst->mutable_thresholds();
    thresholds->set_packet_drop_probability(src.thresholds.packet_drop_probability);
    thresholds->set_max_duplicate_ratio(src.thresholds.max_duplicate_ratio);
    thresholds->set_max_reordering_ratio(src.thresholds.max_reordering_ratio);
    thresholds->set_retransmission_observation_miss_rate(
        src.thresholds.retransmission_observation_miss_rate);
    thresholds->set_retransmission_timeout_in_seconds(
        src.thresholds.retransmission_timeout_in_seconds);
    thresholds->set_admission_grace_period_seconds(
        src.thresholds.admission_grace_period_seconds);
    thresholds->set_monitored_flow_idle_expiry_seconds(
        src.thresholds.monitored_flow_idle_expiry_seconds);
    thresholds->set_drop_state_seconds(src.thresholds.drop_state_seconds);
    thresholds->set_min_packet_drops_per_flow(
        static_cast<std::uint32_t>(src.thresholds.min_packet_drops_per_flow));
    thresholds->set_max_packet_drops_per_flow(
        static_cast<std::uint32_t>(src.thresholds.max_packet_drops_per_flow));
    thresholds->set_max_packet_drops_global_aggregate(
        static_cast<std::uint32_t>(src.thresholds.max_packet_drops_global_aggregate));
    thresholds->set_max_monitored_flows(src.thresholds.max_monitored_flows);
    thresholds->set_stop_after_individual_flows(src.thresholds.stop_after_individual_flows);
    thresholds->set_min_closed_loop_flows(src.thresholds.min_closed_loop_flows);
    thresholds->set_passive_min_flows_to_finish(src.thresholds.passive_min_flows_to_finish);
    thresholds->set_passive_max_parallel_flows(src.thresholds.passive_max_parallel_flows);
    thresholds->set_passive_max_execution_time_seconds(
        src.thresholds.passive_max_execution_time_seconds);
}

void fill_proto_penny_config(const control::DesiredConfig& src,
                             api::PennyConfig* dst) {
    dst->Clear();
    fill_proto_traffic_policy(src.traffic, dst->mutable_traffic_policy());
    fill_proto_runtime_policy(src.runtime, dst->mutable_runtime_policy());
}

bool assign_port(std::uint32_t value,
                 std::optional<std::uint16_t>& target,
                 std::string& error,
                 const char* field) {
    if (value > std::numeric_limits<std::uint16_t>::max()) {
        error = std::string(field) + " must be between 0 and 65535";
        return false;
    }
    target = static_cast<std::uint16_t>(value);
    return true;
}

std::optional<control::TrafficPolicy> traffic_policy_from_proto(
    const api::TrafficPolicy& src,
    const control::TrafficPolicy& base,
    std::string& error) {
    control::TrafficPolicy out{};
    out.default_decision = base.default_decision;
    if (auto decision = traffic_decision_from_proto(src.default_decision())) {
        out.default_decision = *decision;
    }

    int implicit_priority = 0;
    for (const auto& proto_rule : src.rules()) {
        control::TrafficPolicyRule rule{};
        rule.priority = implicit_priority++;
        if (proto_rule.has_enabled()) rule.enabled = proto_rule.enabled();
        if (proto_rule.has_name()) rule.name = proto_rule.name();
        if (proto_rule.has_priority()) rule.priority = proto_rule.priority();
        if (auto decision = traffic_decision_from_proto(proto_rule.decision())) {
            rule.decision = *decision;
        }
        if (proto_rule.has_src_prefix()) {
            auto parsed = parse_prefix(proto_rule.src_prefix());
            if (!parsed) {
                error = "invalid source prefix: " + proto_rule.src_prefix();
                return std::nullopt;
            }
            rule.src_ip = *parsed;
        }
        if (proto_rule.has_dst_prefix()) {
            auto parsed = parse_prefix(proto_rule.dst_prefix());
            if (!parsed) {
                error = "invalid destination prefix: " + proto_rule.dst_prefix();
                return std::nullopt;
            }
            rule.dst_ip = *parsed;
        }
        if (proto_rule.has_protocol()) {
            auto parsed = parse_protocol(proto_rule.protocol());
            if (!parsed) {
                error = "invalid protocol: " + proto_rule.protocol();
                return std::nullopt;
            }
            rule.ip_proto = *parsed;
        }
        if (proto_rule.has_src_port() &&
            !assign_port(proto_rule.src_port(), rule.src_port, error, "src_port")) {
            return std::nullopt;
        }
        if (proto_rule.has_dst_port() &&
            !assign_port(proto_rule.dst_port(), rule.dst_port, error, "dst_port")) {
            return std::nullopt;
        }
        out.rules.push_back(std::move(rule));
    }
    return out;
}

std::optional<control::RuntimePolicy> runtime_policy_from_proto(
    const api::RuntimePolicy& src,
    const control::RuntimePolicy& base,
    std::string& error) {
    control::RuntimePolicy out = base;
    if (auto mode = runtime_mode_from_proto(src.mode())) {
        out.mode = *mode;
    }
    if (src.has_safety() && src.safety().has_allow_ssh_bypass()) {
        out.safety.allow_ssh_bypass = src.safety().allow_ssh_bypass();
    }
    if (src.has_thresholds()) {
        const auto& thresholds = src.thresholds();
        auto& t = out.thresholds;
        if (thresholds.has_packet_drop_probability()) {
            t.packet_drop_probability = thresholds.packet_drop_probability();
        }
        if (thresholds.has_max_duplicate_ratio()) {
            t.max_duplicate_ratio = thresholds.max_duplicate_ratio();
        }
        if (thresholds.has_max_reordering_ratio()) {
            t.max_reordering_ratio = thresholds.max_reordering_ratio();
        }
        if (thresholds.has_retransmission_observation_miss_rate()) {
            t.retransmission_observation_miss_rate =
                thresholds.retransmission_observation_miss_rate();
        }
        if (thresholds.has_retransmission_timeout_in_seconds()) {
            t.retransmission_timeout_in_seconds =
                thresholds.retransmission_timeout_in_seconds();
        }
        if (thresholds.has_admission_grace_period_seconds()) {
            t.admission_grace_period_seconds = thresholds.admission_grace_period_seconds();
        }
        if (thresholds.has_monitored_flow_idle_expiry_seconds()) {
            t.monitored_flow_idle_expiry_seconds =
                thresholds.monitored_flow_idle_expiry_seconds();
        }
        if (thresholds.has_drop_state_seconds()) {
            t.drop_state_seconds = thresholds.drop_state_seconds();
        }
        if (thresholds.has_min_packet_drops_per_flow()) {
            t.min_packet_drops_per_flow =
                static_cast<int>(thresholds.min_packet_drops_per_flow());
        }
        if (thresholds.has_max_packet_drops_per_flow()) {
            t.max_packet_drops_per_flow =
                static_cast<int>(thresholds.max_packet_drops_per_flow());
        }
        if (thresholds.has_max_packet_drops_global_aggregate()) {
            t.max_packet_drops_global_aggregate =
                static_cast<int>(thresholds.max_packet_drops_global_aggregate());
        }
        if (thresholds.has_max_monitored_flows()) {
            t.max_monitored_flows = static_cast<std::size_t>(thresholds.max_monitored_flows());
        }
        if (thresholds.has_stop_after_individual_flows()) {
            t.stop_after_individual_flows =
                static_cast<std::size_t>(thresholds.stop_after_individual_flows());
        }
        if (thresholds.has_min_closed_loop_flows()) {
            t.min_closed_loop_flows =
                static_cast<std::size_t>(thresholds.min_closed_loop_flows());
        }
        if (thresholds.has_passive_min_flows_to_finish()) {
            t.passive_min_flows_to_finish =
                static_cast<std::size_t>(thresholds.passive_min_flows_to_finish());
        }
        if (thresholds.has_passive_max_parallel_flows()) {
            t.passive_max_parallel_flows =
                static_cast<std::size_t>(thresholds.passive_max_parallel_flows());
        }
        if (thresholds.has_passive_max_execution_time_seconds()) {
            t.passive_max_execution_time_seconds =
                thresholds.passive_max_execution_time_seconds();
        }
    }

    const auto probability_valid = [](double value) {
        return value >= 0.0 && value <= 1.0;
    };
    if (!probability_valid(out.thresholds.packet_drop_probability) ||
        !probability_valid(out.thresholds.max_duplicate_ratio) ||
        !probability_valid(out.thresholds.max_reordering_ratio) ||
        !probability_valid(out.thresholds.retransmission_observation_miss_rate)) {
        error = "probability thresholds must be between 0 and 1";
        return std::nullopt;
    }
    if (out.thresholds.retransmission_timeout_in_seconds <= 0.0) {
        error = "retransmission_timeout_in_seconds must be positive";
        return std::nullopt;
    }
    return out;
}

void fill_config_response(api::ConfigResponse* response,
                          const control::DesiredConfig& desired,
                          const control::EffectiveConfig& effective,
                          const std::string& status,
                          bool include_platform_details) {
    response->set_status(status);
    fill_proto_penny_config(desired, response->mutable_desired_config());
    response->set_desired_config_json(
        control::desired_config_to_json(desired, include_platform_details).dump());
    response->set_effective_config_json(
        control::effective_config_to_json(effective, include_platform_details).dump());
    response->clear_warnings();
    for (const auto& warning : effective.warnings) {
        response->add_warnings(warning);
    }
}

/**
 * @brief Parse a "key=value" line into separate key and value strings.
 */
bool parse_kv_line(const std::string& line, std::string& key, std::string& value) {
    auto pos = line.find('=');
    if (pos == std::string::npos) return false;
    key = line.substr(0, pos);
    value = line.substr(pos + 1);
    return true;
}

} // namespace
namespace {
nlohmann::json yaml_to_json(const YAML::Node& node) {
    if (!node) return nullptr;
    if (node.IsScalar()) {
        const std::string s = node.as<std::string>();
        static const std::regex int_re(R"(^-?\d+$)");
        static const std::regex num_re(R"(^-?\d+(\.\d+)?$)");
        if (std::regex_match(s, int_re)) {
            try {
                return std::stoll(s);
            } catch (...) {
                return s;
            }
        }
        if (std::regex_match(s, num_re)) {
            try {
                return std::stod(s);
            } catch (...) {
                return s;
            }
        }
        return s;
    }
    if (node.IsSequence()) {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& v : node) arr.push_back(yaml_to_json(v));
        return arr;
    }
    if (node.IsMap()) {
        nlohmann::json obj = nlohmann::json::object();
        for (const auto& it : node) {
            obj[it.first.as<std::string>()] = yaml_to_json(it.second);
        }
        return obj;
    }
    return nullptr;
}

// Recursive YAML map merge. Mirrors merge_yaml_nodes() in Config.cpp:
// when both nodes are maps, keys from `overlay` win over `base` and
// nested maps merge recursively. Used by resolve_includes_in_place().
YAML::Node merge_yaml_overlay(const YAML::Node& base, const YAML::Node& overlay) {
    if (!base)    return YAML::Clone(overlay);
    if (!overlay) return YAML::Clone(base);
    if (!base.IsMap() || !overlay.IsMap()) {
        return YAML::Clone(overlay);
    }
    YAML::Node out(YAML::NodeType::Map);
    for (auto it = base.begin(); it != base.end(); ++it) {
        out[it->first.as<std::string>()] = YAML::Clone(it->second);
    }
    for (auto it = overlay.begin(); it != overlay.end(); ++it) {
        const auto key = it->first.as<std::string>();
        out[key] = merge_yaml_overlay(out[key], it->second);
    }
    return out;
}

// Expand a YAML config's `includes:` block in place, loading each
// referenced file relative to @p config_path's directory and merging
// the loaded content into root[section]. Existing root[section]
// entries (e.g. from gRPC override JSON applied earlier) win on
// conflicts -- same precedence as Config::from_file's own resolver.
//
// After resolution `includes:` is removed from the root so the worker
// does not re-resolve includes that would re-clobber the explicit
// sections written here.
//
// Without this, the daemon's override-merge path wrote `merged` with
// only the literal `includes:` map (no explicit `egress`, etc.),
// leaving the gRPC client unable to control egress without sending its
// own `egress:` block.
bool resolve_includes_in_place(YAML::Node& root, const std::string& config_path) {
    if (!root || !root.IsMap()) return true;
    auto includes = root["includes"];
    if (!includes) return true;
    if (!includes.IsMap()) return false;

    namespace fs = std::filesystem;
    const fs::path base_dir = fs::path(config_path).parent_path();

    for (auto it = includes.begin(); it != includes.end(); ++it) {
        // One bad include shouldn't tank the whole resolution. Each
        // iteration is wrapped so we skip the offender and continue.
        try {
            const auto section = it->first.as<std::string>();
            const auto& spec   = it->second;

            std::string path_str;
            std::string explicit_section = section;
            bool        section_explicit = false;

            if (spec.IsScalar()) {
                path_str = spec.as<std::string>();
            } else if (spec.IsMap()) {
                if (!spec["path"]) continue;
                path_str = spec["path"].as<std::string>();
                if (auto s = spec["section"]) {
                    explicit_section = s.as<std::string>();
                    section_explicit = true;
                }
            } else {
                continue;
            }

            fs::path inc_path = path_str;
            if (inc_path.is_relative()) inc_path = base_dir / inc_path;

            YAML::Node loaded = YAML::LoadFile(inc_path.string());

            YAML::Node section_node;
            if (loaded[explicit_section]) section_node = loaded[explicit_section];
            else if (!section_explicit)   section_node = loaded;
            else                          continue;

            root[section] = root[section]
                ? merge_yaml_overlay(section_node, root[section])
                : YAML::Clone(section_node);
        } catch (...) {
            // Skip this include; the merge below will not re-resolve it,
            // so the worker's own resolver gets a chance later if the
            // includes block survives (we still remove it below, so the
            // bad section may just stay empty -- acceptable for now).
            continue;
        }
    }

    try {
        root.remove("includes");
    } catch (...) {
        // Not fatal -- worker's own resolver tolerates an absent or
        // unusual includes block.
    }
    return true;
}
} // namespace

::grpc::Status PennyServiceImpl::ApplyConfig(::grpc::ServerContext*,
                                             const openpenny::api::ApplyConfigRequest* request,
                                             openpenny::api::ConfigResponse* response) {
    if (!request || !response) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "missing request or response");
    }

    std::lock_guard<std::mutex> lock(config_mutex_);
    std::string error;
    auto next = desired_config_;

    if (request->config().has_traffic_policy()) {
        auto traffic = traffic_policy_from_proto(request->config().traffic_policy(),
                                                 desired_config_.traffic,
                                                 error);
        if (!traffic) {
            return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, error);
        }
        next.traffic = *traffic;
    }
    if (request->config().has_runtime_policy()) {
        auto runtime = runtime_policy_from_proto(request->config().runtime_policy(),
                                                desired_config_.runtime,
                                                error);
        if (!runtime) {
            return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, error);
        }
        next.runtime = *runtime;
    }

    desired_config_ = std::move(next);
    effective_config_ = control::compile_effective_config(desired_config_);
    control::apply_desired_config_to_legacy(defaults_, desired_config_);
    defaults_.effective_config = effective_config_;
    desired_config_override_active_ = true;
    fill_config_response(response, desired_config_, effective_config_, "ok", false);
    return ::grpc::Status::OK;
}

::grpc::Status PennyServiceImpl::SetTrafficPolicy(
    ::grpc::ServerContext*,
    const openpenny::api::SetTrafficPolicyRequest* request,
    openpenny::api::ConfigResponse* response) {
    if (!request || !response || !request->has_traffic_policy()) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "missing traffic policy");
    }

    std::lock_guard<std::mutex> lock(config_mutex_);
    std::string error;
    auto traffic = traffic_policy_from_proto(request->traffic_policy(),
                                             desired_config_.traffic,
                                             error);
    if (!traffic) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, error);
    }
    desired_config_.traffic = *traffic;
    effective_config_ = control::compile_effective_config(desired_config_);
    control::apply_desired_config_to_legacy(defaults_, desired_config_);
    defaults_.effective_config = effective_config_;
    desired_config_override_active_ = true;
    fill_config_response(response, desired_config_, effective_config_, "ok", false);
    return ::grpc::Status::OK;
}

::grpc::Status PennyServiceImpl::SetRuntimePolicy(
    ::grpc::ServerContext*,
    const openpenny::api::SetRuntimePolicyRequest* request,
    openpenny::api::ConfigResponse* response) {
    if (!request || !response || !request->has_runtime_policy()) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "missing runtime policy");
    }

    std::lock_guard<std::mutex> lock(config_mutex_);
    std::string error;
    auto runtime = runtime_policy_from_proto(request->runtime_policy(),
                                            desired_config_.runtime,
                                            error);
    if (!runtime) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, error);
    }
    desired_config_.runtime = *runtime;
    effective_config_ = control::compile_effective_config(desired_config_);
    control::apply_desired_config_to_legacy(defaults_, desired_config_);
    defaults_.effective_config = effective_config_;
    desired_config_override_active_ = true;
    fill_config_response(response, desired_config_, effective_config_, "ok", false);
    return ::grpc::Status::OK;
}

::grpc::Status PennyServiceImpl::SetMode(::grpc::ServerContext*,
                                         const openpenny::api::SetModeRequest* request,
                                         openpenny::api::ConfigResponse* response) {
    if (!request || !response) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "missing request or response");
    }
    auto mode = runtime_mode_from_proto(request->mode());
    if (!mode) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "mode must be active or passive");
    }

    std::lock_guard<std::mutex> lock(config_mutex_);
    desired_config_.runtime.mode = *mode;
    effective_config_ = control::compile_effective_config(desired_config_);
    control::apply_desired_config_to_legacy(defaults_, desired_config_);
    defaults_.effective_config = effective_config_;
    desired_config_override_active_ = true;
    fill_config_response(response, desired_config_, effective_config_, "ok", false);
    return ::grpc::Status::OK;
}

::grpc::Status PennyServiceImpl::GetDesiredConfig(
    ::grpc::ServerContext*,
    const openpenny::api::GetConfigRequest* request,
    openpenny::api::ConfigResponse* response) {
    if (!response) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "missing response");
    }
    const bool include_platform = request && request->include_platform_details();
    std::lock_guard<std::mutex> lock(config_mutex_);
    fill_config_response(response, desired_config_, effective_config_, "ok", include_platform);
    return ::grpc::Status::OK;
}

::grpc::Status PennyServiceImpl::GetEffectiveConfig(
    ::grpc::ServerContext*,
    const openpenny::api::GetConfigRequest* request,
    openpenny::api::ConfigResponse* response) {
    if (!response) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "missing response");
    }
    const bool include_platform = request && request->include_platform_details();
    std::lock_guard<std::mutex> lock(config_mutex_);
    fill_config_response(response, desired_config_, effective_config_, "ok", include_platform);
    return ::grpc::Status::OK;
}

::grpc::Status PennyServiceImpl::ReloadConfig(
    ::grpc::ServerContext*,
    const openpenny::api::ReloadConfigRequest*,
    openpenny::api::ConfigResponse* response) {
    if (!response) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "missing response");
    }

    auto loaded = config_path_.empty() ? std::optional<Config>(defaults_)
                                      : Config::from_file(config_path_);
    if (!loaded) {
        return ::grpc::Status(::grpc::StatusCode::NOT_FOUND, "failed to reload config");
    }

    std::lock_guard<std::mutex> lock(config_mutex_);
    defaults_ = *loaded;
    desired_config_ = defaults_.desired_config;
    effective_config_ = control::compile_effective_config(desired_config_);
    defaults_.effective_config = effective_config_;
    desired_config_override_active_ = false;
    fill_config_response(response, desired_config_, effective_config_, "ok", false);
    return ::grpc::Status::OK;
}

::grpc::Status PennyServiceImpl::Stop(::grpc::ServerContext*,
                                      const openpenny::api::StopRequest*,
                                      openpenny::api::ConfigResponse* response) {
    if (!response) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "missing response");
    }
    std::lock_guard<std::mutex> lock(config_mutex_);
    fill_config_response(response, desired_config_, effective_config_, "not_running", false);
    return ::grpc::Status::OK;
}

::grpc::Status PennyServiceImpl::GetRuntimeStatus(
    ::grpc::ServerContext*,
    const openpenny::api::RuntimeStatusRequest* request,
    openpenny::api::RuntimeStatusResponse* response) {
    if (!response) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "missing response");
    }
    const bool include_effective = !request || request->include_effective_config();
    std::lock_guard<std::mutex> lock(config_mutex_);
    response->set_status("ready");
    response->set_mode(to_proto(desired_config_.runtime.mode));
    response->clear_warnings();
    for (const auto& warning : effective_config_.warnings) {
        response->add_warnings(warning);
    }
    if (include_effective) {
        response->set_effective_config_json(
            control::effective_config_to_json(effective_config_, false).dump());
    }
    return ::grpc::Status::OK;
}

/**
 * @brief Handle a StartTest RPC call.
 *        Spawns a worker subprocess and parses its output into the gRPC response.
 */
::grpc::Status PennyServiceImpl::StartTest(::grpc::ServerContext*,
                                           const openpenny::api::StartTestRequest* request,
                                           openpenny::api::StartTestResponse* response) {
    if (!request) {
        return ::grpc::Status(::grpc::StatusCode::INVALID_ARGUMENT, "missing request");
    }

    TCPLOG_INFO("[grpc_start] mode=%s prefix=%s/%u test_id=%s override_bytes=%zu",
                (request->has_mode() ? request->mode().c_str() : "active"),
                request->prefix().c_str(),
                static_cast<unsigned>(request->mask_bits()),
                request->test_id().c_str(),
                request->has_config_override_json() ? request->config_override_json().size() : 0);

    // Prepare worker-launch configuration.
    openpenny::app::WorkerLaunchConfig worker_cfg{};
    // Prefer local build path for the worker binary if present.
    const std::filesystem::path local_worker = std::filesystem::current_path() / "build" / "penny_worker";
    if (std::filesystem::exists(local_worker)) {
        worker_cfg.worker_bin = local_worker.string();
    }
    worker_cfg.config_path = config_path_.empty() ? "openpenny.yaml" : config_path_;
    worker_cfg.test_id = request->test_id().empty() ? "default" : request->test_id();

    // Translate the legacy-shaped proto fields into the declarative
    // EgressConfig consumed downstream. We keep the proto as-is because
    // external clients still send these flags; this block is the only
    // place they're reshaped.
    //
    //   forward_raw_socket=true            -> RawSocket egress on forward_device
    //   forward_to_tun=true (default)      -> TUN egress on tun_name / forward_device
    //   forward_to_tun=false, !raw_socket  -> None (drop matched packets)
    const bool req_raw_socket = request->has_forward_raw_socket() && request->forward_raw_socket();
    const bool req_tun_enabled = !request->has_forward_to_tun() || request->forward_to_tun();

    if (req_raw_socket) {
        worker_cfg.egress.kind = openpenny::egress::EgressKind::RawSocket;
        worker_cfg.egress.device =
            (request->has_forward_device() && !request->forward_device().empty())
                ? request->forward_device()
                : (request->has_tun_name() ? request->tun_name() : std::string{});
    } else if (req_tun_enabled) {
        worker_cfg.egress.kind = openpenny::egress::EgressKind::Tun;
        worker_cfg.egress.device =
            (request->has_tun_name() && !request->tun_name().empty())
                ? request->tun_name()
                : (request->has_forward_device() ? request->forward_device() : std::string{"xdp-tu"});
    } else {
        worker_cfg.egress.kind = openpenny::egress::EgressKind::None;
        worker_cfg.egress.device.clear();
    }

    worker_cfg.egress.tun_multi_queue = !request->has_tun_multi_queue() || request->tun_multi_queue();
    if (request->has_tun_mtu() && request->tun_mtu() > 0) {
        worker_cfg.egress.tun_mtu = request->tun_mtu();
    }

    if (!request->prefix().empty() && request->mask_bits() > 0 && request->mask_bits() <= 32) {
        worker_cfg.prefix_ip = request->prefix();
        worker_cfg.mask_bits = static_cast<int>(request->mask_bits());
    }

    // Build pipeline options.
    PipelineOptions opts = make_options(*request);
    if (!request->has_mode()) {
        std::lock_guard<std::mutex> lock(config_mutex_);
        opts.mode = desired_config_.runtime.mode == control::RuntimeMode::Passive
            ? PipelineOptions::Mode::Passive
            : PipelineOptions::Mode::Active;
    }
    // Apply daemon policy state and optional inline JSON to the worker config.
    std::string temp_config_path;
    const bool has_inline_config_override =
        request->has_config_override_json() && !request->config_override_json().empty();
    bool use_daemon_desired_config = false;
    nlohmann::json daemon_desired_json;
    {
        std::lock_guard<std::mutex> lock(config_mutex_);
        use_daemon_desired_config = desired_config_override_active_;
        if (use_daemon_desired_config) {
            daemon_desired_json = control::desired_config_to_json(desired_config_, true);
        }
    }
    if (use_daemon_desired_config || has_inline_config_override) {
        std::filesystem::path base_dir = std::filesystem::path(worker_cfg.config_path).parent_path();
        if (base_dir.empty()) base_dir = std::filesystem::current_path();
        YAML::Node base_cfg;
        try {
            base_cfg = YAML::LoadFile(worker_cfg.config_path);
        } catch (const std::exception& e) {
            TCPLOG_ERROR("Failed to load base config %s: %s", worker_cfg.config_path.c_str(), e.what());
        }
        // Expand `includes:` in place so the merged JSON carries explicit
        // top-level sections (egress, traffic_policy, runtime_policy,
        // platform, ...) and the worker reads them directly instead of
        // re-resolving includes against the temp file's directory.
        //
        // Defensive: any yaml-cpp exception here would otherwise bubble
        // out of StartTest and surface as a generic
        // "Unexpected error in RPC handling" to the gRPC client. Log
        // and fall back to the unresolved YAML; the worker will still
        // run its own resolver at load time, so the only regression is
        // that overrides may not interact correctly with includes
        // (which is exactly what we wanted to fix, but graceful
        // degradation beats a 500-style RPC failure).
        try {
            resolve_includes_in_place(base_cfg, worker_cfg.config_path);
        } catch (const std::exception& e) {
            TCPLOG_ERROR("resolve_includes_in_place failed for %s: %s",
                         worker_cfg.config_path.c_str(), e.what());
        } catch (...) {
            TCPLOG_ERROR("resolve_includes_in_place threw an unknown exception for %s",
                         worker_cfg.config_path.c_str());
        }
        nlohmann::json base_json = yaml_to_json(base_cfg);
        nlohmann::json merged = base_json;
        if (!merged.is_object()) {
            merged = nlohmann::json::object();
        }
        if (!merged.contains("log")) {
            std::lock_guard<std::mutex> lock(config_mutex_);
            merged["log"] = {
                {"mode", defaults_.log_mode},
                {"level", defaults_.log_level}
            };
        }
        if (use_daemon_desired_config) {
            if (daemon_desired_json.contains("traffic_policy")) {
                merged["traffic_policy"] = daemon_desired_json["traffic_policy"];
            }
            if (daemon_desired_json.contains("runtime_policy")) {
                merged["runtime_policy"] = daemon_desired_json["runtime_policy"];
            }
            if (daemon_desired_json.contains("platform")) {
                merged["platform"] = daemon_desired_json["platform"];
            }
        }
        const bool use_active = opts.mode == PipelineOptions::Mode::Active;
        if (has_inline_config_override) {
            try {
                nlohmann::json override_json = nlohmann::json::parse(request->config_override_json());
                if (override_json.contains("traffic_policy")) {
                    merged["traffic_policy"] = override_json["traffic_policy"];
                }
                if (override_json.contains("runtime_policy")) {
                    merged["runtime_policy"] = override_json["runtime_policy"];
                }
                if (override_json.contains("platform")) {
                    merged["platform"] = override_json["platform"];
                }
                // The retired `monitoring.{active,passive}` / `input_sources.*`
                // / `traffic_forwarding.*` override paths have been removed.
                // Clients send overrides using the modern shapes:
                //   runtime_policy:  thresholds / safety / aggregates / mode
                //   platform:        backend / interface / queue / xdp / dpdk
                //   egress:          kind / device / tun / raw_nic

                // Propagate request prefix/mask into a single-rule
                // traffic_policy if no traffic_policy override was given
                // (legacy clients still rely on prefix/mask_bits).
                if (!request->prefix().empty() &&
                    request->mask_bits() > 0 &&
                    request->mask_bits() <= 32 &&
                    !override_json.contains("traffic_policy")) {
                    nlohmann::json policy{
                        {"default", "exclude"},
                        {"rules", nlohmann::json::array({
                            {{"name", "start_test_request_prefix"},
                             {"decision", "include"},
                             {"dst_prefix", request->prefix() + "/" +
                                            std::to_string(request->mask_bits())}}
                        })}
                    };
                    merged["traffic_policy"] = std::move(policy);
                }

                // Egress overrides — modern shape only.
                if (override_json.contains("egress")) {
                    merged["egress"] = override_json["egress"];
                }
                // Shorthand request-level overrides → egress / platform.
                if (override_json.contains("tun_multi_queue")) {
                    merged["egress"]["tun"]["multi_queue"] = override_json["tun_multi_queue"];
                }
                if (override_json.contains("tun_mtu")) {
                    merged["egress"]["tun"]["mtu"] = override_json["tun_mtu"];
                }
                if (override_json.contains("forward_to_tun")) {
                    merged["egress"]["kind"] =
                        override_json["forward_to_tun"].get<bool>() ? "tun" : "none";
                }
                if (override_json.contains("ifname")) {
                    merged["platform"]["interface"] = override_json["ifname"];
                }
                if (override_json.contains("queue")) {
                    merged["platform"]["queue"] = override_json["queue"];
                }
                if (override_json.contains("queue_count")) {
                    merged["platform"]["queue_count"] = override_json["queue_count"];
                }

                // Resolve relative bpf_object path against base_dir if the
                // file is there; otherwise leave it for the worker CWD.
                try {
                    if (merged.contains("platform") &&
                        merged["platform"].contains("xdp") &&
                        merged["platform"]["xdp"].contains("bpf_object")) {
                        std::string bpf_obj =
                            merged["platform"]["xdp"]["bpf_object"].get<std::string>();
                        std::filesystem::path p(bpf_obj);
                        if (p.is_relative()) {
                            std::filesystem::path candidate = base_dir / p;
                            if (std::filesystem::exists(candidate)) {
                                merged["platform"]["xdp"]["bpf_object"] = candidate.string();
                            }
                        }
                    }
                } catch (...) {
                    // leave as-is on failure
                }
            } catch (const std::exception& e) {
                TCPLOG_ERROR("Failed to parse override JSON: %s", e.what());
            }
        }

        // Reflect any final egress selection from `merged` into the worker
        // launch config so the daemon's process-launch path agrees with
        // what the worker will read from the YAML.
        try {
            if (merged.contains("egress") && merged["egress"].contains("kind")) {
                const auto kind = merged["egress"]["kind"].get<std::string>();
                if (kind == "tun") {
                    if (worker_cfg.egress.kind != openpenny::egress::EgressKind::RawSocket) {
                        worker_cfg.egress.kind = openpenny::egress::EgressKind::Tun;
                    }
                    if (merged["egress"].contains("device") &&
                        merged["egress"]["device"].is_string()) {
                        worker_cfg.egress.device =
                            merged["egress"]["device"].get<std::string>();
                    }
                } else if (kind == "none") {
                    if (worker_cfg.egress.kind != openpenny::egress::EgressKind::RawSocket) {
                        worker_cfg.egress.kind = openpenny::egress::EgressKind::None;
                    }
                }
            }
            // Request-level forward_to_tun still wins if present.
            if (request->has_forward_to_tun()) {
                if (worker_cfg.egress.kind != openpenny::egress::EgressKind::RawSocket) {
                    worker_cfg.egress.kind = request->forward_to_tun()
                                                 ? openpenny::egress::EgressKind::Tun
                                                 : openpenny::egress::EgressKind::None;
                }
                merged["egress"]["kind"] = request->forward_to_tun() ? "tun" : "none";
            }
        } catch (...) {}

        std::string pattern = (base_dir / "penny_cfg_XXXXXX.yaml").string();
        std::vector<char> buf(pattern.begin(), pattern.end());
        buf.push_back('\0');
        int fd = mkstemps(buf.data(), 5); // ".yaml" suffix length is 5 including dot.
        if (fd >= 0) {
            temp_config_path = buf.data();
            std::ofstream ofs(temp_config_path);
            // Emit JSON as valid YAML (JSON is a YAML subset).
            ofs << merged.dump(2);
            ofs.close();
            close(fd);
            TCPLOG_INFO("[grpc_config] wrote merged override to %s", temp_config_path.c_str());
            worker_cfg.config_path = temp_config_path;
        } else {
            TCPLOG_ERROR("Failed to create temp config file for override");
        }
    }

    // Launch worker subprocess and capture its output.
    const auto spawned = openpenny::app::spawn_worker_process(worker_cfg, opts);
    const std::string& output = spawned.output;
    if (spawned.status != 0) {
        TCPLOG_ERROR("[grpc_start] worker exited with status=%d", spawned.status);
    }
    if (!temp_config_path.empty()) {
        std::error_code ec;
        std::filesystem::remove(temp_config_path, ec);
        if (ec) {
            TCPLOG_WARN("Failed to remove temp config %s: %s",
                        temp_config_path.c_str(),
                        ec.message().c_str());
        }
    }

    // Worker prints lines in "key=value" format. Parse each and fill response.
    std::string line;
    size_t start = 0;
    while (start < output.size()) {
        auto end = output.find('\n', start);
        if (end == std::string::npos) end = output.size();
        line = output.substr(start, end - start);
        start = end + 1;

        if (line.empty()) continue;

        std::string k, v;
        if (!parse_kv_line(line, k, v)) continue;

        // Map known keys to response fields.
        if (k == "status") response->set_status(v);
        else if (k == "test_id") response->set_test_id(v);
        else if (k == "packets_processed") response->set_packets_processed(std::stoull(v));
        else if (k == "packets_forwarded") response->set_packets_forwarded(std::stoull(v));
        else if (k == "forward_errors") response->set_forward_errors(std::stoull(v));
        else if (k == "pure_ack_packets") response->set_pure_ack_packets(std::stoull(v));
        else if (k == "data_packets") response->set_data_packets(std::stoull(v));
        else if (k == "duplicate_packets") response->set_duplicate_packets(std::stoull(v));
        else if (k == "in_order_packets") response->set_in_order_packets(std::stoull(v));
        else if (k == "out_of_order_packets") response->set_out_of_order_packets(std::stoull(v));
        else if (k == "retransmitted_packets") response->set_retransmitted_packets(std::stoull(v));
        else if (k == "non_retransmitted_packets") response->set_non_retransmitted_packets(std::stoull(v));
        else if (k == "pending_retransmissions") response->set_pending_retransmissions(std::stoull(v));
        else if (k == "flows_tracked_syn") response->set_flows_tracked_syn(std::stoull(v));
        else if (k == "flows_tracked_data") response->set_flows_tracked_data(std::stoull(v));
        else if (k == "penny_completed") response->set_penny_completed(v == "1");
        else if (k == "aggregates_penny_completed") response->set_aggregates_penny_completed(v == "1");
        else if (k == "aggregates_enabled") response->set_aggregates_enabled(v == "1");
        else if (k == "aggregates_status") response->set_aggregates_status(v);
        else if (k == "aggregates_decision_complete" || k == "aggregates_decision_completed") response->set_aggregates_decision_complete(v == "1");
        else if (k == "aggregates_has_eval") response->set_aggregates_has_eval(v == "1");
        else if (k == "aggregates_eval_data_packets") response->set_aggregates_eval_data_packets(std::stoull(v));
        else if (k == "aggregates_eval_duplicate_packets") response->set_aggregates_eval_duplicate_packets(std::stoull(v));
        else if (k == "aggregates_eval_retransmitted_packets") response->set_aggregates_eval_retransmitted_packets(std::stoull(v));
        else if (k == "aggregates_eval_non_retransmitted_packets") response->set_aggregates_eval_non_retransmitted_packets(std::stoull(v));
        else if (k == "aggregates_snapshots") response->set_aggregates_snapshots(std::stoull(v));
        else if (k == "aggregate_flows_monitored") response->set_aggregate_flows_monitored(std::stoull(v));
        else if (k == "aggregate_flows_finished") response->set_aggregate_flows_finished(std::stoull(v));
        else if (k == "aggregate_flows_closed_loop") response->set_aggregate_flows_closed_loop(std::stoull(v));
        else if (k == "aggregate_flows_not_closed_loop") response->set_aggregate_flows_not_closed_loop(std::stoull(v));
        else if (k == "aggregate_flows_rst") response->set_aggregate_flows_rst(std::stoull(v));
        else if (k == "aggregate_flows_duplicates_exceeded") response->set_aggregate_flows_duplicates_exceeded(std::stoull(v));
        else if (k == "json") response->set_json_summary(v);
    }

    // Default status if worker provided none.
    if (response->status().empty()) {
        response->set_status("error");
    }

    TCPLOG_INFO("[grpc_end] test_id=%s status=%s packets_processed=%llu forwarded=%llu",
                response->test_id().c_str(),
                response->status().c_str(),
                static_cast<unsigned long long>(response->packets_processed()),
                static_cast<unsigned long long>(response->packets_forwarded()));

    const bool aggregates_enabled = response->aggregates_enabled();
    std::string aggregates_status = response->aggregates_status();
    if (aggregates_status.empty()) {
        aggregates_status = aggregates_enabled ? "pending" : "n/a";
        response->set_aggregates_status(aggregates_status);
    }
    const bool aggregates_applicable = aggregates_enabled && aggregates_status != "n/a";
    const bool aggregates_has_eval = aggregates_applicable && response->aggregates_has_eval();
    const auto agg_eval_data = aggregates_has_eval ? response->aggregates_eval_data_packets() : 0;
    const auto agg_eval_dup = aggregates_has_eval ? response->aggregates_eval_duplicate_packets() : 0;
    const auto agg_eval_rtx = aggregates_has_eval ? response->aggregates_eval_retransmitted_packets() : 0;
    const auto agg_eval_nonrtx = aggregates_has_eval ? response->aggregates_eval_non_retransmitted_packets() : 0;
    const auto aggregates_snapshots = aggregates_applicable ? response->aggregates_snapshots() : 0;
    const auto agg_flows_monitored = aggregates_applicable ? response->aggregate_flows_monitored() : 0;
    const auto agg_flows_finished = aggregates_applicable ? response->aggregate_flows_finished() : 0;
    const auto agg_flows_closed = aggregates_applicable ? response->aggregate_flows_closed_loop() : 0;
    const auto agg_flows_not_closed = aggregates_applicable ? response->aggregate_flows_not_closed_loop() : 0;
    const auto agg_flows_rst = aggregates_applicable ? response->aggregate_flows_rst() : 0;
    const auto agg_flows_dup_exceeded = aggregates_applicable ? response->aggregate_flows_duplicates_exceeded() : 0;
    const bool aggregates_decision_complete =
        aggregates_applicable &&
        (response->aggregates_decision_complete() ||
         aggregates_status != "pending");
    response->set_aggregates_decision_complete(aggregates_decision_complete);
    response->set_aggregates_has_eval(aggregates_has_eval);
    if (!aggregates_applicable) {
        response->set_aggregates_snapshots(0);
        response->set_aggregate_flows_monitored(0);
        response->set_aggregate_flows_finished(0);
        response->set_aggregate_flows_closed_loop(0);
        response->set_aggregate_flows_not_closed_loop(0);
        response->set_aggregate_flows_rst(0);
        response->set_aggregate_flows_duplicates_exceeded(0);
    }
    if (!aggregates_has_eval) {
        response->set_aggregates_eval_data_packets(0);
        response->set_aggregates_eval_duplicate_packets(0);
        response->set_aggregates_eval_retransmitted_packets(0);
        response->set_aggregates_eval_non_retransmitted_packets(0);
    }
    const std::string aggregates_decision_state = aggregates_applicable
                                                      ? (aggregates_decision_complete ? "completed" : "running")
                                                      : "n/a";

    // Build a JSON summary akin to the CLI output, preserving any
    // worker-emitted detail sections that do not have dedicated proto fields.
    nlohmann::json summary = nlohmann::json::object();
    if (!response->json_summary().empty()) {
        auto parsed = nlohmann::json::parse(response->json_summary(), nullptr, false);
        if (parsed.is_object()) {
            summary = std::move(parsed);
        }
    }
    summary["test_id"] = response->test_id();
    summary["status"] = response->status();
    summary["packets"] = {
        {"processed", response->packets_processed()},
        {"forwarded", response->packets_forwarded()},
        {"errors", response->forward_errors()},
        {"pure_ack", response->pure_ack_packets()},
        {"data", response->data_packets()},
        {"duplicate", response->duplicate_packets()},
        {"in_order", response->in_order_packets()},
        {"out_of_order", response->out_of_order_packets()},
        {"retransmitted", response->retransmitted_packets()},
        {"non_retransmitted", response->non_retransmitted_packets()}
    };
    summary["flows"] = {
        {"tracked_syn", response->flows_tracked_syn()},
        {"tracked_data", response->flows_tracked_data()}
    };
    summary["penny_completed"] = response->penny_completed();
    summary["aggregates_completed"] = response->aggregates_penny_completed();
    summary["aggregates_enabled"] = response->aggregates_enabled();
    summary["aggregates_status"] = aggregates_status;
    summary["aggregates_decision_complete"] = aggregates_decision_complete;
    summary["aggregates_decision_state"] = aggregates_decision_state;
    summary["aggregates_has_eval"] = aggregates_has_eval;
    summary["aggregates_snapshots"] = aggregates_snapshots;
    summary["aggregates_eval"] = {
        {"data", agg_eval_data},
        {"duplicate", agg_eval_dup},
        {"retransmitted", agg_eval_rtx},
        {"non_retransmitted", agg_eval_nonrtx}
    };
    summary["aggregate_flows"] = {
        {"monitored", agg_flows_monitored},
        {"finished", agg_flows_finished},
        {"closed_loop", agg_flows_closed},
        {"not_closed_loop", agg_flows_not_closed},
        {"rst", agg_flows_rst},
        {"duplicates_exceeded", agg_flows_dup_exceeded}
    };
    response->set_json_summary(summary.dump());

    return ::grpc::Status::OK;
}

} // namespace openpenny::grpc_service
