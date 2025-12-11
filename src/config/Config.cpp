// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/config/Config.h"

#include <arpa/inet.h>
#include <yaml-cpp/yaml.h>
#include <initializer_list>
#include <nlohmann/json.hpp>
#include <nlohmann/json-schema.hpp>
#include <fstream>
#include <filesystem>
#include <iostream>

namespace openpenny {
namespace {

// Helpers below massage YAML scalars into host-order integers so the rest of the
// code can operate without touching YAML APIs.

/**
 * @brief Parse a dotted-decimal IPv4 string into host-order integer form.
 */
std::optional<uint32_t> parse_ipv4_host(const std::string& text) {
    if (text.empty()) return std::nullopt;
    in_addr addr{};
    if (inet_pton(AF_INET, text.c_str(), &addr) != 1) return std::nullopt;
    return ntohl(addr.s_addr);
}

/**
 * @brief Produce a standard CIDR mask given the number of prefix bits.
 */
uint32_t mask_from_bits(int bits) {
    if (bits <= 0) return 0;
    if (bits >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - bits);
}

template <typename T>
void set_if_present(const YAML::Node& node, const char* key, T& target) {
    if (!node) return;
    if (auto child = node[key]) {
        target = child.as<T>();
    }
}

/**
 * @brief Iterate across alternative keys and copy the first match into @p target.
 */
template <typename T>
void set_if_present_any(const YAML::Node& node,
                        T& target,
                        std::initializer_list<const char*> keys) {
    if (!node) return;
    for (auto key : keys) {
        if (auto child = node[key]) {
            target = child.as<T>();
            return;
        }
    }
}

// Convert YAML scalars to JSON types with best-effort typing.
static nlohmann::json yaml_scalar_to_json(const YAML::Node& node) {
    try { return node.as<bool>(); } catch (...) {}
    try { return node.as<long long>(); } catch (...) {}
    try { return node.as<double>(); } catch (...) {}
    try { return node.as<std::string>(); } catch (...) {}
    return nullptr;
}

static nlohmann::json yaml_to_json(const YAML::Node& node) {
    switch (node.Type()) {
    case YAML::NodeType::Scalar:
        return yaml_scalar_to_json(node);
    case YAML::NodeType::Sequence: {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& elem : node) arr.push_back(yaml_to_json(elem));
        return arr;
    }
    case YAML::NodeType::Map: {
        nlohmann::json obj = nlohmann::json::object();
        for (auto it = node.begin(); it != node.end(); ++it) {
            obj[it->first.as<std::string>()] = yaml_to_json(it->second);
        }
        return obj;
    }
    default:
        return nullptr;
    }
}

static std::optional<nlohmann::json> load_schema(const std::string& config_path) {
    namespace fs = std::filesystem;
    fs::path schema_path = fs::path(config_path).parent_path() / "config_schema.json";
    std::ifstream in(schema_path);
    if (!in) return std::nullopt;
    try {
        nlohmann::json schema;
        in >> schema;
        return schema;
    } catch (...) {
        return std::nullopt;
    }
}

static bool validate_root(const YAML::Node& root, const nlohmann::json& schema, std::string& error) {
    try {
        nlohmann::json_schema::json_validator validator(
            nullptr,
            nlohmann::json_schema::default_string_format_check);
        validator.set_root_schema(schema);
        validator.validate(yaml_to_json(root));
        return true;
    } catch (const std::exception& ex) {
        error = ex.what();
        return false;
    } catch (...) {
        error = "unknown validation error";
        return false;
    }
}

} // namespace

static void apply_xdp_config(const YAML::Node& xdp, Config& cfg) {
    if (!xdp) return;
    // Allow overriding interface/queue from within the xdp block.
    set_if_present(xdp, "ifname", cfg.ifname);
    set_if_present(xdp, "queue", cfg.queue);
    set_if_present(xdp, "interface", cfg.ifname);   // alternate naming
    set_if_present(xdp, "rx_queue", cfg.queue);      // alternate naming
    set_if_present(xdp, "drv_mode", cfg.xdp_drv_mode);
    set_if_present(xdp, "zerocopy", cfg.zerocopy);
    set_if_present(xdp, "frame_size", cfg.frame_size);
    set_if_present(xdp, "num_frames", cfg.num_frames);
    set_if_present(xdp, "rx_ring", cfg.rx_ring);

    if (auto runtime = xdp["runtime"]) {
        auto& rt = cfg.xdp_runtime;
        set_if_present(runtime, "enable", rt.enable);
        set_if_present_any(runtime, rt.attach_program, {"attach_program", "attach"});
        set_if_present(runtime, "detach_on_close", rt.detach_on_close);
        set_if_present(runtime, "reuse_pins", rt.reuse_pins);
        set_if_present(runtime, "pin_maps", rt.pin_maps);
        set_if_present(runtime, "update_conf_map", rt.update_conf_map);
        set_if_present(runtime, "verbose", rt.verbose);
        set_if_present(runtime, "drop_unmatched", rt.drop_unmatched);
        set_if_present(runtime, "allow_ssh_bypass", rt.allow_ssh_bypass);
        set_if_present(runtime, "allow_skb_fallback", rt.allow_skb_fallback);
        set_if_present(runtime, "force_copy_mode", rt.force_copy_mode);
        set_if_present(runtime, "require_zerocopy", rt.require_zerocopy);
        set_if_present(runtime, "allow_copy_fallback", rt.allow_copy_fallback);
        set_if_present(runtime, "batch", rt.batch);
        set_if_present(runtime, "poll_timeout_ms", rt.poll_timeout_ms);
        set_if_present(runtime, "ifname", cfg.ifname);
        set_if_present(runtime, "queue", cfg.queue);
        set_if_present(runtime, "interface", cfg.ifname);
        set_if_present(runtime, "rx_queue", cfg.queue);
        set_if_present(runtime, "bpf_object", rt.bpf_object);
        set_if_present_any(runtime, rt.bpf_program, {"program", "bpf_program"});
        set_if_present(runtime, "map_conf_name", rt.map_conf_name);
        set_if_present(runtime, "map_xsks_name", rt.map_xsks_name);
        set_if_present(runtime, "map_stats_name", rt.map_stats_name);
        set_if_present(runtime, "pin_conf_path", rt.pin_conf_path);
        set_if_present(runtime, "pin_xsks_path", rt.pin_xsks_path);
        set_if_present(runtime, "pin_stats_path", rt.pin_stats_path);
        set_if_present(runtime, "prefix", rt.prefix_text);
        set_if_present(runtime, "mask", rt.mask_text);
        set_if_present(runtime, "mask_bits", rt.mask_bits);

        if (auto parsed = parse_ipv4_host(rt.prefix_text)) {
            rt.prefix_host = *parsed;
        }
        if (auto parsed = parse_ipv4_host(rt.mask_text)) {
            rt.mask_host = *parsed;
        }
        if (rt.mask_host == 0 && rt.mask_bits > 0) {
            rt.mask_host = mask_from_bits(rt.mask_bits);
        }
    }
}

static void apply_dpdk_config(const YAML::Node& dpdk, Config& cfg) {
    if (!dpdk) return;
    set_if_present(dpdk, "enable", cfg.dpdk.enable);
    set_if_present(dpdk, "burst", cfg.dpdk.burst);
    set_if_present(dpdk, "ifname", cfg.ifname);
    set_if_present(dpdk, "interface", cfg.ifname);
    set_if_present(dpdk, "device", cfg.ifname);
    set_if_present(dpdk, "queue", cfg.queue);
}

static void apply_active_config(const YAML::Node& active, Config::ActiveConfig& cfg) {
    if (!active) return;
    set_if_present(active, "enabled", cfg.enabled);

    // New nested layout (preferred).
    if (auto aggregates = active["aggregates"]) {
        set_if_present(aggregates, "enabled", cfg.aggregates_enabled);
        set_if_present(aggregates, "max_monitored_flows", cfg.max_tracked_flows);
    }
    if (auto drop_policy = active["drop_policy"]) {
        set_if_present(drop_policy, "packet_drop_probability", cfg.drop_probability);
        set_if_present(drop_policy, "max_duplicate_ratio", cfg.max_duplicate_fraction);
        set_if_present(drop_policy, "max_reordering_ratio", cfg.max_out_of_order_fraction);
        set_if_present(drop_policy,
                       "retransmission_observation_miss_rate",
                       cfg.retransmission_miss_probability);
    }
    if (auto timeouts = active["timeouts"]) {
        set_if_present(timeouts,
                       "retransmission_timeout_multiplier",
                       cfg.rtt_timeout_factor);
        set_if_present(timeouts,
                       "retransmission_timeout_seconds",
                       cfg.rtt_timeout_factor);
        set_if_present(timeouts,
                       "retransmission_timeout_threshold",
                       cfg.rtt_timeout_factor);
        set_if_present(timeouts,
                       "admission_grace_period_seconds",
                       cfg.flow_grace_period_seconds);
        set_if_present(timeouts,
                       "idle_flow_timeout_seconds",
                       cfg.flow_idle_timeout_seconds);
        set_if_present(timeouts,
                       "monitored_flow_idle_expiry_seconds",
                       cfg.flow_idle_timeout_seconds);
        set_if_present(timeouts, "drop_state_seconds", cfg.drop_state_seconds);
        set_if_present(timeouts, "drop_expiration", cfg.drop_state_seconds); // legacy
    }
    if (auto execution = active["execution"]) {
        set_if_present(execution, "min_drops_per_flow", cfg.min_drops_per_flow);
        set_if_present(execution, "max_drops_per_indiv_flow", cfg.max_drops_per_indiv_flow);
        set_if_present(execution, "max_drops_aggregates", cfg.max_drops_aggregates);
        set_if_present(execution, "max_packet_drops_per_flow", cfg.max_drops_per_indiv_flow);
        set_if_present(execution,
                       "max_packet_drops_global_aggregate",
                       cfg.max_drops_aggregates);
        set_if_present(execution,
                       "max_number_of_individual_flows",
                       cfg.max_tracked_flows);
        set_if_present(execution,
                       "stop_after_individual_flows",
                       cfg.stop_after_individual_flows);
        // Backward compatibility with legacy names.
        set_if_present(execution, "min_packet_drops", cfg.min_drops_per_flow);
        set_if_present(execution, "max_packet_drops", cfg.max_drops_per_indiv_flow);
        set_if_present(execution, "max_drops_per_flow", cfg.max_drops_per_indiv_flow);
    }

    // Backward-compatible flat keys.
    set_if_present(active, "drop_probability", cfg.drop_probability);
    set_if_present(active, "max_duplicate_fraction", cfg.max_duplicate_fraction);
    set_if_present(active, "max_duplicates", cfg.max_duplicate_fraction); // legacy
    set_if_present(active,
                   "retransmission_miss_probability",
                   cfg.retransmission_miss_probability);
    set_if_present(active,
                   "probability_not_observe_retransmission",
                   cfg.retransmission_miss_probability); // legacy
    set_if_present(active, "rtt_timeout_factor", cfg.rtt_timeout_factor);
    set_if_present(active, "rtt_timeout_seconds", cfg.rtt_timeout_factor);
    set_if_present(active, "retransmission_timeout_seconds", cfg.rtt_timeout_factor);
    set_if_present(active, "retransmission_timeout_threshold", cfg.rtt_timeout_factor);
    set_if_present(active, "tmax_rt_x", cfg.rtt_timeout_factor); // legacy
    set_if_present(active,
                   "flow_grace_period_seconds",
                   cfg.flow_grace_period_seconds);
    set_if_present(active,
                   "time_to_wait_to_monitor_flow",
                   cfg.flow_grace_period_seconds); // legacy
    set_if_present(active,
                   "idle_flow_timeout_seconds",
                   cfg.flow_idle_timeout_seconds);
    set_if_present(active, "max_tracked_flows", cfg.max_tracked_flows);
    set_if_present(active,
                   "max_number_of_monitored_flows",
                   cfg.max_tracked_flows); // legacy
    set_if_present(active,
                   "max_number_of_individual_flows",
                   cfg.max_tracked_flows);
    set_if_present(active,
                   "stop_after_individual_flows",
                   cfg.stop_after_individual_flows);
    set_if_present(active,
                   "max_out_of_order_fraction",
                   cfg.max_out_of_order_fraction);
    set_if_present(active,
                   "max_out_of_order_ratio",
                   cfg.max_out_of_order_fraction); // legacy
}

static void apply_passive_config(const YAML::Node& passive, Config::PassiveConfig& cfg) {
    if (!passive) return;
    set_if_present(passive, "enabled", cfg.enabled);
    set_if_present(passive, "min_number_of_flows_to_finish", cfg.min_number_of_flows_to_finish);
    set_if_present(passive, "max_parallel_flows", cfg.max_parallel_flows);
    set_if_present(passive, "max_execution_time", cfg.max_execution_time_seconds);

    if (auto timeouts = passive["timeouts"]) {
        set_if_present(timeouts,
                       "admission_grace_period_seconds",
                       cfg.flow_grace_period_seconds);
        set_if_present(timeouts,
                       "monitored_flow_idle_expiry_seconds",
                       cfg.flow_idle_timeout_seconds);
    }

    // Allow flat passive keys.
    set_if_present(passive,
                   "admission_grace_period_seconds",
                   cfg.flow_grace_period_seconds);
    set_if_present(passive,
                   "monitored_flow_idle_expiry_seconds",
                   cfg.flow_idle_timeout_seconds);
}

/**
 * @brief Populate a Config structure from a YAML document on disk.
 */
std::optional<Config> Config::from_file(const std::string& path) {
    YAML::Node root;
    try {
        root = YAML::LoadFile(path);
    } catch (const YAML::BadFile&) {
        return std::nullopt;
    } catch (const YAML::ParserException&) {
        return std::nullopt;
    }

    Config cfg;

    auto schema = load_schema(path);
    if (!schema) {
        std::cerr << "Failed to load config schema near " << path << '\n';
        return std::nullopt;
    }

    std::string validation_error;
    if (!validate_root(root, *schema, validation_error)) {
        std::cerr << "Config validation failed: " << validation_error << '\n';
        return std::nullopt;
    }

    try {
        if (auto log = root["log"]) {
            set_if_present(log, "mode", cfg.log_mode);
            set_if_present(log, "level", cfg.log_level);
        }

        // Prefer grouped input source config under input_sources; fall back to legacy top-level keys.
        if (auto inputs = root["input_sources"]) {
            if (auto xdp_inline = inputs["xdp"]) {
                apply_xdp_config(xdp_inline, cfg);
            }
            if (auto dpdk_inline = inputs["dpdk"]) {
                apply_dpdk_config(dpdk_inline, cfg);
            }
        } else {
            if (auto xdp_inline = root["xdp"]) {
                apply_xdp_config(xdp_inline, cfg);
            }
            if (auto dpdk_inline = root["dpdk"]) {
                apply_dpdk_config(dpdk_inline, cfg);
            }
        }

        // Active-mode config: prefer monitoring.active, then active, then penny (legacy).
        if (auto monitoring = root["monitoring"]) {
            if (auto active = monitoring["active"]) {
                apply_active_config(active, cfg.active);
            } else if (auto penny_inline = monitoring["penny"]) {
                apply_active_config(penny_inline, cfg.active);
            }
            if (auto passive = monitoring["passive"]) {
                apply_passive_config(passive, cfg.passive);
            }
        } else if (auto active = root["active"]) {
            apply_active_config(active, cfg.active);
        } else if (auto penny_inline = root["penny"]) {
            apply_active_config(penny_inline, cfg.active);
        }
    } catch (const YAML::Exception&) {
        return std::nullopt;
    }

    if (cfg.active.retransmission_miss_probability <= 0.0) {
        return std::nullopt;
    }

    return cfg;
}

} // namespace openpenny
