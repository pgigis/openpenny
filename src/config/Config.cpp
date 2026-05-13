// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/config/Config.h"
#include "openpenny/control/Planner.h"

#include <arpa/inet.h>
#include <yaml-cpp/yaml.h>
#include <initializer_list>
#include <nlohmann/json.hpp>
#include <nlohmann/json-schema.hpp>
#include <fstream>
#include <filesystem>
#include <iostream>
#include <string>
#include <utility>

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

std::optional<net::TrafficIpPrefix> parse_ipv4_prefix_host(const std::string& text) {
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

    auto prefix = parse_ipv4_host(ip_text);
    if (!prefix) return std::nullopt;

    return net::TrafficIpPrefix{*prefix, mask_from_bits(bits)};
}

std::string lower_copy(std::string value) {
    for (auto& ch : value) {
        if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
    }
    return value;
}

// One canonical spelling per enum value. Aliases have been retired to
// keep the YAML one obvious thing to learn and let the schema enforce
// the set. The previous aliases (e.g. "xdp", "mirror", "steal",
// "select", "redirect_to_userspace") will now fail validation; map
// them to the canonical spelling shown below.

std::optional<PacketInputBackend> parse_backend(const std::string& value) {
    const auto normalized = lower_copy(value);
    if (normalized == "af_xdp")           return PacketInputBackend::XdpAfXdp;
    if (normalized == "dpdk")             return PacketInputBackend::Dpdk;
    if (normalized == "af_packet_mirror") return PacketInputBackend::AfPacketMirror;
    return std::nullopt;
}

std::optional<IngressMode> parse_ingress_mode(const std::string& value) {
    const auto normalized = lower_copy(value);
    if (normalized == "auto" || normalized.empty()) return IngressMode::Auto;
    if (normalized == "copy")     return IngressMode::Copy;
    if (normalized == "redirect") return IngressMode::Redirect;
    return std::nullopt;
}

std::optional<control::PlatformBackend> parse_platform_backend(const std::string& value) {
    const auto normalized = lower_copy(value);
    if (normalized == "af_xdp") return control::PlatformBackend::AfXdp;
    if (normalized == "dpdk")   return control::PlatformBackend::Dpdk;
    return std::nullopt;
}

std::optional<control::TrafficDecision> parse_traffic_decision(const std::string& value) {
    const auto normalized = lower_copy(value);
    if (normalized == "include") return control::TrafficDecision::Include;
    if (normalized == "exclude") return control::TrafficDecision::Exclude;
    return std::nullopt;
}

std::optional<control::RuntimeMode> parse_runtime_mode(const std::string& value) {
    const auto normalized = lower_copy(value);
    if (normalized == "active")  return control::RuntimeMode::Active;
    if (normalized == "passive") return control::RuntimeMode::Passive;
    return std::nullopt;
}

std::optional<std::uint8_t> parse_ip_proto_scalar(const YAML::Node& node) {
    if (!node) return std::nullopt;
    try {
        auto value = node.as<int>();
        if (value >= 0 && value <= 255) return static_cast<std::uint8_t>(value);
    } catch (...) {}
    try {
        const auto text = lower_copy(node.as<std::string>());
        if (text == "tcp") return 6;
        if (text == "udp") return 17;
        if (text == "icmp") return 1;
    } catch (...) {}
    return std::nullopt;
}

template <typename T>
void set_if_present(const YAML::Node& node, const char* key, T& target) {
    if (!node) return;
    if (auto child = node[key]) {
        target = child.as<T>();
    }
}

void set_uint_vector_if_present(const YAML::Node& node,
                                const char* key,
                                std::vector<unsigned>& target) {
    if (!node) return;
    if (auto child = node[key]) {
        if (!child.IsSequence()) return;
        std::vector<unsigned> values;
        values.reserve(child.size());
        for (const auto& item : child) {
            values.push_back(item.as<unsigned>());
        }
        target = std::move(values);
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

static YAML::Node merge_yaml_nodes(const YAML::Node& base, const YAML::Node& overlay) {
    if (!base) return YAML::Clone(overlay);
    if (!overlay) return YAML::Clone(base);
    if (!base.IsMap() || !overlay.IsMap()) {
        return YAML::Clone(overlay);
    }

    YAML::Node merged(YAML::NodeType::Map);
    for (auto it = base.begin(); it != base.end(); ++it) {
        merged[it->first.as<std::string>()] = YAML::Clone(it->second);
    }
    for (auto it = overlay.begin(); it != overlay.end(); ++it) {
        const auto key = it->first.as<std::string>();
        merged[key] = merge_yaml_nodes(merged[key], it->second);
    }
    return merged;
}

struct IncludeSpec {
    std::filesystem::path path{};
    std::string section{};
    bool section_explicit{false};
};

static std::optional<IncludeSpec> parse_include_spec(const std::string& section,
                                                     const YAML::Node& node,
                                                     std::string& error) {
    IncludeSpec spec{};
    spec.section = section;

    if (node.IsScalar()) {
        spec.path = node.as<std::string>();
        return spec;
    }
    if (node.IsMap()) {
        if (!node["path"]) {
            error = "include '" + section + "' must define path";
            return std::nullopt;
        }
        spec.path = node["path"].as<std::string>();
        if (auto section_node = node["section"]) {
            spec.section = section_node.as<std::string>();
            spec.section_explicit = true;
        }
        return spec;
    }

    error = "include '" + section + "' must be a path string or {path, section}";
    return std::nullopt;
}

static bool resolve_yaml_includes(YAML::Node& root,
                                  const std::string& config_path,
                                  std::string& error) {
    if (!root || !root.IsMap()) return true;

    const auto includes = root["includes"];
    if (!includes) return true;
    if (!includes.IsMap()) {
        error = "includes must be a map";
        return false;
    }

    namespace fs = std::filesystem;
    const fs::path base_dir = fs::path(config_path).parent_path();

    for (auto it = includes.begin(); it != includes.end(); ++it) {
        const auto section = it->first.as<std::string>();
        auto spec = parse_include_spec(section, it->second, error);
        if (!spec) return false;

        fs::path include_path = spec->path;
        if (include_path.is_relative()) {
            include_path = base_dir / include_path;
        }

        YAML::Node included;
        try {
            included = YAML::LoadFile(include_path.string());
        } catch (const YAML::Exception& ex) {
            error = "failed to load include '" + include_path.string() + "': " + ex.what();
            return false;
        }

        YAML::Node included_section;
        if (included[spec->section]) {
            included_section = included[spec->section];
        } else if (!spec->section_explicit) {
            included_section = included;
        } else {
            error = "include '" + include_path.string() + "' has no section '" + spec->section + "'";
            return false;
        }

        root[section] = root[section]
            ? merge_yaml_nodes(included_section, root[section])
            : YAML::Clone(included_section);
    }

    return true;
}

} // namespace

// Legacy YAML helpers (apply_xdp_config, apply_dpdk_config,
// apply_active_config, apply_passive_config, apply_traffic_match_config)
// have been removed. Configs go through the modern entry points only:
//   traffic_policy: -> apply_traffic_policy_config
//   runtime_policy: -> apply_runtime_policy_config
//   platform:       -> apply_platform_config
//   egress:         -> apply_egress_config
// The legacy fields (cfg.input.*, cfg.active.*, cfg.passive.*,
// cfg.xdp_runtime.*, cfg.traffic_match) are populated from the modern
// shape via control::apply_desired_config_to_legacy() at the end of
// from_file().

/**
 * @brief Parse the top-level `egress:` block.
 *
 * Accepts the following shape (all fields optional, defaults match
 * EgressConfig):
 *
 *   egress:
 *     kind: tun | raw_nic | raw_socket | none
 *     device: openpenny-tun
 *     tun:
 *       multi_queue: true
 *       mtu: 9000
 *       txqlen: 10000
 *       bring_up: true
 *     raw_nic:
 *       bind_device: true
 *
 * Unknown kinds are downgraded to 'none' with a warning (see
 * parse_egress_kind()).
 */
static void apply_egress_config(const YAML::Node& egress, egress::EgressConfig& cfg) {
    if (!egress) return;

    if (auto kind = egress["kind"]) {
        cfg.kind = egress::parse_egress_kind(kind.as<std::string>());
    }
    set_if_present(egress, "device", cfg.device);
    // Alternate keys for operator convenience.
    set_if_present(egress, "interface", cfg.device);
    set_if_present(egress, "ifname", cfg.device);

    if (auto tun = egress["tun"]) {
        set_if_present(tun, "multi_queue", cfg.tun_multi_queue);
        set_if_present(tun, "mtu", cfg.tun_mtu);
        set_if_present(tun, "txqlen", cfg.tun_txqlen);
        set_if_present(tun, "bring_up", cfg.tun_bring_up);
        set_if_present(tun, "rp_filter_loose", cfg.tun_rp_filter_loose);
    }
    if (auto raw_nic = egress["raw_nic"]) {
        set_if_present(raw_nic, "bind_device", cfg.raw_nic_bind_device);
    }
}

static void apply_traffic_policy_config(const YAML::Node& policy,
                                        control::TrafficPolicy& cfg) {
    if (!policy) return;

    // Canonical spelling: `default`. The earlier `default_policy` and
    // `default_action` aliases have been retired.
    if (auto default_node = policy["default"]) {
        if (auto decision = parse_traffic_decision(default_node.as<std::string>())) {
            cfg.default_decision = *decision;
        }
    }

    const auto rules = policy["rules"];
    if (!rules || !rules.IsSequence()) return;

    cfg.rules.clear();
    int implicit_priority = 0;
    for (const auto& rule_node : rules) {
        control::TrafficPolicyRule rule{};
        rule.priority = implicit_priority++;
        set_if_present(rule_node, "enabled", rule.enabled);
        set_if_present(rule_node, "name", rule.name);
        set_if_present(rule_node, "priority", rule.priority);

        // Canonical: `decision`. The `action` alias has been retired.
        if (auto decision_node = rule_node["decision"]) {
            if (auto decision = parse_traffic_decision(decision_node.as<std::string>())) {
                rule.decision = *decision;
            }
        }

        // Canonical: `src_prefix` / `dst_prefix`. The `src_ip` / `dst_ip`
        // aliases have been retired; use a /32 prefix for a single host.
        if (auto src = rule_node["src_prefix"]) {
            if (auto parsed = parse_ipv4_prefix_host(src.as<std::string>())) {
                rule.src_ip = *parsed;
            }
        }
        if (auto dst = rule_node["dst_prefix"]) {
            if (auto parsed = parse_ipv4_prefix_host(dst.as<std::string>())) {
                rule.dst_ip = *parsed;
            }
        }
        if (auto proto = parse_ip_proto_scalar(rule_node["protocol"])) {
            rule.ip_proto = *proto;
        }
        if (auto src_port = rule_node["src_port"]) {
            rule.src_port = static_cast<std::uint16_t>(src_port.as<unsigned>());
        }
        if (auto dst_port = rule_node["dst_port"]) {
            rule.dst_port = static_cast<std::uint16_t>(dst_port.as<unsigned>());
        }

        cfg.rules.push_back(std::move(rule));
    }
}

static void apply_runtime_policy_config(const YAML::Node& policy,
                                        control::RuntimePolicy& cfg) {
    if (!policy) return;

    if (auto mode = policy["mode"]) {
        if (auto parsed = parse_runtime_mode(mode.as<std::string>())) {
            cfg.mode = *parsed;
        }
    }

    if (auto safety = policy["safety"]) {
        set_if_present(safety, "allow_ssh_bypass", cfg.safety.allow_ssh_bypass);
    }
    set_if_present(policy, "allow_ssh_bypass", cfg.safety.allow_ssh_bypass);

    // Canonical: nested `aggregates: { enabled: ... }`. The flat
    // `aggregates_enabled` shortcut has been retired.
    if (auto aggregates = policy["aggregates"]) {
        set_if_present(aggregates, "enabled", cfg.aggregates_enabled);
    }

    const auto thresholds = policy["thresholds"] ? policy["thresholds"] : policy;
    auto& t = cfg.thresholds;
    set_if_present(thresholds, "packet_drop_probability", t.packet_drop_probability);
    set_if_present(thresholds, "max_duplicate_ratio", t.max_duplicate_ratio);
    set_if_present(thresholds, "max_reordering_ratio", t.max_reordering_ratio);
    set_if_present(thresholds,
                   "retransmission_observation_miss_rate",
                   t.retransmission_observation_miss_rate);
    set_if_present(thresholds,
                   "retransmission_timeout_in_seconds",
                   t.retransmission_timeout_in_seconds);
    set_if_present(thresholds,
                   "admission_grace_period_seconds",
                   t.admission_grace_period_seconds);
    set_if_present(thresholds,
                   "monitored_flow_idle_expiry_seconds",
                   t.monitored_flow_idle_expiry_seconds);
    set_if_present(thresholds, "drop_state_seconds", t.drop_state_seconds);
    set_if_present(thresholds, "min_packet_drops_per_flow", t.min_packet_drops_per_flow);
    set_if_present(thresholds, "max_packet_drops_per_flow", t.max_packet_drops_per_flow);
    set_if_present(thresholds,
                   "max_packet_drops_global_aggregate",
                   t.max_packet_drops_global_aggregate);
    set_if_present(thresholds, "max_monitored_flows", t.max_monitored_flows);
    set_if_present(thresholds,
                   "stop_after_individual_flows",
                   t.stop_after_individual_flows);
    set_if_present(thresholds,
                   "min_closed_loop_flows",
                   t.min_closed_loop_flows);
    set_if_present(thresholds,
                   "passive_min_flows_to_finish",
                   t.passive_min_flows_to_finish);
    set_if_present(thresholds,
                   "passive_max_parallel_flows",
                   t.passive_max_parallel_flows);
    set_if_present(thresholds,
                   "passive_max_execution_time_seconds",
                   t.passive_max_execution_time_seconds);
}

static void apply_platform_config(const YAML::Node& platform,
                                  control::PlatformConfig& cfg) {
    if (!platform) return;

    if (auto backend = platform["backend"]) {
        if (auto parsed = parse_platform_backend(backend.as<std::string>())) {
            cfg.backend = *parsed;
        }
    }

    set_if_present(platform, "interface", cfg.interface_name);
    set_if_present(platform, "ifname", cfg.interface_name);   // ifname kept as convenience alias for `interface`
    set_if_present(platform, "queue", cfg.queue);
    set_if_present(platform, "queue_count", cfg.queue_count);
    set_uint_vector_if_present(platform, "worker_cpus", cfg.worker_cpus);
    set_if_present(platform, "batch", cfg.batch);
    set_if_present(platform, "poll_timeout_ms", cfg.poll_timeout_ms);

    // Canonical: nested `xdp:` block (inside `platform:`, so the path
    // is `platform.xdp.*`). The earlier `af_xdp:` alias here has been
    // retired; the `backend: af_xdp` value (used at the platform root)
    // is unchanged.
    if (auto xdp = platform["xdp"]) {
        set_if_present(xdp, "interface", cfg.interface_name);
        set_if_present(xdp, "ifname", cfg.interface_name);
        set_if_present(xdp, "queue", cfg.queue);
        set_if_present(xdp, "rx_queue", cfg.queue);
        set_if_present(xdp, "queue_count", cfg.queue_count);
        set_uint_vector_if_present(xdp, "worker_cpus", cfg.worker_cpus);
        set_if_present(xdp, "drv_mode", cfg.prefer_xdp_driver_mode);
        set_if_present(xdp, "zerocopy", cfg.request_zerocopy);
        set_if_present(xdp, "require_zerocopy", cfg.require_zerocopy);
        set_if_present(xdp, "allow_skb_fallback", cfg.allow_skb_fallback);
        set_if_present(xdp, "allow_copy_fallback", cfg.allow_copy_fallback);
        set_if_present(xdp, "force_copy_mode", cfg.force_copy_mode);
        set_if_present(xdp, "attach_program", cfg.attach_xdp_program);
        set_if_present(xdp, "detach_on_close", cfg.detach_xdp_on_close);
        set_if_present(xdp, "pin_maps", cfg.pin_maps);
        set_if_present(xdp, "reuse_pins", cfg.reuse_pins);
        set_if_present(xdp, "update_dataplane_rules", cfg.update_dataplane_rules);
        set_if_present(xdp, "frame_size", cfg.frame_size);
        set_if_present(xdp, "num_frames", cfg.num_frames);
        set_if_present(xdp, "rx_ring", cfg.rx_ring);
        set_if_present(xdp, "batch", cfg.batch);
        set_if_present(xdp, "poll_timeout_ms", cfg.poll_timeout_ms);
        set_if_present(xdp, "bpf_object", cfg.bpf_object);
        set_if_present(xdp, "bpf_program", cfg.bpf_program);
    }

    if (auto dpdk = platform["dpdk"]) {
        set_if_present(dpdk, "interface", cfg.interface_name);
        set_if_present(dpdk, "ifname", cfg.interface_name);
        set_if_present(dpdk, "device", cfg.interface_name);
        set_if_present(dpdk, "queue", cfg.queue);
        set_if_present(dpdk, "burst", cfg.dpdk_burst);
    }
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

    std::string include_error;
    if (!resolve_yaml_includes(root, path, include_error)) {
        std::cerr << "Config include resolution failed: " << include_error << '\n';
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

        bool has_traffic_policy = false;
        bool has_runtime_policy = false;
        bool has_platform_config = false;
        if (auto traffic_policy = root["traffic_policy"]) {
            apply_traffic_policy_config(traffic_policy, cfg.desired_config.traffic);
            has_traffic_policy = true;
        }
        if (auto runtime_policy = root["runtime_policy"]) {
            apply_runtime_policy_config(runtime_policy, cfg.desired_config.runtime);
            has_runtime_policy = true;
        }
        if (auto platform = root["platform"]) {
            apply_platform_config(platform, cfg.desired_config.platform);
            has_platform_config = true;
        }

        // Egress block: declarative configuration of the PacketSink used
        // to re-inject matched packets. Absent => EgressKind::None.
        if (auto egress_node = root["egress"]) {
            apply_egress_config(egress_node, cfg.egress);
        }

        // The retired legacy entry points -- `input_sources:`,
        // `monitoring.active`/`monitoring.penny`, root-level `active:` /
        // `penny:` / `xdp:` / `dpdk:` / `input_backend:` / `ingress_mode:` /
        // `traffic_match:` -- have been removed. Use the modern shape:
        //   traffic_policy:  ...   (5-tuple include/exclude rules)
        //   runtime_policy:  ...   (mode, thresholds, aggregates, safety)
        //   platform:        ...   (backend, interface, queue, xdp/dpdk tuning)
        //   egress:          ...   (where matched packets go)

        auto legacy_desired = control::desired_from_legacy_config(cfg);
        if (!has_traffic_policy) {
            cfg.desired_config.traffic = legacy_desired.traffic;
        }
        if (!has_runtime_policy) {
            cfg.desired_config.runtime = legacy_desired.runtime;
        }
        if (!has_platform_config) {
            cfg.desired_config.platform = legacy_desired.platform;
        }
        control::apply_desired_config_to_legacy(cfg, cfg.desired_config);
        cfg.effective_config = control::compile_effective_config(cfg.desired_config);
    } catch (const YAML::Exception&) {
        return std::nullopt;
    }

    if (cfg.active.retransmission_miss_probability <= 0.0) {
        return std::nullopt;
    }

    // Preserve the YAML-configured starting queue before any per-worker
    // mutation touches cfg.queue. Consumers that need the invariant base
    // (e.g. the AF_XDP RSS coverage check) read cfg.queue_base.
    cfg.queue_base = cfg.queue;

    return cfg;
}

} // namespace openpenny
