// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/grpc/PennyService.h"

#include "openpenny/app/core/WorkerLauncher.h"
#include "openpenny/config/Config.h"
#include "openpenny/log/Log.h"

#include <nlohmann/json.hpp>
#include <filesystem>
#include <yaml-cpp/yaml.h>
#include <grpcpp/grpcpp.h>
#include <cstdio>
#include <fstream>
#include <vector>
#include <regex>
#include <system_error>

namespace openpenny::grpc_service {

/**
 * @brief Construct a PennyServiceImpl with default configuration values and an optional
 *        configuration-path override.
 */
PennyServiceImpl::PennyServiceImpl(const Config& defaults, std::string config_path)
    : defaults_(defaults), config_path_(std::move(config_path)) {}

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

    // Prefix and mask.
    if (!req.prefix().empty() && req.mask_bits() > 0 && req.mask_bits() <= 32) {
        opts.prefix_ip = req.prefix();
        opts.mask_bits = static_cast<int>(req.mask_bits());
        opts.has_prefix = true;
        // Pipeline helpers will derive mask_host/prefix_host from prefix_cidr.
        opts.prefix_cidr = opts.prefix_ip + "/" + std::to_string(opts.mask_bits);
    }

    // Default forwarding to TUN unless explicitly disabled by the caller.
    opts.forward_to_tun = !req.has_forward_to_tun() || req.forward_to_tun();
    if (req.has_tun_name() && !req.tun_name().empty()) {
        opts.tun_name = req.tun_name();
    } else {
        opts.tun_name = "xdp-tu";
    }

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
} // namespace

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

    worker_cfg.forward_to_tun = request->has_forward_to_tun() ? request->forward_to_tun() : worker_cfg.forward_to_tun;
    worker_cfg.forward_raw_socket = request->has_forward_raw_socket() && request->forward_raw_socket();

    if (request->has_tun_name() && !request->tun_name().empty()) {
        worker_cfg.tun_name = request->tun_name();
    }

    worker_cfg.forward_device = (request->has_forward_device() && !request->forward_device().empty())
                                    ? request->forward_device()
                                    : "";

    worker_cfg.tun_multi_queue = !request->has_tun_multi_queue() || request->tun_multi_queue();
    worker_cfg.tun_mtu = request->has_tun_mtu() ? request->tun_mtu() : 0;

    // Build pipeline options.
    PipelineOptions opts = make_options(*request);
    // Allow inline JSON override from the request.
    std::string temp_config_path;
    if (request->has_config_override_json() && !request->config_override_json().empty()) {
        std::filesystem::path base_dir = std::filesystem::path(worker_cfg.config_path).parent_path();
        if (base_dir.empty()) base_dir = std::filesystem::current_path();
        YAML::Node base_cfg;
        try {
            base_cfg = YAML::LoadFile(worker_cfg.config_path);
        } catch (const std::exception& e) {
            TCPLOG_ERROR("Failed to load base config %s: %s", worker_cfg.config_path.c_str(), e.what());
        }
        nlohmann::json base_json = yaml_to_json(base_cfg);
        nlohmann::json merged = base_json;
        const bool use_active = opts.mode == PipelineOptions::Mode::Active;
        if (request->has_config_override_json() && !request->config_override_json().empty()) {
            try {
                nlohmann::json override_json = nlohmann::json::parse(request->config_override_json());
                if (override_json.contains("monitoring") && override_json["monitoring"].is_object()) {
                    auto& mon = override_json["monitoring"];
            if (use_active && mon.contains("active")) {
                merged["monitoring"]["active"] = mon["active"];
            } else if (!use_active && mon.contains("passive")) {
                merged["monitoring"]["passive"] = mon["passive"];
            }
        }
        // Propagate request prefix/mask into XDP runtime if provided.
        if (!request->prefix().empty() && request->mask_bits() > 0 && request->mask_bits() <= 32) {
            merged["input_sources"]["xdp"]["runtime"]["prefix"] = request->prefix();
            merged["input_sources"]["xdp"]["runtime"]["mask_bits"] = request->mask_bits();
        }
                // Global forward overrides (if provided).
                if (override_json.contains("traffic_forwarding")) {
                    merged["traffic_forwarding"] = override_json["traffic_forwarding"];
                }
                // Interface/queue overrides.
                if (override_json.contains("ifname")) merged["ifname"] = override_json["ifname"];
                if (override_json.contains("queue")) merged["queue"] = override_json["queue"];
                if (override_json.contains("queue_count")) merged["queue_count"] = override_json["queue_count"];
                if (override_json.contains("tun_multi_queue")) {
                    merged["traffic_forwarding"]["tun"]["multi_queue"] = override_json["tun_multi_queue"];
                }
                if (override_json.contains("tun_mtu")) {
                    merged["traffic_forwarding"]["tun"]["mtu"] = override_json["tun_mtu"];
                }
                if (override_json.contains("forward_to_tun")) {
                    merged["traffic_forwarding"]["tun"]["enable"] = override_json["forward_to_tun"];
                }

                // Resolve relative bpf_object path against base_dir only if the file exists there;
                // otherwise keep the original relative path so it can be found in the worker CWD.
                try {
                    if (merged.contains("input_sources") && merged["input_sources"].contains("xdp") &&
                        merged["input_sources"]["xdp"].contains("runtime") &&
                        merged["input_sources"]["xdp"]["runtime"].contains("bpf_object")) {
                        std::string bpf_obj = merged["input_sources"]["xdp"]["runtime"]["bpf_object"].get<std::string>();
                        std::filesystem::path p(bpf_obj);
                        if (p.is_relative()) {
                            std::filesystem::path candidate = base_dir / p;
                            if (std::filesystem::exists(candidate)) {
                                merged["input_sources"]["xdp"]["runtime"]["bpf_object"] = candidate.string();
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

        // Fill forwarding defaults (TUN) from merged config unless overridden by request.
        auto bool_from_json = [](const nlohmann::json& j, bool fallback) {
            if (j.is_boolean()) return j.get<bool>();
            if (j.is_number_integer()) return j.get<int>() != 0;
            return fallback;
        };
        auto str_from_json = [](const nlohmann::json& j, const std::string& fallback) {
            if (j.is_string()) return j.get<std::string>();
            return fallback;
        };
        try {
            if (merged.contains("traffic_forwarding") && merged["traffic_forwarding"].contains("tun")) {
                auto& tun = merged["traffic_forwarding"]["tun"];
                bool tun_enable_cfg = bool_from_json(tun["enable"], true);
                // Request flag wins if present.
                if (request->has_forward_to_tun()) {
                    tun_enable_cfg = request->forward_to_tun();
                }
                merged["traffic_forwarding"]["tun"]["enable"] = tun_enable_cfg;
                // Set worker/opts from merged values.
                worker_cfg.forward_to_tun = tun_enable_cfg;
                opts.forward_to_tun = tun_enable_cfg;
                std::string tun_name_cfg = str_from_json(tun["name"], "");
                if (!tun_name_cfg.empty()) {
                    worker_cfg.tun_name = tun_name_cfg;
                    opts.tun_name = tun_name_cfg;
                }
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

    // Build a JSON summary akin to the CLI output.
    nlohmann::json summary;
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
