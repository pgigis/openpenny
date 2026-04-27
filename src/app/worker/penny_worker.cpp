// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/config/Config.h"
#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/egress/PacketSink.h"
#include "openpenny/log/Log.h"

#include <filesystem>
#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <vector>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <nlohmann/json.hpp>

namespace {

struct Args {
    std::string config{"openpenny.yaml"};
    std::string prefix;
    int mask_bits{0};
    std::string test_id{"worker"};
    openpenny::LogLevel log_level{openpenny::LogLevel::WARN};
    bool log_override{false};
    // Egress selection. `egress_kind` defaults to "tun" to preserve the
    // historical worker behaviour (forward matched packets into a TUN
    // device unless explicitly told not to). Any of the four EgressKind
    // values supported by make_packet_sink() is accepted.
    std::string egress_kind{"tun"};
    std::string egress_device;
    bool tun_multi_queue{true};
    int tun_mtu{9000};
    openpenny::PipelineOptions::Mode mode{openpenny::PipelineOptions::Mode::Active};
    std::string stats_socket{};
    unsigned queue_count{1};
};

namespace {

std::string resolve_bpf_object(const std::string& path,
                               const std::string& config_path) {
    namespace fs = std::filesystem;
    fs::path p(path);
    if (p.is_absolute() && fs::exists(p)) return p.string();
    fs::path cfg_dir = fs::path(config_path).parent_path();
    std::vector<fs::path> candidates{
        fs::current_path() / p,
        cfg_dir / p,
        cfg_dir.parent_path() / p,
        cfg_dir.parent_path() / "ebpf" / "af_xdp" / p.filename(),
        cfg_dir.parent_path().parent_path() / "ebpf" / "af_xdp" / p.filename()
    };
    for (const auto& c : candidates) {
        if (!c.empty() && fs::exists(c)) {
            return c.string();
        }
    }
    for (const auto& c : candidates) {
        fs::path dir = c.parent_path();
        if (!dir.empty() &&
            fs::exists(dir / "Makefile") &&
            fs::exists(dir / "xdp_redirect_openpenny.c")) {
            return c.string();
        }
    }
    return path;
}

bool ensure_xdp_object(const std::string& object_path) {
    namespace fs = std::filesystem;
    fs::path obj(object_path);
    fs::path xdp_dir = obj.parent_path();
    fs::path source = xdp_dir / "xdp_redirect_openpenny.c";
    fs::path makefile = xdp_dir / "Makefile";

    std::error_code ec;
    const bool object_exists = fs::exists(obj, ec);
    bool needs_build = !object_exists;
    if (object_exists) {
        const auto obj_time = fs::last_write_time(obj, ec);
        if (!ec && fs::exists(source, ec)) {
            const auto source_time = fs::last_write_time(source, ec);
            needs_build = !ec && source_time > obj_time;
        }
        if (!needs_build && !ec && fs::exists(makefile, ec)) {
            const auto makefile_time = fs::last_write_time(makefile, ec);
            needs_build = !ec && makefile_time > obj_time;
        }
    }

    if (!needs_build) return true;
    if (!fs::exists(makefile, ec)) return false;

    std::string cmd = "make -C " + xdp_dir.string() + " xdp_redirect_openpenny.o";
    return std::system(cmd.c_str()) == 0 && fs::exists(obj, ec);
}

} // namespace

Args parse_args(int argc, char** argv) {
    Args a;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            a.config = argv[++i];
        } else if (arg == "--prefix" && i + 1 < argc) {
            a.prefix = argv[++i];
        } else if (arg == "--mask-bits" && i + 1 < argc) {
            a.mask_bits = std::stoi(argv[++i]);
        } else if (arg == "--test-id" && i + 1 < argc) {
            a.test_id = argv[++i];
        } else if (arg == "--log" && i + 1 < argc) {
            std::string lvl = argv[++i];
            if (lvl == "trace") a.log_level = openpenny::LogLevel::TRACE;
            else if (lvl == "debug") a.log_level = openpenny::LogLevel::DEBUG;
            else if (lvl == "info") a.log_level = openpenny::LogLevel::INFO;
            else if (lvl == "warn") a.log_level = openpenny::LogLevel::WARN;
            else if (lvl == "error") a.log_level = openpenny::LogLevel::ERROR;
            a.log_override = true;
        } else if (arg == "--egress" && i + 1 < argc) {
            // New unified selector: --egress <none|tun|raw_socket|raw_nic>
            a.egress_kind = argv[++i];
        } else if (arg == "--egress-device" && i + 1 < argc) {
            a.egress_device = argv[++i];
        } else if (arg == "--stats-sock" && i + 1 < argc) {
            a.stats_socket = argv[++i];
        } else if (arg == "--mode" && i + 1 < argc) {
            std::string m = argv[++i];
            if (m == "active") a.mode = openpenny::PipelineOptions::Mode::Active;
            else if (m == "passive") a.mode = openpenny::PipelineOptions::Mode::Passive;
        } else if (arg == "--tun-mtu" && i + 1 < argc) {
            a.tun_mtu = std::stoi(argv[++i]);
        } else if (arg == "--tun-multi-queue") {
            a.tun_multi_queue = true;
        } else if (arg == "--no-tun-multi-queue") {
            a.tun_multi_queue = false;
        } else if ((arg == "--queues" || arg == "-Q") && i + 1 < argc) {
            std::string v = argv[++i];
            char* end = nullptr;
            errno = 0;
            long n = std::strtol(v.c_str(), &end, 10);
            if (errno != 0 || end == v.c_str() || *end != '\0' || n <= 0) {
                std::cerr << "Invalid queue count: " << v << "\n";
                std::exit(1);
            }
            a.queue_count = static_cast<unsigned>(n);
        }
    }
    return a;
}

// Promote CLI args into the declarative EgressConfig consumed by the
// pipeline. We keep the TUN-oriented knobs (mtu, multi-queue) on the CLI
// because historically the worker expected them; they only apply when
// `kind == Tun` and are otherwise ignored by the factory.
openpenny::egress::EgressConfig egress_from_args(const Args& args) {
    openpenny::egress::EgressConfig egress{};
    egress.kind = openpenny::egress::parse_egress_kind(args.egress_kind);
    egress.device = args.egress_device;
    egress.tun_multi_queue = args.tun_multi_queue;
    egress.tun_mtu = args.tun_mtu;
    return egress;
}

bool apply_prefix_to_runtime(const Args& args, openpenny::Config& cfg) {
    if (args.prefix.empty() || args.mask_bits <= 0 || args.mask_bits > 32) {
        return false;
    }
    in_addr addr{};
    if (inet_pton(AF_INET, args.prefix.c_str(), &addr) != 1) {
        std::cerr << "status=error\nerror=invalid_prefix\n";
        return false;
    }
    uint32_t mask_host = 0;
    if (args.mask_bits == 32) {
        mask_host = 0xFFFFFFFFu;
    } else {
        mask_host = 0xFFFFFFFFu << (32 - args.mask_bits);
    }

    // Propagate the runtime override into the XDP/BPF filter config. The
    // legacy PipelineOptions prefix_* fields are gone now; the pipeline
    // looks at cfg.xdp_runtime for the kernel filter parameters.
    cfg.xdp_runtime.prefix_host = ntohl(addr.s_addr);
    cfg.xdp_runtime.mask_host = mask_host;
    cfg.xdp_runtime.prefix_text = args.prefix;
    cfg.xdp_runtime.mask_bits = args.mask_bits;
    return true;
}

} // namespace

int main(int argc, char** argv) {
    auto args = parse_args(argc, argv);

    auto cfg = openpenny::Config::from_file(args.config);
    if (!cfg) {
        std::cerr << "status=error\nerror=failed_to_load_config\n";
        return 1;
    }
    cfg->xdp_runtime.bpf_object = resolve_bpf_object(cfg->xdp_runtime.bpf_object, args.config);
    if (cfg->input.backend == openpenny::PacketInputBackend::XdpAfXdp &&
        !ensure_xdp_object(cfg->xdp_runtime.bpf_object)) {
        std::cerr << "status=error\nerror=xdp_bpf_object_build_failed\n";
        return 1;
    }
    cfg->queue_count = std::max(1u, args.queue_count);

    if (!args.log_override) {
        std::string lvl = cfg->log_level;
        for (auto& c : lvl) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (lvl == "trace") args.log_level = openpenny::LogLevel::TRACE;
        else if (lvl == "debug") args.log_level = openpenny::LogLevel::DEBUG;
        else if (lvl == "info") args.log_level = openpenny::LogLevel::INFO;
        else if (lvl == "warn") args.log_level = openpenny::LogLevel::WARN;
        else if (lvl == "error") args.log_level = openpenny::LogLevel::ERROR;
    }

    openpenny::Logger::init({.level = args.log_level});

    // Install the declarative egress on the config. CLI args override any
    // egress block already present in the YAML so worker subprocesses can
    // be steered by the orchestrator without having to rewrite the file.
    if (!args.egress_kind.empty()) {
        auto egress = egress_from_args(args);
        if (egress.kind != openpenny::egress::EgressKind::None || !cfg->egress.enabled()) {
            cfg->egress = egress;
        }
    }
    // If the caller didn't specify a device but the YAML already has one,
    // leave the YAML value alone. If the caller did specify one, it wins
    // (already applied in egress_from_args above).

    openpenny::app::init_thread_counters(cfg->queue_count);
    openpenny::app::set_thread_counter_index(0);
    (void)apply_prefix_to_runtime(args, *cfg);

    openpenny::PipelineOptions opts{};
    opts.mode = args.mode;
    opts.stats_socket_path = args.stats_socket;
    opts.queue_count = cfg->queue_count;
    if (opts.traffic_match.empty()) {
        opts.traffic_match = cfg->traffic_match;
    }

    auto summary = drive_pipeline_threaded(*cfg, opts);
    if (!summary.active) {
        std::cout << "status=error\nerror=pipeline_failed\n";
        return 0;
    }

    const auto& res = *summary.active;
    std::cout << "status=ok\n";
    std::cout << "test_id=" << args.test_id << "\n";
    std::cout << "packets_processed=" << res.packets_processed << "\n";
    std::cout << "packets_forwarded=" << res.packets_forwarded << "\n";
    std::cout << "forward_errors=" << res.forward_errors << "\n";
    std::cout << "pure_ack_packets=" << res.pure_ack_packets << "\n";
    std::cout << "data_packets=" << res.data_packets << "\n";
    std::cout << "duplicate_packets=" << res.duplicate_packets << "\n";
    std::cout << "in_order_packets=" << res.in_order_packets << "\n";
    std::cout << "out_of_order_packets=" << res.out_of_order_packets << "\n";
    std::cout << "retransmitted_packets=" << res.retransmitted_packets << "\n";
    std::cout << "non_retransmitted_packets=" << res.non_retransmitted_packets << "\n";
    std::cout << "pending_retransmissions=" << res.pending_retransmissions << "\n";
    std::cout << "flows_tracked_syn=" << res.flows_tracked_syn << "\n";
    std::cout << "flows_tracked_data=" << res.flows_tracked_data << "\n";
    std::cout << "penny_completed=" << (res.penny_completed ? 1 : 0) << "\n";
    std::cout << "aggregates_penny_completed=" << (res.aggregates_penny_completed ? 1 : 0) << "\n";
    std::cout << "aggregates_enabled=" << (summary.aggregates_enabled ? 1 : 0) << "\n";
    const bool is_active_mode = opts.mode == openpenny::PipelineOptions::Mode::Active;
    const auto runtime = openpenny::current_runtime_setup();
    const bool aggregates_enabled = summary.aggregates_enabled && is_active_mode;
    auto aggregates_status_str = [&]() -> std::string {
        if (!aggregates_enabled) return "n/a";
        switch (runtime.aggregates_status) {
            case openpenny::RuntimeStatus::AggregatesStatus::CLOSED_LOOP: return "closed_loop";
            case openpenny::RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP: return "not_closed_loop";
            case openpenny::RuntimeStatus::AggregatesStatus::DUPLICATES_EXCEEDED: return "duplicates_exceeded";
            case openpenny::RuntimeStatus::AggregatesStatus::PENDING:
            default: return "pending";
        }
    }();
    const bool aggregates_done = aggregates_enabled &&
                                 runtime.aggregates_status != openpenny::RuntimeStatus::AggregatesStatus::PENDING;
    const std::string aggregates_decision_state =
        aggregates_enabled ? (aggregates_done ? "completed" : "running") : "n/a";
    const bool aggregates_has_eval = aggregates_enabled && runtime.has_aggregate_eval;
    const uint64_t agg_eval_data = aggregates_has_eval ? runtime.aggregate_eval_counters.data_packets : 0;
    const uint64_t agg_eval_dup = aggregates_has_eval ? runtime.aggregate_eval_counters.duplicate_packets : 0;
    const uint64_t agg_eval_rtx = aggregates_has_eval ? runtime.aggregate_eval_counters.retransmitted_packets : 0;
    const uint64_t agg_eval_nonrtx = aggregates_has_eval ? runtime.aggregate_eval_counters.non_retransmitted_packets : 0;
    const uint64_t aggregates_snapshots = aggregates_enabled ? summary.drop_snapshots.size() : 0;
    openpenny::app::AggregatedCounters agg_snapshot{};
    if (is_active_mode) {
        agg_snapshot = res.aggregates_snapshot
                           ? *res.aggregates_snapshot
                           : openpenny::app::aggregate_counters();
    }
    std::cout << "aggregates_status=" << aggregates_status_str << "\n";
    std::cout << "aggregates_decision_complete=" << (aggregates_done ? 1 : 0) << "\n";
    std::cout << "aggregates_has_eval=" << (aggregates_has_eval ? 1 : 0) << "\n";
    std::cout << "aggregates_eval_data_packets=" << agg_eval_data << "\n";
    std::cout << "aggregates_eval_duplicate_packets=" << agg_eval_dup << "\n";
    std::cout << "aggregates_eval_retransmitted_packets=" << agg_eval_rtx << "\n";
    std::cout << "aggregates_eval_non_retransmitted_packets=" << agg_eval_nonrtx << "\n";
    std::cout << "aggregates_snapshots=" << aggregates_snapshots << "\n";
    std::cout << "aggregate_flows_monitored=" << agg_snapshot.flows_monitored << "\n";
    std::cout << "aggregate_flows_finished=" << agg_snapshot.flows_finished << "\n";
    std::cout << "aggregate_flows_closed_loop=" << agg_snapshot.flows_closed_loop << "\n";
    std::cout << "aggregate_flows_not_closed_loop=" << agg_snapshot.flows_not_closed_loop << "\n";
    std::cout << "aggregate_flows_rst=" << agg_snapshot.flows_rst << "\n";
    std::cout << "aggregate_flows_duplicates_exceeded=" << agg_snapshot.flows_duplicates_exceeded << "\n";
    // Emit JSON summary similar to CLI output.
    nlohmann::json j;
    j["test_id"] = args.test_id;
    j["status"] = "ok";
    j["packets"] = {
        {"processed", res.packets_processed},
        {"forwarded", res.packets_forwarded},
        {"errors", res.forward_errors},
        {"pure_ack", res.pure_ack_packets},
        {"data", res.data_packets},
        {"duplicate", res.duplicate_packets},
        {"in_order", res.in_order_packets},
        {"out_of_order", res.out_of_order_packets},
        {"retransmitted", res.retransmitted_packets},
        {"non_retransmitted", res.non_retransmitted_packets}
    };
    j["flows"] = {
        {"tracked_syn", res.flows_tracked_syn},
        {"tracked_data", res.flows_tracked_data}
    };
    j["penny_completed"] = res.penny_completed;
    j["aggregates_completed"] = res.aggregates_penny_completed;
    j["aggregates_enabled"] = summary.aggregates_enabled;
    j["aggregates_status"] = aggregates_status_str;
    j["aggregates_decision_complete"] = aggregates_done;
    j["aggregates_decision_state"] = aggregates_decision_state;
    j["aggregates_has_eval"] = aggregates_has_eval;
    j["aggregates_snapshots"] = aggregates_snapshots;
    j["aggregates_eval"] = {
        {"data", agg_eval_data},
        {"duplicate", agg_eval_dup},
        {"retransmitted", agg_eval_rtx},
        {"non_retransmitted", agg_eval_nonrtx}
    };
    j["aggregate_flows"] = {
        {"monitored", agg_snapshot.flows_monitored},
        {"finished", agg_snapshot.flows_finished},
        {"closed_loop", agg_snapshot.flows_closed_loop},
        {"not_closed_loop", agg_snapshot.flows_not_closed_loop},
        {"rst", agg_snapshot.flows_rst},
        {"duplicates_exceeded", agg_snapshot.flows_duplicates_exceeded}
    };
    // Aggregate snapshot counters, if available.
    if (res.passive_flows_finished > 0 || !res.passive_gap_summaries.empty()) {
        nlohmann::json passive;
        passive["finished"] = res.passive_flows_finished;
        passive["open_gaps_flows"] = res.passive_flows_with_open_gaps;
        passive["open_gaps"] = res.passive_open_gaps;
        passive["rst"] = res.passive_flows_rst;
        passive["syn_only"] = res.passive_flows_syn_only;
        nlohmann::json details = nlohmann::json::array();
        for (const auto& line : res.passive_gap_summaries) {
            details.push_back(line);
        }
        passive["details"] = details;
        j["passive"] = passive;
    }
    std::cout << "json=" << j.dump() << "\n";
    // No explicit fd cleanup needed: the PacketSink owns its fd internally
    // and closes it on destruction when drive_pipeline_threaded returns.
    return 0;
}
