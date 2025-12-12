// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/config/Config.h"
#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/app/core/PerThreadStats.h"
#include "openpenny/log/Log.h"

#include <filesystem>
#include <iostream>
#include <string>
#include <cstring>
#include <cerrno>
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <nlohmann/json.hpp>

namespace {

struct Args {
    std::string config{"openpenny.yaml"};
    std::string prefix;
    int mask_bits{0};
    std::string test_id{"worker"};
    openpenny::LogLevel log_level{openpenny::LogLevel::WARN};
    bool log_override{false};
    bool forward_to_tun{true};
    bool forward_raw_socket{false};
    std::string tun_name{};
    std::string forward_device;
    bool tun_multi_queue{true};
    int tun_mtu{9000};
    openpenny::PipelineOptions::Mode mode{openpenny::PipelineOptions::Mode::Active};
    std::string stats_socket;
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
        cfg_dir.parent_path() / "xdp-fw" / p.filename(),
        cfg_dir.parent_path().parent_path() / "xdp-fw" / p.filename()
    };
    for (const auto& c : candidates) {
        if (!c.empty() && fs::exists(c)) {
            return c.string();
        }
    }
    return path;
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
        } else if (arg == "--forward-to-tun") {
            a.forward_to_tun = true;
        } else if (arg == "--no-forward-to-tun") {
            a.forward_to_tun = false;
        } else if (arg == "--forward-raw-socket") {
            a.forward_raw_socket = true;
            a.forward_to_tun = false;
        } else if (arg == "--tun-name" && i + 1 < argc) {
            a.tun_name = argv[++i];
        } else if (arg == "--forward-device" && i + 1 < argc) {
            a.forward_device = argv[++i];
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

int open_tun_device(const std::string& device, bool multi_queue, int tun_mtu) {
    auto tune_link = [&](const std::string& name) {
        int s = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) return;
        ifreq ifr{};
        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        ifr.ifr_qlen = 10000;
        (void)ioctl(s, SIOCSIFTXQLEN, &ifr);
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        ifr.ifr_mtu = tun_mtu > 0 ? tun_mtu : 9000;
        (void)ioctl(s, SIOCSIFMTU, &ifr);
        ::close(s);
    };

    int fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0) return -1;

    auto try_attach = [&](short flags) -> bool {
        ifreq ifr{};
        ifr.ifr_flags = flags;
        std::strncpy(ifr.ifr_name, device.c_str(), IFNAMSIZ - 1);
        return ioctl(fd, TUNSETIFF, &ifr) == 0;
    };

    short base_flags = IFF_TUN | IFF_NO_PI;
    if (multi_queue) {
        if (!try_attach(base_flags | IFF_MULTI_QUEUE)) {
            if (!try_attach(base_flags)) {
                int saved = errno;
                ::close(fd);
                errno = saved;
                return -1;
            }
        }
    } else {
        if (!try_attach(base_flags)) {
            int saved = errno;
            ::close(fd);
            errno = saved;
            return -1;
        }
    }

    tune_link(device);
    return fd;
}

int open_raw_socket(const std::string& device) {
    int fd = ::socket(AF_INET, SOCK_RAW | SOCK_NONBLOCK, IPPROTO_RAW);
    if (fd < 0) return -1;

    if (!device.empty()) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, device.c_str(), device.size()) != 0) {
            int saved = errno;
            ::close(fd);
            errno = saved;
            return -1;
        }
    }

    int one = 1;
    (void)setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
    return fd;
}

bool apply_prefix_to_opts(const Args& args, openpenny::PipelineOptions& opts) {
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

    opts.prefix_ip = args.prefix;
    opts.prefix_host = ntohl(addr.s_addr);
    opts.mask_bits = args.mask_bits;
    opts.mask_host = mask_host;
    opts.has_prefix = true;
    opts.prefix_cidr = opts.prefix_ip + "/" + std::to_string(opts.mask_bits);
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

    int forward_fd = -1;
    const std::string forward_name = !args.forward_device.empty() ? args.forward_device : args.tun_name;

    if (args.forward_raw_socket) {
        forward_fd = open_raw_socket(forward_name);
        if (forward_fd < 0) {
            std::cerr << "status=error\nerror=raw_socket_open_failed\n";
            return 1;
        }
    } else if (args.forward_to_tun) {
        forward_fd = open_tun_device(forward_name, args.tun_multi_queue, args.tun_mtu);
        if (forward_fd < 0) {
            std::cerr << "status=error\nerror=tun_open_failed\n";
            return 1;
        }
    }

    openpenny::PipelineOptions opts{};
    openpenny::app::init_thread_counters(cfg->queue_count);
    openpenny::app::set_thread_counter_index(0);
    (void)apply_prefix_to_opts(args, opts);
    opts.forward_raw_socket = args.forward_raw_socket && forward_fd >= 0;
    opts.forward_to_tun = args.forward_to_tun && !opts.forward_raw_socket && forward_fd >= 0;
    opts.tun_fd = opts.forward_to_tun ? forward_fd : -1;
    opts.tun_name = args.tun_name;
    opts.forward_fd = forward_fd;
    opts.forward_device = forward_name;
    opts.mode = args.mode;
    opts.stats_socket_path = args.stats_socket;
    opts.queue_count = cfg->queue_count;

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
    if (forward_fd >= 0) ::close(forward_fd);
    return 0;
}
