// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/config/Config.h"
#include "openpenny/log/Log.h"
#include "openpenny/app/cli/cli_helpers.h"
#include "openpenny/app/cli/source_setup.h"
#include "openpenny/app/core/PerThreadStats.h"

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <system_error>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <thread>
#include <chrono>

namespace {
// Tracks the attachment that was initiated by this process so we can undo it
// during shutdown even if execution exits via signal/exception.
struct AttachState {
    bool active{false};
    std::string iface;
    std::string mode;
};

AttachState g_attach_state;
volatile sig_atomic_t g_stop_requested = 0;

std::string attach_script_path() {
    static const std::string path = std::filesystem::absolute("scripts/xdp_attach.py").string();
    return path;
}

void run_detach_command() {
    // symmetrically detach the helper-installed XDP program (if any)
    if (!g_attach_state.active || g_attach_state.iface.empty()) return;
    std::ostringstream cmd;
    cmd << "python3 " << attach_script_path() << " --iface " << g_attach_state.iface
        << " --mode " << g_attach_state.mode << " --detach";
    std::system(cmd.str().c_str());
    g_attach_state.active = false;
}

void handle_signal(int sig) {
    // Simply note the request; drive_pipeline polls this flag between batches.
    g_stop_requested = 1;
    std::signal(sig, handle_signal);
}

void install_signal_handlers() {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
}

bool ensure_xdp_object(const std::filesystem::path& bpf_obj) {
    if (std::filesystem::exists(bpf_obj)) {
        return true;
    }
    std::cout << "[openpenny] building XDP program (make -C xdp-fw xdp_redirect_dstprefix.o)\n";
    int rc = std::system("make -C xdp-fw xdp_redirect_dstprefix.o");
    if (rc != 0) {
        std::cerr << "[openpenny] failed to build xdp_redirect_dstprefix.o (rc=" << rc << ")\n";
        return false;
    }
    if (!std::filesystem::exists(bpf_obj)) {
        std::cerr << "[openpenny] build completed but xdp-fw/xdp_redirect_dstprefix.o is still missing\n";
        return false;
    }
    return true;
}

std::string host_to_string(uint32_t host) {
    std::ostringstream out;
    out << ((host >> 24) & 0xff) << '.'
        << ((host >> 16) & 0xff) << '.'
        << ((host >> 8) & 0xff) << '.'
        << (host & 0xff);
    return out.str();
}

int open_tun_device(const std::string& device) {
    auto tune_link = [](const std::string& name) -> bool {
        int s = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) {
            std::cerr << "Failed to open socket to tune TUN '" << name
                      << "': " << std::strerror(errno) << "\n";
            return false;
        }
        bool ok = true;
        ifreq ifr{};
        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        ifr.ifr_qlen = 10000;
        if (ioctl(s, SIOCSIFTXQLEN, &ifr) != 0) ok = false;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        ifr.ifr_mtu = 9000;
        if (ioctl(s, SIOCSIFMTU, &ifr) != 0) ok = false;
        std::memset(&ifr, 0, sizeof(ifr));
        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
            ifr.ifr_flags |= IFF_UP;
            if (ioctl(s, SIOCSIFFLAGS, &ifr) != 0) ok = false;
        } else {
            ok = false;
        }
        ::close(s);
        if (!ok) {
            std::cerr << "Failed to configure TUN '" << name << "' (mtu/up/qlen)\n";
        }
        return ok;
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
    if (!try_attach(base_flags | IFF_MULTI_QUEUE)) {
        if (!try_attach(base_flags)) {
            int saved = errno;
            ::close(fd);
            errno = saved;
            return -1;
        }
    }

    if (!tune_link(device)) {
        ::close(fd);
        return -1;
    }
    return fd;
}

} // namespace

int main(int argc, char** argv) {
    auto cli_opts = openpenny::cli::normalize_options(openpenny::cli::parse_args(argc, argv));
    install_signal_handlers();

    pid_t pid = ::fork();
    if (pid < 0) {
        std::cerr << "Failed to fork: " << std::strerror(errno) << "\n";
        return 1;
    }
    if (pid > 0) {
        int status = 0;
        ::waitpid(pid, &status, 0);
        if (WIFEXITED(status)) return WEXITSTATUS(status);
        return 1;
    }

    int tun_fd = -1;
    auto close_tun = [&]() {
        if (tun_fd >= 0) {
            ::close(tun_fd);
            tun_fd = -1;
        }
    };

    if (cli_opts.forward_to_tun) {
        tun_fd = open_tun_device(cli_opts.tun_name);
        if (tun_fd < 0) {
            std::cerr << "Failed to open TUN device '" << cli_opts.tun_name
                      << "': " << std::strerror(errno) << std::endl;
            run_detach_command();
            return 1;
        }
    }

    auto cfg = openpenny::Config::from_file(cli_opts.config_path);
    if (!cfg) {
        std::cerr << "Failed to load config: " << cli_opts.config_path << '\n';
        run_detach_command();
        close_tun();
        return 1;
    }
    const bool use_xdp = openpenny::cli::to_lower(cli_opts.source) == "xdp";
    const bool use_dpdk = openpenny::cli::to_lower(cli_opts.source) == "dpdk";

    // CLI overrides for interface/queue take precedence over config defaults.
    if (!cli_opts.iface.empty()) {
        cfg->ifname = cli_opts.iface;
    }
    if (cli_opts.queue_override) {
        cfg->queue = cli_opts.queue_value;
    }
    cfg->queue_count = std::max(1u, cli_opts.queue_count);

    std::filesystem::path bpf_obj = std::filesystem::absolute("xdp-fw/xdp_redirect_dstprefix.o");
    if (use_xdp) {
        if (ensure_xdp_object(bpf_obj)) {
            cfg->xdp_runtime.bpf_object = bpf_obj.string();
        } else {
            std::cerr << "[openpenny] warning: continuing without a built XDP object; build manually if attach fails\n";
        }
    }
    
    if (!cli_opts.pin_conf_path.empty()) {
        cfg->xdp_runtime.pin_conf_path = cli_opts.pin_conf_path;
        cfg->xdp_runtime.pin_xsks_path = cli_opts.pin_xsks_path;
        cfg->xdp_runtime.pin_stats_path = cli_opts.pin_stats_path;
    }

    openpenny::app::init_thread_counters(std::max(1u, cli_opts.queue_count));
    openpenny::app::set_thread_counter_index(0);

    std::atomic<bool> agg_stop{false};
    std::atomic<uint64_t> agg_drop_threshold{12};
    std::thread agg_thread([&agg_stop, &agg_drop_threshold] {
        uint64_t last_agg_drops = 0;
        while (!agg_stop.load(std::memory_order_relaxed)) {
            auto agg = openpenny::app::aggregate_counters();
            if (agg.dropped_packets >= agg_drop_threshold.load(std::memory_order_relaxed) &&
                agg.dropped_packets != last_agg_drops) {
                // Place to emit/report aggregated counters when threshold crossed.
                last_agg_drops = agg.dropped_packets;
                // Hook: log, write to socket, etc.
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    if (use_xdp) {
        openpenny::cli::configure_xdp_source(*cfg, cli_opts);
    } else if (use_dpdk) {
        openpenny::cli::configure_dpdk_source(*cfg, cli_opts);
    }

    auto init_logger_from_cfg = [](const openpenny::Config& config) {
        openpenny::LoggerConfig lc;
        const auto mode = openpenny::cli::to_lower(config.log_mode);
        if (mode == "console") lc.mode = openpenny::LogMode::Console;
        else if (mode == "file") lc.mode = openpenny::LogMode::File;
        else lc.mode = openpenny::LogMode::Silent;
        lc.file_path = config.log_file;

        const auto lvl = openpenny::cli::to_lower(config.log_level);
        if (lvl == "trace") lc.level = openpenny::LogLevel::TRACE;
        else if (lvl == "debug") lc.level = openpenny::LogLevel::DEBUG;
        else if (lvl == "warn") lc.level = openpenny::LogLevel::WARN;
        else if (lvl == "error") lc.level = openpenny::LogLevel::ERROR;
        else lc.level = openpenny::LogLevel::INFO;

        openpenny::Logger::set_level(lc.level);
        openpenny::Logger::init(lc);
    };

    init_logger_from_cfg(*cfg);

    openpenny::PipelineOptions pipeline_opts;
    pipeline_opts.prefix_ip = cli_opts.prefix_ip;
    pipeline_opts.prefix_cidr = cli_opts.prefix_cidr;
    pipeline_opts.prefix_host = cli_opts.prefix_host;
    pipeline_opts.mask_host = cli_opts.mask_host;
    pipeline_opts.mask_bits = cli_opts.mask_bits;
    pipeline_opts.has_prefix = cli_opts.has_prefix;
    pipeline_opts.forward_to_tun = cli_opts.forward_to_tun && tun_fd >= 0;
    pipeline_opts.tun_fd = tun_fd;
    pipeline_opts.tun_name = cli_opts.tun_name;
    pipeline_opts.forward_fd = tun_fd;
    pipeline_opts.forward_device = cli_opts.tun_name;
    pipeline_opts.should_stop = [] { return g_stop_requested != 0; };
    pipeline_opts.mode = cli_opts.mode;
    pipeline_opts.stats_socket_path = cli_opts.stats_socket_path;
    pipeline_opts.queue_count = std::max(1u, cli_opts.queue_count);

    std::cout << "Polling packets on " << cfg->ifname << " queue " << cfg->queue
              << " (count=" << pipeline_opts.queue_count
              << ", Ctrl+C to stop, or wait for Penny to finish)..." << std::endl;

    // All heavy lifting happens inside the pipeline helper: this wires together
    // the reader, matcher, and the user-facing print/forward callbacks on a dedicated driver thread.
    auto result = openpenny::drive_pipeline_threaded(*cfg, pipeline_opts);

    agg_stop.store(true, std::memory_order_relaxed);
    if (agg_thread.joinable()) agg_thread.join();

    if (result.active) {
        const auto agg_snapshot = (result.active->aggregates_snapshot
                                       ? *result.active->aggregates_snapshot
                                       : openpenny::app::aggregate_counters());
        const auto agg_live = openpenny::app::aggregate_counters();
        const auto runtime = openpenny::current_runtime_setup();
        const bool is_passive = pipeline_opts.mode == openpenny::PipelineOptions::Mode::Passive;
        auto agg_status_str = [&]() {
            switch (runtime.aggregates_status) {
                case openpenny::RuntimeStatus::AggregatesStatus::CLOSED_LOOP: return "closed_loop";
                case openpenny::RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP: return "not_closed_loop";
                case openpenny::RuntimeStatus::AggregatesStatus::DUPLICATES_EXCEEDED: return "duplicates_exceeded";
                case openpenny::RuntimeStatus::AggregatesStatus::PENDING:
                default: return "pending";
            }
        }();
        const bool agg_done = result.aggregates_enabled &&
                              runtime.aggregates_status != openpenny::RuntimeStatus::AggregatesStatus::PENDING;
        const std::string sep = "+--------------------------------------------------+\n";
        std::cout << "\n" << sep;
        std::cout << "| Run Summary                                      |\n" << sep;
        std::cout << "| Prefix: " << pipeline_opts.prefix_cidr << "\n";
        if (is_passive) {
            std::cout << "| Packets: processed=" << result.active->packets_processed
                      << " forwarded=" << result.active->packets_forwarded
                      << " errors=" << result.active->forward_errors << "\n";
            std::cout << "|   data=" << result.active->data_packets
                      << " pure_ack=" << result.active->pure_ack_packets
                      << " duplicate=" << result.active->duplicate_packets << "\n";
            std::cout << "|   in_order=" << result.active->in_order_packets
                      << " out_of_order=" << result.active->out_of_order_packets << "\n";
        } else {
            const auto total_monitored_pkts =
                agg_live.droppable_packets + agg_live.pure_ack_packets + agg_live.duplicate_packets;
            std::cout << "| Packets: processed=" << agg_live.packets
                      << " forwarded=" << result.active->packets_forwarded
                      << " errors=" << result.active->forward_errors << "\n";
            std::cout << "|   Total monitored flow packets=" << total_monitored_pkts
                      << " data=" << agg_live.droppable_packets
                      << " pure_ack=" << agg_live.pure_ack_packets
                      << " duplicate=" << agg_live.duplicate_packets << "\n";
            std::cout << "|   in_order=" << agg_live.in_order_packets
                      << " out_of_order=" << agg_live.out_of_order_packets
                      << " retransmitted=" << agg_live.retransmitted_packets
                      << " non_retransmitted=" << agg_live.non_retransmitted_packets
                      << " dropped=" << agg_live.dropped_packets << "\n";
        }
        if (is_passive) {
            std::cout << "| Flows (passive): finished=" << result.active->passive_flows_finished
                      << " open_gaps_flows=" << result.active->passive_flows_with_open_gaps
                      << " open_gaps=" << result.active->passive_open_gaps
                      << " rst=" << result.active->passive_flows_rst
                      << " syn_only=" << result.active->passive_flows_syn_only << "\n";
            for (const auto& g : result.active->passive_gap_summaries) {
                std::cout << "|   " << g << "\n";
            }
        } else {
            auto color_for_status = [&](const std::string& status) {
                if (status == "closed_loop") return "\033[34m";
                if (status == "not_closed_loop") return "\033[31m";
                if (status == "duplicates_exceeded") return "\033[33m";
                return "\033[0m";
            };
            const auto status_color = color_for_status(agg_status_str);
            const std::string status_rendered = (result.aggregates_enabled
                                                     ? (std::string(status_color) + agg_status_str + "\033[0m")
                                                     : "n/a");
            uint64_t agg_data = runtime.aggregate_eval_counters.data_packets;
            uint64_t agg_dup = runtime.aggregate_eval_counters.duplicate_packets;
            uint64_t agg_rtx = runtime.aggregate_eval_counters.retransmitted_packets;
            uint64_t agg_nonrtx = runtime.aggregate_eval_counters.non_retransmitted_packets;
            std::cout << "| Aggregates: " << (result.aggregates_enabled ? "enabled" : "disabled")
                      << " status=" << status_rendered
                      << " snapshots=" << (result.aggregates_enabled ? result.drop_snapshots.size() : 0)
                      << " decision_state=" << (agg_done ? "completed" : "running")
                      << " ";
            if (runtime.has_aggregate_eval) {
                std::cout << "(data=" << agg_data
                          << " dup=" << agg_dup
                          << " rtx=" << agg_rtx
                          << " non_rtx=" << agg_nonrtx << ")";
            } else {
                std::cout << "(eval=n/a)";
            }
            std::cout
                      << "\n";
            std::cout << "| Flows: monitored=" << agg_snapshot.flows_monitored
                      << " finished=" << agg_snapshot.flows_finished
                      << " closed_loop=" << agg_snapshot.flows_closed_loop
                      << " not_closed_loop=" << agg_snapshot.flows_not_closed_loop
                      << " rst=" << agg_snapshot.flows_rst
                      << " dup_exceeded=" << agg_snapshot.flows_duplicates_exceeded << "\n";
        }
        std::cout << sep;

        std::cout << "End state: ";
        auto color_for_status = [&](const std::string& status) {
            if (status == "closed_loop") return "\033[34m";
            if (status == "not_closed_loop") return "\033[31m";
            if (status == "duplicates_exceeded") return "\033[33m";
            return "\033[0m";
        };
        if (!is_passive && agg_done) {
            std::cout << "Aggregates completed (" << color_for_status(agg_status_str) << agg_status_str << "\033[0m)";
        } else if (result.active->penny_completed) {
            if (is_passive) {
                std::cout << "Passive pipeline completed (flows=" << (result.active ? result.active->passive_flows_finished : 0) << ")";
            } else {
                std::cout << "Penny heuristics completed";
            }
        } else if (g_stop_requested != 0) {
            std::cout << "Stopped via signal (Ctrl+C)";
        } else {
            std::cout << "Reader/pipeline error (see logs)";
        }
        std::cout << "\n";
    } else {
        std::cout << "No packets were processed.\n";
    }

    close_tun();
    run_detach_command();
    return 0;
}
