// SPDX-License-Identifier: BSD-2-Clause

// Pipeline driver that wires together the reader, matcher, forwarding, and
// Penny logic on one or more worker threads.
#include "openpenny/app/core/OpenpennyPipelineDriver.h"

// Declarative egress configuration consumed by the pipeline driver.
#include "openpenny/egress/PacketSink.h"

// Configuration loader and config object.
#include "openpenny/config/Config.h"

// Dataplane factory used to create AF_XDP or DPDK sessions.
#include "openpenny/dataplane/Factory.h"

// Logging infrastructure.
#include "openpenny/log/Log.h"

// CLI parsing/normalisation helpers.
#include "openpenny/app/cli/cli_helpers.h"

// Source-specific setup helpers for AF_XDP / DPDK.
#include "openpenny/app/cli/source_setup.h"

// Per-thread counters and counter aggregation helpers.
#include "openpenny/app/core/PerThreadStats.h"

// Traffic match policy describer used by the run-summary printout.
#include "openpenny/net/TrafficMatch.h"

#include <atomic>
#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <system_error>
#include <sys/wait.h>
#include <unistd.h>
#include <thread>
#include <chrono>

namespace {

// Tracks whether this process initiated an XDP attachment and therefore
// needs to detach it on shutdown.
//
// This is useful because the program may exit via:
// - normal return
// - signal
// - early error path
//
// If attachment was initiated by this process, we want a symmetrical detach.
struct AttachState {
    bool active{false};      // true if this process attached an XDP program
    std::string iface;       // interface where attach happened
    std::string mode;        // attach mode, e.g. native/generic/offload
};

// Global attach state.
AttachState g_attach_state;

// Signal-safe stop flag.
// Only simple operations should happen in a signal handler, so we just set this.
volatile sig_atomic_t g_stop_requested = 0;

// ---------------------------------------------------------------------------
// Summary formatting helpers
//
// The CLI summary is printed after the pipeline finishes. These helpers keep
// the formatting code compact: thousand-separated numbers, right-aligned
// value columns, simple section rules, and a consistent layout for both
// active and passive modes.
// ---------------------------------------------------------------------------

// Detect whether stdout is a terminal. Disables ANSI colour codes when the
// output is being piped to a file or another process so grep/awk stay clean.
bool stdout_is_tty() {
    static const bool tty = ::isatty(fileno(stdout)) != 0;
    return tty;
}

constexpr const char* kAnsiReset  = "\033[0m";
constexpr const char* kAnsiBold   = "\033[1m";
constexpr const char* kAnsiDim    = "\033[2m";
constexpr const char* kAnsiRed    = "\033[31m";
constexpr const char* kAnsiGreen  = "\033[32m";
constexpr const char* kAnsiYellow = "\033[33m";
constexpr const char* kAnsiBlue   = "\033[34m";

const char* ansi(const char* code) {
    return stdout_is_tty() ? code : "";
}

// Format a non-negative integer with thousand separators (locale-independent).
// Example: 1234567 -> "1,234,567". Keeps counter output scannable.
std::string fmt_count(std::uint64_t n) {
    std::string s = std::to_string(n);
    for (std::ptrdiff_t i = static_cast<std::ptrdiff_t>(s.size()) - 3; i > 0; i -= 3) {
        s.insert(static_cast<std::size_t>(i), ",");
    }
    return s;
}

// Print a section header:
//
//   Packets
//   -------
void print_section(std::ostream& out, const std::string& title) {
    out << "\n"
        << ansi(kAnsiBold) << title << ansi(kAnsiReset) << "\n"
        << std::string(title.size(), '-') << "\n";
}

// Print an aligned key/value row inside a section. Values are right-aligned
// in a fixed-width column so numeric counters line up cleanly regardless of
// label length.
constexpr int kLabelColumn = 22;
constexpr int kValueColumn = 16;

void print_row(std::ostream& out,
               const std::string& label,
               const std::string& value,
               int indent = 2,
               const char* value_color = nullptr) {
    out << std::string(static_cast<std::size_t>(indent), ' ')
        << std::left << std::setw(kLabelColumn - indent) << label
        << ansi(value_color ? value_color : "")
        << std::right << std::setw(kValueColumn) << value
        << ansi(value_color ? kAnsiReset : "")
        << "\n";
}

void print_count_row(std::ostream& out,
                     const std::string& label,
                     std::uint64_t value,
                     int indent = 2) {
    print_row(out, label, fmt_count(value), indent);
}

// Colour-code the aggregate decision status so operators can spot final
// state at a glance without parsing the label themselves.
const char* color_for_agg_status(const std::string& status) {
    if (status == "closed_loop")         return kAnsiBlue;
    if (status == "not_closed_loop")     return kAnsiRed;
    if (status == "duplicates_exceeded") return kAnsiYellow;
    return "";
}

// Render a human-friendly duration: "12.3s", "2m 04s", "1h 03m".
std::string fmt_duration(double seconds) {
    std::ostringstream oss;
    if (seconds < 60.0) {
        oss << std::fixed << std::setprecision(1) << seconds << "s";
    } else if (seconds < 3600.0) {
        const int m = static_cast<int>(seconds) / 60;
        const int s = static_cast<int>(seconds) % 60;
        oss << m << "m " << std::setw(2) << std::setfill('0') << s << "s";
    } else {
        const int h = static_cast<int>(seconds) / 3600;
        const int m = (static_cast<int>(seconds) % 3600) / 60;
        oss << h << "h " << std::setw(2) << std::setfill('0') << m << "m";
    }
    return oss.str();
}

// Render the queue range as "0" or "0-3" so the Run section stays compact.
std::string fmt_queue_range(unsigned base, unsigned count) {
    if (count <= 1) return std::to_string(base);
    std::ostringstream oss;
    oss << base << "-" << (base + count - 1);
    return oss.str();
}

// Returns the absolute path to the helper script used to attach/detach XDP.
//
// Using an absolute path avoids confusion if the working directory changes.
std::string attach_script_path() {
    static const std::string path =
        std::filesystem::absolute("scripts/xdp_attach.py").string();
    return path;
}

// If this process attached an XDP program, detach it using the same helper script.
//
// This function is intentionally tolerant:
// - if no attach happened, it does nothing
// - if interface is empty, it does nothing
//
// Cleanup should never crash the process during shutdown.
void run_detach_command() {
    if (!g_attach_state.active || g_attach_state.iface.empty()) {
        return;
    }

    std::ostringstream cmd;
    cmd << "python3 " << attach_script_path()
        << " --iface " << g_attach_state.iface
        << " --mode " << g_attach_state.mode
        << " --detach";

    std::system(cmd.str().c_str());
    g_attach_state.active = false;
}

// Signal handler for SIGINT / SIGTERM.
//
// Important rule: do not do heavy work here.
// We only record the stop request and let the main pipeline poll the flag.
void handle_signal(int sig) {
    g_stop_requested = 1;

    // Reinstall the handler for portability/robustness.
    std::signal(sig, handle_signal);
}

// Register signal handlers so Ctrl+C and SIGTERM trigger a graceful stop.
void install_signal_handlers() {
    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
}

// Ensure that the XDP object file exists and is reasonably up to date.
//
// This helper:
// 1. checks whether the compiled object exists
// 2. if it exists, compares timestamps against the source and Makefile
// 3. rebuilds if needed
//
// Returns true if the object exists and is ready to use.
bool ensure_xdp_object(const std::filesystem::path& bpf_obj) {
    const auto xdp_dir  = bpf_obj.parent_path();
    const auto source   = xdp_dir / "xdp_redirect_openpenny.c";
    const auto makefile = xdp_dir / "Makefile";

    std::error_code ec;
    const bool object_exists = std::filesystem::exists(bpf_obj, ec);

    // Rebuild if object is missing.
    bool needs_build = !object_exists;

    if (object_exists) {
        const auto obj_time = std::filesystem::last_write_time(bpf_obj, ec);

        // Rebuild if source is newer than object.
        if (!ec && std::filesystem::exists(source, ec)) {
            const auto source_time = std::filesystem::last_write_time(source, ec);
            needs_build = !ec && source_time > obj_time;
        }

        // Rebuild if Makefile is newer than object.
        if (!needs_build && !ec && std::filesystem::exists(makefile, ec)) {
            const auto makefile_time = std::filesystem::last_write_time(makefile, ec);
            needs_build = !ec && makefile_time > obj_time;
        }
    }

    // Nothing to do.
    if (!needs_build) {
        return true;
    }

    std::cout
        << "[openpenny] building XDP program "
        << "(make -C ebpf/af_xdp xdp_redirect_openpenny.o)\n";

    int rc = std::system("make -C ebpf/af_xdp xdp_redirect_openpenny.o");
    if (rc != 0) {
        std::cerr
            << "[openpenny] failed to build xdp_redirect_openpenny.o (rc="
            << rc << ")\n";
        return false;
    }

    // Double-check that the expected file really exists after the build.
    if (!std::filesystem::exists(bpf_obj)) {
        std::cerr
            << "[openpenny] build completed but "
            << "ebpf/af_xdp/xdp_redirect_openpenny.o is still missing\n";
        return false;
    }

    return true;
}

// Convert a host-order IPv4 address to dotted-quad string.
//
// Example:
//   0xC0000201 -> "192.0.2.1"
//
// This is a helper for logging/debugging.
std::string host_to_string(uint32_t host) {
    std::ostringstream out;
    out << ((host >> 24) & 0xff) << '.'
        << ((host >> 16) & 0xff) << '.'
        << ((host >> 8)  & 0xff) << '.'
        << (host & 0xff);
    return out.str();
}

// Note: the TUN-opening helper used to live here and in penny_worker.cpp.
// Both copies have been replaced by openpenny::egress::TunSink, which is
// built from an EgressConfig and owns the fd internally. The canonical
// implementation always brings the interface administratively UP; the
// worker copy used to skip that step, which silently black-holed every
// forwarded packet because the TUN was DOWN.

// Discover how many RX queues a NIC exposes by looking under:
//
//   /sys/class/net/<ifname>/queues
//
// Returns:
// - number of RX queues if discovered
// - nullopt if discovery fails
std::optional<unsigned> detect_rx_queue_count(const std::string& ifname) {
    namespace fs = std::filesystem;

    const fs::path queues_dir =
        fs::path("/sys/class/net") / ifname / "queues";

    std::error_code ec;
    if (!fs::exists(queues_dir, ec)) {
        return std::nullopt;
    }

    unsigned count = 0;
    for (const auto& entry : fs::directory_iterator(queues_dir, ec)) {
        if (ec) {
            break;
        }

        const auto name = entry.path().filename().string();
        if (name.rfind("rx-", 0) == 0) {
            ++count;
        }
    }

    if (ec || count == 0) {
        return std::nullopt;
    }

    return count;
}

// Probe all RX queues and select the first queue that receives traffic matching
// the current policy.
//
// Why is this useful for AF_XDP?
// - AF_XDP sockets are queue-specific.
// - If the interesting flow lands on queue 3 and we listen on queue 0,
//   we may see nothing.
// - This helper opens each queue briefly and checks whether packets arrive.
//
// Returns:
// - selected queue id
// - nullopt if none matched or probing failed/interrupted
std::optional<unsigned> auto_select_xdp_queue(openpenny::Config& cfg,
                                              const std::string& ifname,
                                              unsigned probe_ms) {
    const auto rx_queue_count = detect_rx_queue_count(ifname);
    if (!rx_queue_count) {
        std::cerr
            << "[openpenny] failed to discover RX queues for " << ifname
            << " under /sys/class/net/" << ifname << "/queues\n";
        return std::nullopt;
    }

    std::cout
        << "[openpenny] probing " << *rx_queue_count
        << " RX queues on " << ifname
        << " (" << probe_ms << " ms per queue) using the current traffic policy\n";

    for (unsigned queue = 0; queue < *rx_queue_count; ++queue) {
        if (g_stop_requested != 0) {
            std::cout << "[openpenny] queue probe interrupted\n";
            return std::nullopt;
        }

        // Clone current config and override the queue for probing.
        openpenny::Config probe_cfg = cfg;
        probe_cfg.queue = queue;

        // Use a short poll timeout during probing so the scan stays responsive.
        probe_cfg.xdp_runtime.poll_timeout_ms = std::min<unsigned>(probe_ms, 50u);

        auto session = openpenny::dataplane::create_session(probe_cfg);
        if (!session) {
            std::cerr
                << "[openpenny] failed to create dataplane session while probing queue "
                << queue << "\n";
            return std::nullopt;
        }

        if (!session->open(ifname, queue)) {
            std::cout
                << "[openpenny] queue probe q" << queue
                << ": open failed\n";
            continue;
        }

        std::size_t packets = 0;
        const auto deadline =
            std::chrono::steady_clock::now() + std::chrono::milliseconds(probe_ms);

        // Poll until:
        // - stopped
        // - deadline reached
        // - first packet observed
        while (g_stop_requested == 0 &&
               std::chrono::steady_clock::now() < deadline &&
               packets == 0) {
            if (!session->poll([&](const openpenny::net::PacketView&) {
                    ++packets;
                }, 64)) {
                break;
            }
        }

        session->close();

        if (g_stop_requested != 0) {
            std::cout << "[openpenny] queue probe interrupted\n";
            return std::nullopt;
        }

        if (packets > 0) {
            std::cout
                << "[openpenny] queue probe q" << queue
                << ": matched " << packets
                << " packet(s); selecting this queue\n";
            return queue;
        }

        std::cout
            << "[openpenny] queue probe q" << queue
            << ": no matched packets\n";
    }

    return std::nullopt;
}

} // namespace

int main(int argc, char** argv) {
    // Parse CLI arguments and normalise them into a consistent internal form.
    auto cli_opts =
        openpenny::cli::normalize_options(
            openpenny::cli::parse_args(argc, argv));

    // Install SIGINT/SIGTERM handlers so Ctrl+C becomes a graceful stop request.
    install_signal_handlers();

    // Fork into:
    // - parent: supervisor/waiter
    // - child: actual pipeline runner
    //
    // This gives the parent a simple role: wait for child and forward signals.
    pid_t pid = ::fork();
    if (pid < 0) {
        std::cerr << "Failed to fork: " << std::strerror(errno) << "\n";
        return 1;
    }

    // Parent process.
    if (pid > 0) {
        while (true) {
            int status = 0;
            pid_t rc = ::waitpid(pid, &status, 0);

            if (rc == pid) {
                if (WIFEXITED(status)) {
                    return WEXITSTATUS(status);
                }
                if (WIFSIGNALED(status)) {
                    return 128 + WTERMSIG(status);
                }
                return 1;
            }

            // If wait was interrupted by a signal, forward SIGINT to the child
            // if the user requested stop.
            if (rc < 0 && errno == EINTR) {
                if (g_stop_requested != 0) {
                    (void)::kill(pid, SIGINT);
                }
                continue;
            }

            return 1;
        }
    }

    // Child process from here onward. The egress sink (if any) is built
    // from the declarative cfg->egress once the config is loaded; its fd
    // lifecycle is owned by the PacketSink, so the old local `tun_fd`
    // bookkeeping is gone.

    // Load configuration file.
    auto cfg = openpenny::Config::from_file(cli_opts.config_path);
    if (!cfg) {
        std::cerr
            << "Failed to load config: " << cli_opts.config_path << '\n';
        run_detach_command();
        return 1;
    }

    // Determine source backend.
    const bool use_xdp  = openpenny::cli::to_lower(cli_opts.source) == "xdp";
    const bool use_dpdk = openpenny::cli::to_lower(cli_opts.source) == "dpdk";

    // Queue auto-probe only makes sense for AF_XDP.
    if (cli_opts.queue_auto && !use_xdp) {
        std::cerr
            << "[openpenny] --queue auto is currently supported only for the AF_XDP backend\n";
        return 1;
    }

    // Auto-probing is only defined for one queue, not multi-queue fan-out.
    if (cli_opts.queue_auto && cli_opts.queue_count > 1) {
        std::cerr
            << "[openpenny] use --queues <count> for AF_XDP queue fan-out; "
            << "--queue auto is only for single-queue discovery\n";
        return 1;
    }

    // CLI interface override takes precedence over config file.
    if (!cli_opts.iface.empty()) {
        cfg->ifname = cli_opts.iface;
    }

    // CLI queue override also takes precedence.
    if (cli_opts.queue_override) {
        cfg->queue = cli_opts.queue_value;
    }

    // Number of queues to process in this run.
    cfg->queue_count = std::max(1u, cli_opts.queue_count);

    // For AF_XDP, sanity-check the requested queue range against the NIC's
    // actual RX queue count. Two failure modes are surfaced explicitly here
    // because they otherwise show up only as "processed=0" with nothing in
    // the logs to point at the cause:
    //   (a) queue_count exceeds the NIC's RX queues — workers on the
    //       non-existent tail queues will fail xsk_socket__create() with
    //       -ENOENT. We clamp and warn.
    //   (b) queue_count is a strict subset of the NIC's RX queues — RSS
    //       can route matched traffic to queues we don't serve, and those
    //       packets will pass to the kernel without OpenPenny seeing them.
    if (use_xdp) {
        if (auto detected_rx_queues = detect_rx_queue_count(cfg->ifname)) {
            const unsigned first_queue = cfg->queue;
            const unsigned last_queue  = cfg->queue + cfg->queue_count - 1;

            if (last_queue >= *detected_rx_queues) {
                const unsigned new_count =
                    *detected_rx_queues > cfg->queue
                        ? *detected_rx_queues - cfg->queue
                        : 1u;
                std::cerr
                    << "[openpenny] warning: requested queues "
                    << first_queue << "-" << last_queue << " exceed "
                    << cfg->ifname << "'s RX queue count ("
                    << *detected_rx_queues << "). Clamping queue_count to "
                    << new_count << " to avoid AF_XDP socket failures on "
                    << "non-existent queues.\n";
                cli_opts.queue_count = new_count;
                cfg->queue_count = new_count;
            } else if (!cli_opts.queue_auto &&
                       (first_queue != 0 || last_queue + 1 < *detected_rx_queues)) {
                std::cerr
                    << "[openpenny] warning: " << cfg->ifname
                    << " exposes " << *detected_rx_queues
                    << " RX queues, but this run is bound to queues "
                    << first_queue << "-" << last_queue << ". "
                    << "Matched traffic that lands on other RX queues will pass "
                    << "to the kernel and will not be processed by AF_XDP.\n";
            }
        }

        // Stale pin detection. /sys/fs/bpf/openpenny_* survives a crash or
        // a kill -9 of a previous run. With reuse_pins=false (the default)
        // they are not actually used, but they can confuse a fresh attach
        // because bpf_obj_pin will fail with -EEXIST when this run tries
        // to pin its own maps under the same paths. Surface a clear hint
        // before the failure rather than after.
        const std::string* pin_paths[] = {
            &cfg->xdp_runtime.pin_conf_path,
            &cfg->xdp_runtime.pin_xsks_path,
            &cfg->xdp_runtime.pin_stats_path,
            &cfg->xdp_runtime.pin_settings_path,
        };
        bool any_stale = false;
        for (const auto* p : pin_paths) {
            std::error_code pec;
            if (p && !p->empty() &&
                std::filesystem::exists(*p, pec) && !pec) {
                any_stale = true;
                break;
            }
        }
        if (any_stale && !cfg->xdp_runtime.reuse_pins) {
            std::cerr
                << "[openpenny] note: pre-existing BPF pins detected under "
                << "/sys/fs/bpf/openpenny_*. If attach fails or no packets "
                << "are received, clean up the previous run first:\n"
                << "    sudo python3 scripts/xdp_attach.py --iface "
                << cfg->ifname << " --mode drv --detach\n"
                << "    sudo rm -rf /sys/fs/bpf/openpenny*\n";
        }
    }

    // If AF_XDP is selected, make sure the XDP BPF object exists.
    std::filesystem::path bpf_obj =
        std::filesystem::absolute("ebpf/af_xdp/xdp_redirect_openpenny.o");

    if (use_xdp) {
        if (ensure_xdp_object(bpf_obj)) {
            cfg->xdp_runtime.bpf_object = bpf_obj.string();
        } else {
            std::cerr
                << "[openpenny] warning: continuing without a built XDP object; "
                << "build manually if attach fails\n";
        }
    }

    // Optional override of pinned BPF map paths.
    // Useful when users want explicit pin locations.
    if (!cli_opts.pin_conf_path.empty()) {
        cfg->xdp_runtime.pin_conf_path     = cli_opts.pin_conf_path;
        cfg->xdp_runtime.pin_xsks_path     = cli_opts.pin_xsks_path;
        cfg->xdp_runtime.pin_stats_path    = cli_opts.pin_stats_path;
        cfg->xdp_runtime.pin_settings_path = cli_opts.pin_settings_path;
    }

    // Prepare per-thread counters.
    openpenny::app::init_thread_counters(std::max(1u, cli_opts.queue_count));
    openpenny::app::set_thread_counter_index(0);

    // Small helper thread for periodically checking aggregate counters.
    // Currently this looks like a hook point for future reporting/export.
    std::atomic<bool> agg_stop{false};
    std::atomic<uint64_t> agg_drop_threshold{12};

    std::thread agg_thread([&agg_stop, &agg_drop_threshold] {
        uint64_t last_agg_drops = 0;

        while (!agg_stop.load(std::memory_order_relaxed)) {
            auto agg = openpenny::app::aggregate_counters();

            if (agg.dropped_packets >= agg_drop_threshold.load(std::memory_order_relaxed) &&
                agg.dropped_packets != last_agg_drops) {
                // This is a placeholder where aggregated counters could be:
                // - logged
                // - exported to a socket
                // - sent to telemetry
                last_agg_drops = agg.dropped_packets;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });

    // Apply source-specific setup to the config.
    if (use_xdp) {
        openpenny::cli::configure_xdp_source(*cfg, cli_opts);
    } else if (use_dpdk) {
        openpenny::cli::configure_dpdk_source(*cfg, cli_opts);
    }

    // Local helper to initialise the logger from config strings.
    auto init_logger_from_cfg = [](const openpenny::Config& config) {
        openpenny::LoggerConfig lc;

        const auto mode = openpenny::cli::to_lower(config.log_mode);
        if (mode == "console") {
            lc.mode = openpenny::LogMode::Console;
        } else if (mode == "file") {
            lc.mode = openpenny::LogMode::File;
        } else {
            lc.mode = openpenny::LogMode::Silent;
        }

        lc.file_path = config.log_file;

        const auto lvl = openpenny::cli::to_lower(config.log_level);
        if (lvl == "trace") {
            lc.level = openpenny::LogLevel::TRACE;
        } else if (lvl == "debug") {
            lc.level = openpenny::LogLevel::DEBUG;
        } else if (lvl == "warn") {
            lc.level = openpenny::LogLevel::WARN;
        } else if (lvl == "error") {
            lc.level = openpenny::LogLevel::ERROR;
        } else {
            lc.level = openpenny::LogLevel::INFO;
        }

        openpenny::Logger::set_level(lc.level);
        openpenny::Logger::init(lc);
    };

    init_logger_from_cfg(*cfg);

    // If requested, probe all RX queues and pick the first queue where matching
    // traffic is observed.
    if (use_xdp && cli_opts.queue_auto) {
        auto selected_queue =
            auto_select_xdp_queue(*cfg, cfg->ifname, cli_opts.queue_probe_ms);

        if (!selected_queue) {
            if (g_stop_requested != 0) {
                return 130;
            }

            std::cerr
                << "[openpenny] queue auto-probe found no matching traffic. "
                << "Check that the flow matches the policy and is active during the probe.\n";
            return 1;
        }

        cfg->queue = *selected_queue;
    }

    // Configure the egress sink declaratively on the config. --tun/--tun-name
    // on the CLI is treated as a shorthand for "TUN egress targeting this
    // device"; the pipeline driver will open the sink (via TunSink) and
    // share it across all worker threads. Whatever the YAML already held in
    // `egress:` is only overridden when the CLI opted in explicitly, so
    // runs driven purely from YAML still work.
    if (cli_opts.forward_to_tun) {
        cfg->egress.kind = openpenny::egress::EgressKind::Tun;
        cfg->egress.device = cli_opts.tun_name;
        // Leave tun_mtu / tun_multi_queue / tun_txqlen at their YAML /
        // EgressConfig defaults unless the operator overrides them via
        // the YAML egress block.
    }

    // Build the pipeline options that will be passed to the threaded driver.
    openpenny::PipelineOptions pipeline_opts;

    pipeline_opts.traffic_match = cfg->traffic_match;

    // The pipeline polls this callback to decide when to stop.
    pipeline_opts.should_stop = [] {
        return g_stop_requested != 0;
    };

    pipeline_opts.mode              = cli_opts.mode;
    pipeline_opts.stats_socket_path = cli_opts.stats_socket_path;
    pipeline_opts.queue_count       = std::max(1u, cli_opts.queue_count);

    // User-facing status message before starting the processing pipeline.
    std::cout << "Polling packets on " << cfg->ifname
              << " queue " << cfg->queue;

    if (pipeline_opts.queue_count > 1) {
        std::cout << "-"
                  << (cfg->queue + pipeline_opts.queue_count - 1);
    }

    std::cout
        << " (count=" << pipeline_opts.queue_count
        << ", Ctrl+C to stop, or wait for Penny to finish)..."
        << std::endl;

    // Start the actual threaded pipeline.
    //
    // This is where the heavy lifting happens:
    // - open the dataplane reader
    // - run the pipeline
    // - process packets
    // - produce summaries/results
    const auto run_started = std::chrono::steady_clock::now();
    auto result = openpenny::drive_pipeline_threaded(*cfg, pipeline_opts);
    const auto run_finished = std::chrono::steady_clock::now();
    const double run_duration_seconds =
        std::chrono::duration<double>(run_finished - run_started).count();

    // Stop and join the aggregate helper thread now that the pipeline is done.
    agg_stop.store(true, std::memory_order_relaxed);
    if (agg_thread.joinable()) {
        agg_thread.join();
    }

    // If the pipeline produced a result, print a structured summary.
    //
    // Layout (both modes share this skeleton; only the rows differ):
    //
    //   Run
    //   ---
    //     Mode                passive
    //     Prefix              192.168.41.0/24
    //     Interface           ens5f0np0 q0
    //     Workers                        1
    //     Duration                   12.3s
    //
    //   Packets
    //   -------
    //     processed              1,234,567
    //     ...
    //
    //   Flows
    //   -----
    //     ...
    //
    //   End state: Passive pipeline completed (flows=42)
    if (result.active) {
        const auto agg_snapshot =
            (result.active->aggregates_snapshot
                ? *result.active->aggregates_snapshot
                : openpenny::app::aggregate_counters());

        const auto agg_live = openpenny::app::aggregate_counters();
        const auto runtime  = openpenny::current_runtime_setup();

        const bool is_passive =
            pipeline_opts.mode == openpenny::PipelineOptions::Mode::Passive;

        // Convert aggregate status enum into a readable string.
        const std::string agg_status_str = [&]() -> std::string {
            switch (runtime.aggregates_status) {
                case openpenny::RuntimeStatus::AggregatesStatus::CLOSED_LOOP:
                    return "closed_loop";
                case openpenny::RuntimeStatus::AggregatesStatus::NON_CLOSED_LOOP:
                    return "not_closed_loop";
                case openpenny::RuntimeStatus::AggregatesStatus::DUPLICATES_EXCEEDED:
                    return "duplicates_exceeded";
                case openpenny::RuntimeStatus::AggregatesStatus::PENDING:
                default:
                    return "pending";
            }
        }();

        const bool agg_done =
            result.aggregates_enabled &&
            runtime.aggregates_status !=
                openpenny::RuntimeStatus::AggregatesStatus::PENDING;

        // --- Run ---------------------------------------------------------
        print_section(std::cout, "Run");
        print_row(std::cout, "Mode", is_passive ? "passive" : "active");
        // Show the actual traffic-match policy that was loaded into the
        // pipeline rather than the legacy --prefix CLI flag, since the rule
        // set fully describes which packets are selected (the legacy
        // prefix is only one of several inputs that contribute to it).
        print_row(std::cout, "Policy",
                  openpenny::net::describe_traffic_match(cfg->traffic_match));
        {
            std::ostringstream iface;
            iface << cfg->ifname << " q"
                  << fmt_queue_range(cfg->queue, pipeline_opts.queue_count);
            print_row(std::cout, "Interface", iface.str());
        }
        print_count_row(std::cout, "Workers", pipeline_opts.queue_count);
        print_row(std::cout, "Duration", fmt_duration(run_duration_seconds));

        // --- Packets -----------------------------------------------------
        print_section(std::cout, "Packets");
        if (is_passive) {
            print_count_row(std::cout, "processed",
                            result.active->packets_processed);
            print_count_row(std::cout, "forwarded",
                            result.active->packets_forwarded);
            print_count_row(std::cout, "errors",
                            result.active->forward_errors);
            print_count_row(std::cout, "data",
                            result.active->data_packets, 4);
            print_count_row(std::cout, "pure_ack",
                            result.active->pure_ack_packets, 4);
            print_count_row(std::cout, "duplicate",
                            result.active->duplicate_packets, 4);
            print_count_row(std::cout, "in_order",
                            result.active->in_order_packets, 4);
            print_count_row(std::cout, "out_of_order",
                            result.active->out_of_order_packets, 4);
        } else {
            // Active mode uses aggregate counters which cover all worker
            // threads; packets_forwarded / forward_errors stay on the
            // per-result struct.
            const auto total_monitored_pkts =
                agg_live.droppable_packets +
                agg_live.pure_ack_packets +
                agg_live.duplicate_packets;

            print_count_row(std::cout, "processed",         agg_live.packets);
            print_count_row(std::cout, "forwarded",
                            result.active->packets_forwarded);
            print_count_row(std::cout, "errors",
                            result.active->forward_errors);
            print_count_row(std::cout, "monitored",         total_monitored_pkts, 4);
            print_count_row(std::cout, "data",              agg_live.droppable_packets, 4);
            print_count_row(std::cout, "pure_ack",          agg_live.pure_ack_packets, 4);
            print_count_row(std::cout, "duplicate",         agg_live.duplicate_packets, 4);
            print_count_row(std::cout, "in_order",          agg_live.in_order_packets, 4);
            print_count_row(std::cout, "out_of_order",      agg_live.out_of_order_packets, 4);
            print_count_row(std::cout, "retransmitted",     agg_live.retransmitted_packets, 4);
            print_count_row(std::cout, "non_retransmitted", agg_live.non_retransmitted_packets, 4);
            print_count_row(std::cout, "dropped",           agg_live.dropped_packets, 4);
        }

        // --- Aggregates (active only) -----------------------------------
        if (!is_passive) {
            print_section(std::cout, "Aggregates");
            print_row(std::cout, "enabled",
                      result.aggregates_enabled ? "yes" : "no");

            // Status row is the one place colour earns its keep: a glance
            // at blue/red/yellow is faster than reading the label.
            const char* status_color =
                result.aggregates_enabled
                    ? color_for_agg_status(agg_status_str)
                    : "";
            print_row(std::cout,
                      "status",
                      result.aggregates_enabled ? agg_status_str : "n/a",
                      /*indent=*/2,
                      status_color);

            print_count_row(std::cout, "snapshots",
                            result.aggregates_enabled
                                ? result.drop_snapshots.size()
                                : 0);
            print_row(std::cout, "decision",
                      agg_done ? "completed" : "running");

            if (runtime.has_aggregate_eval) {
                print_count_row(std::cout, "eval data",
                                runtime.aggregate_eval_counters.data_packets, 4);
                print_count_row(std::cout, "eval dup",
                                runtime.aggregate_eval_counters.duplicate_packets, 4);
                print_count_row(std::cout, "eval rtx",
                                runtime.aggregate_eval_counters.retransmitted_packets, 4);
                print_count_row(std::cout, "eval non_rtx",
                                runtime.aggregate_eval_counters.non_retransmitted_packets, 4);
            }
        }

        // --- Flows -------------------------------------------------------
        print_section(std::cout, "Flows");
        if (is_passive) {
            print_count_row(std::cout, "finished",
                            result.active->passive_flows_finished);
            print_count_row(std::cout, "with_open_gaps",
                            result.active->passive_flows_with_open_gaps);
            print_count_row(std::cout, "open_gaps",
                            result.active->passive_open_gaps);
            print_count_row(std::cout, "rst",
                            result.active->passive_flows_rst);
            print_count_row(std::cout, "syn_only",
                            result.active->passive_flows_syn_only);
        } else {
            print_count_row(std::cout, "monitored",
                            agg_snapshot.flows_monitored);
            print_count_row(std::cout, "finished",
                            agg_snapshot.flows_finished);
            print_count_row(std::cout, "closed_loop",
                            agg_snapshot.flows_closed_loop);
            print_count_row(std::cout, "not_closed_loop",
                            agg_snapshot.flows_not_closed_loop);
            print_count_row(std::cout, "rst",
                            agg_snapshot.flows_rst);
            print_count_row(std::cout, "dup_exceeded",
                            agg_snapshot.flows_duplicates_exceeded);
        }

        // --- Per-flow detail (passive only, if any) ----------------------
        if (is_passive && !result.active->passive_gap_summaries.empty()) {
            print_section(std::cout, "Per-flow detail");
            for (const auto& g : result.active->passive_gap_summaries) {
                std::cout << "  " << g << "\n";
            }
        }

        // --- End state ---------------------------------------------------
        std::ostringstream end_state;
        const char* end_color = "";
        if (!is_passive && agg_done) {
            end_state << "Aggregates completed (" << agg_status_str << ")";
            end_color = color_for_agg_status(agg_status_str);
        } else if (result.active->penny_completed) {
            if (is_passive) {
                end_state << "Passive pipeline completed (flows="
                          << result.active->passive_flows_finished << ")";
                end_color = kAnsiGreen;
            } else {
                end_state << "Penny heuristics completed";
                end_color = kAnsiGreen;
            }
        } else if (g_stop_requested != 0) {
            end_state << "Stopped via signal (Ctrl+C)";
            end_color = kAnsiYellow;
        } else {
            end_state << "Reader/pipeline error (see logs)";
            end_color = kAnsiRed;
        }

        std::cout << "\n"
                  << ansi(kAnsiBold) << "End state:" << ansi(kAnsiReset) << " "
                  << ansi(end_color) << end_state.str() << ansi(kAnsiReset)
                  << "\n";
    } else {
        // No active result usually means no packets were processed or the
        // pipeline did not reach a meaningful execution state.
        std::cout << "\n"
                  << ansi(kAnsiBold) << "End state:" << ansi(kAnsiReset) << " "
                  << ansi(kAnsiYellow)
                  << "No packets were processed."
                  << ansi(kAnsiReset) << "\n";
    }

    // Cleanup. The egress PacketSink (if any) was destroyed when
    // drive_pipeline_threaded returned, which closed its fd and left any
    // TUN device it opened in place for observers. No explicit cleanup
    // of the forwarding fd is needed here any more.
    run_detach_command();
    return 0;
}