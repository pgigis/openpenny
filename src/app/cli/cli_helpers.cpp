// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/cli/cli_helpers.h"

#include <arpa/inet.h>

#include <cctype>
#include <cstdlib>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/stat.h>

namespace openpenny::cli {

std::string to_lower(std::string value) {
    for (auto& ch : value) ch = static_cast<char>(::tolower(static_cast<unsigned char>(ch)));
    return value;
}

namespace {

uint32_t mask_from_bits(int bits) {
    if (bits <= 0) return 0;
    if (bits >= 32) return 0xFFFFFFFFu;
    return 0xFFFFFFFFu << (32 - bits);
}

bool parse_cidr(const std::string& spec,
                std::string& prefix_ip,
                std::string& normalized,
                uint32_t& prefix_host,
                uint32_t& mask_host,
                int& mask_bits) {
    auto slash = spec.find('/');
    const std::string ip = spec.substr(0, slash);
    const std::string mask_str = (slash == std::string::npos) ? "32" : spec.substr(slash + 1);

    in_addr addr{};
    if (inet_pton(AF_INET, ip.c_str(), &addr) != 1) {
        return false;
    }

    char* end = nullptr;
    errno = 0;
    long bits = std::strtol(mask_str.c_str(), &end, 10);
    if (errno != 0 || end == mask_str.c_str() || *end != '\0' || bits < 0 || bits > 32) {
        return false;
    }

    prefix_ip = ip;
    prefix_host = ntohl(addr.s_addr);
    mask_bits = static_cast<int>(bits);
    mask_host = mask_from_bits(mask_bits);
    std::ostringstream oss;
    oss << ip << "/" << bits;
    normalized = oss.str();
    return true;
}

} // namespace

CliOptions parse_args(int argc, char** argv) {
    CliOptions opts;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "--config" || arg == "-c") && i + 1 < argc) {
            opts.config_path = argv[++i];
        } else if (arg == "--source" && i + 1 < argc) {
            opts.source = to_lower(argv[++i]);
            if (opts.source != "xdp" && opts.source != "dpdk") {
                std::cerr << "Invalid --source value: " << opts.source << " (use xdp or dpdk)\n";
                std::exit(1);
            }
            opts.source_set = true;
        } else if ((arg == "--prefix" || arg == "-p") && i + 1 < argc) {
            std::string spec = argv[++i];
            if (!parse_cidr(spec, opts.prefix_ip, opts.prefix_cidr, opts.prefix_host, opts.mask_host, opts.mask_bits)) {
                std::cerr << "Invalid prefix specification (use IP/MASK): " << spec << '\n';
                std::exit(1);
            }
            opts.has_prefix = true;
        } else if ((arg == "--queue" || arg == "-q") && i + 1 < argc) {
            std::string value = argv[++i];
            if (to_lower(value) == "auto") {
                opts.queue_auto = true;
                opts.queue_override = false;
                continue;
            }
            char* end = nullptr;
            errno = 0;
            long q = std::strtol(value.c_str(), &end, 10);
            if (errno != 0 || end == value.c_str() || *end != '\0' || q < 0) {
                std::cerr << "Invalid queue index: " << value << '\n';
                std::exit(1);
            }
            opts.queue_override = true;
            opts.queue_auto = false;
            opts.queue_value = static_cast<unsigned>(q);
        } else if (arg == "--queue-probe-ms" && i + 1 < argc) {
            std::string value = argv[++i];
            char* end = nullptr;
            errno = 0;
            long ms = std::strtol(value.c_str(), &end, 10);
            if (errno != 0 || end == value.c_str() || *end != '\0' || ms <= 0) {
                std::cerr << "Invalid queue probe duration: " << value << '\n';
                std::exit(1);
            }
            opts.queue_probe_ms = static_cast<unsigned>(ms);
        } else if ((arg == "--queues" || arg == "-Q") && i + 1 < argc) {
            std::string value = argv[++i];
            char* end = nullptr;
            errno = 0;
            long n = std::strtol(value.c_str(), &end, 10);
            if (errno != 0 || end == value.c_str() || *end != '\0' || n <= 0) {
                std::cerr << "Invalid queue count: " << value << '\n';
                std::exit(1);
            }
            opts.queue_count = static_cast<unsigned>(n);
            opts.queue_count_set = true;
        } else if (arg == "--iface" && i + 1 < argc) {
            opts.iface = argv[++i];
        } else if (arg == "--xdp-mode" && i + 1 < argc) {
            opts.xdp_mode = to_lower(argv[++i]);
            if (opts.xdp_mode != "auto" && opts.xdp_mode != "drv" && opts.xdp_mode != "generic") {
                std::cerr << "Invalid --xdp-mode value: " << opts.xdp_mode << "\n";
                std::exit(1);
            }
        } else if (arg == "--mode" && i + 1 < argc) {
            std::string m = to_lower(argv[++i]);
            if (m == "active") opts.mode = openpenny::PipelineOptions::Mode::Active;
            else if (m == "passive") opts.mode = openpenny::PipelineOptions::Mode::Passive;
            else {
                std::cerr << "Invalid --mode value: " << m << " (use active|passive)\n";
                std::exit(1);
            }
            opts.mode_set = true;
        } else if (arg == "--stats-sock" && i + 1 < argc) {
            opts.stats_socket_path = argv[++i];
        } else if ((arg == "--tun" || arg == "--tun-name") && i + 1 < argc) {
            opts.tun_name = argv[++i];
            opts.forward_to_tun = true;
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: openpenny_cli [options]\n"
                      << "  -c, --config <path>     Configuration file (default examples/configs/config_default.yaml)\n"
                      << "  --source <xdp|dpdk>     Packet source backend; falls back to the YAML platform if omitted\n"
                      << "  --mode <active|passive> Pipeline mode; falls back to runtime_policy.mode in the YAML if omitted\n"
                      << "  --stats-sock <path>     Unix datagram socket path for live stats (optional)\n"
                      << "  -p, --prefix <CIDR>     Legacy runtime prefix metadata (traffic_match controls capture)\n"
                      << "  --iface <dev>           Override the YAML interface (otherwise platform.interface wins)\n"
                      << "  --xdp-mode <auto|drv|generic>  Attachment mode (default auto)\n"
                      << "  -q, --queue <id|auto>   AF_XDP queue id, or auto-probe the active RX queue\n"
                      << "  --queue-probe-ms <ms>   Probe time per queue when using --queue auto\n"
                      << "  --tun <dev>             Forward matching packets to the named TUN device\n"
                      << "  -Q, --queues <count>    Override platform.queue_count from the YAML (otherwise YAML wins)\n"
                      << "\nWhen a flag is omitted, the corresponding value from --config wins; the\n"
                      << "CLI is for ad-hoc overrides on top of the YAML, not for replacing it.\n"
                      << "\nPolling continues until Penny heuristics finish or you press Ctrl+C.\n";
            std::exit(0);
        }
    }

    if (!opts.has_prefix) {
        // defaults deferred to normalize_options
    }

    return opts;
}

CliOptions normalize_options(CliOptions opts) {
    if (!opts.has_prefix) {
        opts.prefix_ip = "0.0.0.0";
        opts.prefix_cidr = "0.0.0.0/0";
        opts.prefix_host = 0;
        opts.mask_host = 0;
        opts.mask_bits = 0;
    }

    if (!opts.iface.empty()) {
        std::ostringstream base;
        base << "/sys/fs/bpf/openpenny_" << opts.iface;
        opts.pin_conf_path = base.str() + "/conf";
        opts.pin_xsks_path = base.str() + "/xsks";
        opts.pin_stats_path = base.str() + "/stats";
        opts.pin_settings_path = base.str() + "/settings";
    }
    return opts;
}

} // namespace openpenny::cli
