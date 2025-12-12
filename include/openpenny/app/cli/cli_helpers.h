// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/app/core/OpenpennyPipelineDriver.h"

#include <cstdint>
#include <string>

namespace openpenny::cli {

struct CliOptions {
    std::string config_path = "examples/configs/config_default.yaml";
    std::string source = "xdp"; // "xdp" or "dpdk"
    PipelineOptions::Mode mode{PipelineOptions::Mode::Active};
    std::string stats_socket_path;
    std::string prefix_ip;
    std::string prefix_cidr;
    uint32_t prefix_host = 0;
    uint32_t mask_host = 0;
    int mask_bits = 0;
    bool has_prefix = false;
    std::string iface;
    std::string xdp_mode = "auto";
    std::string pin_conf_path;
    std::string pin_xsks_path;
    std::string pin_stats_path;
    std::string tun_name;
    bool forward_to_tun = false;
    bool queue_override = false;
    unsigned queue_value = 0;
    unsigned queue_count = 1;
};

std::string to_lower(std::string value);
CliOptions parse_args(int argc, char** argv);
CliOptions normalize_options(CliOptions opts);

} // namespace openpenny::cli
