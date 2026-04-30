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
    std::string pin_settings_path;
    // CLI shorthand for TUN egress. When set via `--tun <device>`, the
    // driver populates `cfg->egress` with `{kind=Tun, device=tun_name}`
    // before launching the pipeline. Raw-socket or raw-nic egress are
    // selected declaratively through the YAML `egress:` block instead.
    std::string tun_name;
    bool forward_to_tun = false;
    bool queue_override = false;
    bool queue_auto = false;
    unsigned queue_value = 0;
    unsigned queue_count = 1;
    unsigned queue_probe_ms = 250;

    // ------------------------------------------------------------------
    // "Was this set on the command line?" flags.
    //
    // Several of the fields above carry a sensible default (e.g. mode =
    // Active, queue_count = 1, source = "xdp"). Without these flags we
    // cannot distinguish "operator typed --mode active" from "operator
    // typed nothing and we left the default", which means a YAML file
    // saying `mode: passive` would be silently overwritten by the
    // baked-in CLI default. Any code path that copies a CLI value into
    // the loaded Config should branch on the matching `*_set` flag and
    // leave the YAML value alone when it is false.
    // ------------------------------------------------------------------
    bool mode_set = false;          ///< true if --mode was supplied.
    bool source_set = false;        ///< true if --source was supplied.
    bool queue_count_set = false;   ///< true if --queues was supplied.
};

std::string to_lower(std::string value);
CliOptions parse_args(int argc, char** argv);
CliOptions normalize_options(CliOptions opts);

} // namespace openpenny::cli
