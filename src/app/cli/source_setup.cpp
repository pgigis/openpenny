// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/cli/source_setup.h"

#include <sstream>

namespace openpenny::cli {

void configure_xdp_source(openpenny::Config& cfg, const CliOptions& opts) {
    cfg.dpdk.enable = false;

    cfg.xdp_runtime.enable = true;
    cfg.xdp_runtime.attach_program = true;
    cfg.xdp_runtime.detach_on_close = true;
    cfg.xdp_runtime.update_conf_map = true;
    cfg.xdp_runtime.pin_maps = true;
    cfg.xdp_runtime.reuse_pins = false;
    cfg.xdp_runtime.prefix_host = opts.prefix_host;
    cfg.xdp_runtime.mask_host = opts.mask_host;
    cfg.xdp_runtime.prefix_text = opts.prefix_ip;
    cfg.xdp_runtime.mask_text = opts.prefix_ip; // not used when mask_host already set
    cfg.xdp_runtime.mask_bits = opts.mask_bits;

    if (!opts.iface.empty() && opts.has_prefix) {
        std::ostringstream base;
        base << "/sys/fs/bpf/openpenny_" << opts.iface << "_" << opts.mask_bits;
        cfg.xdp_runtime.pin_conf_path = base.str() + "/conf";
        cfg.xdp_runtime.pin_xsks_path = base.str() + "/xsks";
        cfg.xdp_runtime.pin_stats_path = base.str() + "/stats";
    }
}

void configure_dpdk_source(openpenny::Config& cfg, const CliOptions&) {
    cfg.dpdk.enable = true;

    // Disable XDP-specific actions when using DPDK.
    cfg.xdp_runtime.enable = false;
    cfg.xdp_runtime.attach_program = false;
    cfg.xdp_runtime.detach_on_close = false;
    cfg.xdp_runtime.update_conf_map = false;
    cfg.xdp_runtime.pin_maps = false;
    cfg.xdp_runtime.reuse_pins = false;
}

} // namespace openpenny::cli
