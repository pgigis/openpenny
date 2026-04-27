// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/cli/source_setup.h"

#include <sstream>

namespace openpenny::cli {

void configure_xdp_source(openpenny::Config& cfg, const CliOptions& opts) {
    cfg.input.backend = openpenny::PacketInputBackend::XdpAfXdp;

    cfg.xdp_runtime.enable = true;
    cfg.xdp_runtime.attach_program = true;
    cfg.xdp_runtime.detach_on_close = true;
    cfg.xdp_runtime.update_conf_map = true;
    cfg.xdp_runtime.pin_maps = true;
    cfg.xdp_runtime.reuse_pins = false;

    if (!opts.iface.empty()) {
        std::ostringstream base;
        base << "/sys/fs/bpf/openpenny_" << opts.iface;
        cfg.xdp_runtime.pin_conf_path = base.str() + "/conf";
        cfg.xdp_runtime.pin_xsks_path = base.str() + "/xsks";
        cfg.xdp_runtime.pin_stats_path = base.str() + "/stats";
        cfg.xdp_runtime.pin_settings_path = base.str() + "/settings";
    }
}

void configure_dpdk_source(openpenny::Config& cfg, const CliOptions& opts) {
    (void)opts;
    cfg.input.backend = openpenny::PacketInputBackend::Dpdk;
    cfg.dpdk.enable = true;
}

} // namespace openpenny::cli
