// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/RuntimeSetup.h"

namespace openpenny {
namespace {
RuntimeSetupSnapshot g_runtime_setup;
}

void set_runtime_setup(const Config& cfg,
                       const PipelineOptions& opts,
                       bool use_xdp,
                       bool use_dpdk) {
    g_runtime_setup.config = cfg;
    g_runtime_setup.options = opts;
    g_runtime_setup.use_xdp = use_xdp;
    g_runtime_setup.use_dpdk = use_dpdk;
}

const RuntimeSetupSnapshot& current_runtime_setup() {
    return g_runtime_setup;
}

RuntimeSetupSnapshot& runtime_setup_mutable() {
    return g_runtime_setup;
}

} // namespace openpenny
