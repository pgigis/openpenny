// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/cli/cli_helpers.h"

#include <cassert>
#include <string>

int main() {
    // Defaults: no prefix provided should normalize to 0.0.0.0/0.
    openpenny::cli::CliOptions defaults;
    auto normalized_default = openpenny::cli::normalize_options(defaults);
    assert(normalized_default.prefix_cidr == "0.0.0.0/0");
    assert(normalized_default.mask_bits == 0);
    assert(normalized_default.mask_host == 0);

    // Interface-specific pins are independent from traffic matching rules.
    openpenny::cli::CliOptions with_iface;
    with_iface.iface = "eth0";
    auto normalized_with_iface = openpenny::cli::normalize_options(with_iface);
    assert(normalized_with_iface.pin_conf_path.find("openpenny_eth0") != std::string::npos);
    assert(!normalized_with_iface.pin_conf_path.empty());
    assert(normalized_with_iface.pin_settings_path.find("openpenny_eth0") != std::string::npos);

    // Queue auto-probe should be accepted as an alternative to an explicit queue id.
    const char* argv[] = {
        "openpenny_cli",
        "--queue", "auto",
        "--queue-probe-ms", "750",
    };
    auto parsed = openpenny::cli::parse_args(static_cast<int>(sizeof(argv) / sizeof(argv[0])),
                                             const_cast<char**>(argv));
    assert(parsed.queue_auto);
    assert(!parsed.queue_override);
    assert(parsed.queue_probe_ms == 750);

    return 0;
}
