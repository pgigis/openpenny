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

    // Prefix + iface should generate pin paths.
    openpenny::cli::CliOptions with_prefix;
    with_prefix.has_prefix = true;
    with_prefix.mask_bits = 24;
    with_prefix.iface = "eth0";
    auto normalized_with_prefix = openpenny::cli::normalize_options(with_prefix);
    assert(normalized_with_prefix.pin_conf_path.find("openpenny_eth0_24") != std::string::npos);
    assert(!normalized_with_prefix.pin_conf_path.empty());

    return 0;
}
