// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: CLI option normalisation and argument parsing.
//
//   - normalize_options() supplies a 0.0.0.0/0 fallback prefix when
//     none was given.
//   - The XDP map-pin paths are derived from the chosen interface name
//     (so two interfaces don't clobber each other's pinned maps).
//   - `--queue auto` is accepted as a stand-in for an explicit queue id,
//     and `--queue-probe-ms` flows through to the parsed options.
//
// If this fails: pre-flight defaults or pin-path derivation drift,
// which surfaces as confusing "ENOENT for /sys/fs/bpf/openpenny_..."
// errors at runtime.

#include "openpenny/app/cli/cli_helpers.h"

#include <cassert>
#include <iostream>
#include <string>

int main() {
    {
        std::cout << "scenario: default options yield 0.0.0.0/0\n";
        openpenny::cli::CliOptions defaults;
        const auto out = openpenny::cli::normalize_options(defaults);
        assert(out.prefix_cidr == "0.0.0.0/0");
        assert(out.mask_bits   == 0);
        assert(out.mask_host   == 0);
    }

    {
        std::cout << "scenario: --iface eth0 derives the pin paths\n";
        openpenny::cli::CliOptions with_iface;
        with_iface.iface = "eth0";
        const auto out = openpenny::cli::normalize_options(with_iface);
        assert(out.pin_conf_path.find("openpenny_eth0")     != std::string::npos);
        assert(!out.pin_conf_path.empty());
        assert(out.pin_settings_path.find("openpenny_eth0") != std::string::npos);
    }

    {
        std::cout << "scenario: --queue auto --queue-probe-ms 750 parses correctly\n";
        const char* argv[] = {
            "openpenny_cli",
            "--queue", "auto",
            "--queue-probe-ms", "750",
        };
        const auto parsed = openpenny::cli::parse_args(
            static_cast<int>(sizeof(argv) / sizeof(argv[0])),
            const_cast<char**>(argv));
        assert(parsed.queue_auto);
        assert(!parsed.queue_override);
        assert(parsed.queue_probe_ms == 750);
    }

    return 0;
}
