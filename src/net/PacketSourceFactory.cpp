// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/net/PacketSourceFactory.h"

#include "openpenny/log/Log.h"

#if defined(OPENPENNY_WITH_DPDK)
#include "openpenny/sources/dpdk/DpdkReader.h"
#endif
#if defined(OPENPENNY_WITH_XDP)
#include "openpenny/sources/xdp/XdpReader.h"
#endif

namespace openpenny::net {
namespace {
const IPacketSourceFactory* g_factory_override = nullptr;
}

PacketSourcePtr DefaultPacketSourceFactory::create(const Config& cfg) const {
    // Use DPDK when explicitly enabled in config.
    if (cfg.dpdk.enable) {
#if defined(OPENPENNY_WITH_DPDK)
        auto reader = std::make_unique<DpdkReader>();
        reader->configure_from_config(cfg);
        return reader;
#else
        TCPLOG_ERROR("DPDK requested in config but OPENPENNY_WITH_DPDK is disabled at build time.");
#endif
    }

    // Otherwise use XDP when available (default).
#if defined(OPENPENNY_WITH_XDP)
    auto reader = std::make_unique<XdpReader>();
    reader->configure_from_config(cfg);
    return reader;
#else
    TCPLOG_ERROR("No packet source available: XDP disabled at build time.");
    return {};
#endif
}

const IPacketSourceFactory& default_packet_source_factory() {
    static DefaultPacketSourceFactory factory;
    return factory;
}

PacketSourcePtr create_packet_source(const Config& cfg) {
    if (g_factory_override) {
        return g_factory_override->create(cfg);
    }
    return default_packet_source_factory().create(cfg);
}

void set_packet_source_factory_for_tests(const IPacketSourceFactory* factory) {
    g_factory_override = factory;
}

} // namespace openpenny::net
