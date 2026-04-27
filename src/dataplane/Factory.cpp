// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/dataplane/Factory.h"

#include "openpenny/config/Config.h"
#include "openpenny/log/Log.h"

#if defined(OPENPENNY_WITH_DPDK)
#include "openpenny/ingress/dpdk/DpdkReader.h"
#endif
#if defined(OPENPENNY_WITH_XDP)
#include "openpenny/ingress/af_xdp/XdpReader.h"
#endif

#include "openpenny/ingress/af_packet/AfPacketMirrorReader.h"

namespace openpenny::dataplane {
namespace {

const IFactory* g_factory_override = nullptr;

} // namespace

SessionPtr DefaultFactory::create(const Config& cfg) const {
    if (cfg.input.backend == PacketInputBackend::Dpdk) {
#if defined(OPENPENNY_WITH_DPDK)
        auto reader = std::make_unique<DpdkReader>();
        reader->configure_from_config(cfg);
        return reader;
#else
        TCPLOG_ERROR("DPDK requested in config but OPENPENNY_WITH_DPDK is disabled at build time.");
        return {};
#endif
    }

    // AF_PACKET mirror: passive, copy-mode tap. Always available (no libbpf
    // or DPDK dependency) which is why it is the default for passive mode.
    if (cfg.input.backend == PacketInputBackend::AfPacketMirror) {
        auto reader = std::make_unique<ingress::af_packet::AfPacketMirrorReader>();
        reader->configure_from_config(cfg);
        return reader;
    }

#if defined(OPENPENNY_WITH_XDP)
    auto reader = std::make_unique<XdpReader>();
    reader->configure_from_config(cfg);
    return reader;
#else
    TCPLOG_ERROR("No dataplane session available: XDP disabled at build time.");
    return {};
#endif
}

const IFactory& default_factory() {
    static DefaultFactory factory;
    return factory;
}

SessionPtr create_session(const Config& cfg) {
    if (g_factory_override) {
        return g_factory_override->create(cfg);
    }
    return default_factory().create(cfg);
}

void set_factory_for_tests(const IFactory* factory) {
    g_factory_override = factory;
}

} // namespace openpenny::dataplane
