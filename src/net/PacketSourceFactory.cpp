// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/net/PacketSourceFactory.h"

namespace openpenny::net {

const IPacketSourceFactory& default_packet_source_factory() {
    return openpenny::dataplane::default_factory();
}

PacketSourcePtr create_packet_source(const Config& cfg) {
    return openpenny::dataplane::create_session(cfg);
}

void set_packet_source_factory_for_tests(const IPacketSourceFactory* factory) {
    openpenny::dataplane::set_factory_for_tests(factory);
}

} // namespace openpenny::net
