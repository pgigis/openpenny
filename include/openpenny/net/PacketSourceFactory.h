// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/dataplane/Factory.h"
#include "openpenny/net/Packet.h"

namespace openpenny {
struct Config;
}

namespace openpenny::net {

using IPacketSourceFactory = openpenny::dataplane::IFactory;
using DefaultPacketSourceFactory = openpenny::dataplane::DefaultFactory;

// Backward-compatible helper that uses the default factory (or an override, if set).
PacketSourcePtr create_packet_source(const Config& cfg);

// Access the default factory instance shared across the process.
const IPacketSourceFactory& default_packet_source_factory();

// For tests: override the factory used by create_packet_source.
void set_packet_source_factory_for_tests(const IPacketSourceFactory* factory);

} // namespace openpenny::net
