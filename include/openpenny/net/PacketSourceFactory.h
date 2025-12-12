// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/config/Config.h"
#include "openpenny/net/Packet.h"

namespace openpenny::net {

class IPacketSourceFactory {
public:
    virtual ~IPacketSourceFactory() = default;
    virtual PacketSourcePtr create(const Config& cfg) const = 0;
};

class DefaultPacketSourceFactory : public IPacketSourceFactory {
public:
    PacketSourcePtr create(const Config& cfg) const override;
};

// Backward-compatible helper that uses the default factory (or an override, if set).
PacketSourcePtr create_packet_source(const Config& cfg);

// Access the default factory instance shared across the process.
const IPacketSourceFactory& default_packet_source_factory();

// For tests: override the factory used by create_packet_source.
void set_packet_source_factory_for_tests(const IPacketSourceFactory* factory);

} // namespace openpenny::net
