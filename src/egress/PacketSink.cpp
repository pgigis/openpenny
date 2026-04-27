// SPDX-License-Identifier: BSD-2-Clause
/**
 * @file PacketSink.cpp
 * @brief PacketSink factory, NullSink, string <-> EgressKind helpers.
 *
 * The concrete sinks for TUN / IPPROTO_RAW / AF_PACKET live in sibling
 * translation units; this file contains only the dispatcher and the
 * no-op NullSink used when egress.kind == None (or when the caller wants
 * to drive the pipeline without touching the network at all, e.g. unit
 * tests).
 */

#include "openpenny/egress/PacketSink.h"
#include "openpenny/egress/TunSink.h"
#include "openpenny/egress/RawSocketSink.h"
#include "openpenny/egress/RawNicSink.h"
#include "openpenny/log/Log.h"
#include "openpenny/net/Packet.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace openpenny::egress {

namespace {

/**
 * @brief No-op sink.
 *
 * Does nothing on open() / write() / close() and never touches network
 * state. Used when egress.kind == None so the pipeline can keep calling
 * sink_->write() unconditionally without branching.
 */
class NullSink : public PacketSink {
public:
    bool open() override { return true; }
    void close() noexcept override {}
    bool write(const net::PacketView&) override {
        // Matched packets are intentionally dropped; counters stay zero to
        // make "no egress configured" observable in metrics instead of
        // pretending we forwarded anything.
        return true;
    }
    std::string describe() const override { return "none (packets dropped)"; }
    EgressKind kind() const noexcept override { return EgressKind::None; }
};

std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

} // namespace

EgressKind parse_egress_kind(const std::string& value) {
    const auto normalized = lower_copy(value);
    if (normalized == "none" || normalized.empty()) return EgressKind::None;
    if (normalized == "tun" || normalized == "xdp-tun") return EgressKind::Tun;
    if (normalized == "raw_socket" || normalized == "raw-socket" ||
        normalized == "ipproto_raw") return EgressKind::RawSocket;
    if (normalized == "raw_nic" || normalized == "raw-nic" ||
        normalized == "af_packet" || normalized == "nic") return EgressKind::RawNic;
    TCPLOG_WARN("Unknown egress kind '%s'; defaulting to 'none'", value.c_str());
    return EgressKind::None;
}

const char* egress_kind_name(EgressKind kind) noexcept {
    switch (kind) {
        case EgressKind::None:      return "none";
        case EgressKind::Tun:       return "tun";
        case EgressKind::RawSocket: return "raw_socket";
        case EgressKind::RawNic:    return "raw_nic";
    }
    return "unknown";
}

PacketSinkPtr make_packet_sink(const EgressConfig& cfg) {
    PacketSinkPtr sink;
    switch (cfg.kind) {
        case EgressKind::None:
            sink = std::make_shared<NullSink>();
            break;
        case EgressKind::Tun:
            sink = std::make_shared<TunSink>(cfg);
            break;
        case EgressKind::RawSocket:
            sink = std::make_shared<RawSocketSink>(cfg);
            break;
        case EgressKind::RawNic:
            sink = std::make_shared<RawNicSink>(cfg);
            break;
    }
    if (!sink) {
        TCPLOG_ERROR("Failed to construct packet sink for kind '%s'",
                     egress_kind_name(cfg.kind));
        return nullptr;
    }
    if (!sink->open()) {
        TCPLOG_ERROR("PacketSink::open() failed for kind '%s' (device='%s')",
                     egress_kind_name(cfg.kind),
                     cfg.device.c_str());
        return nullptr;
    }
    return sink;
}

} // namespace openpenny::egress
