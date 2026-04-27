// SPDX-License-Identifier: BSD-2-Clause

#pragma once
/**
 * @file PacketSink.h
 * @brief Egress abstraction for the openpenny pipeline.
 *
 * Historically, the pipeline had a tangle of fields on PipelineOptions --
 * tun_fd, forward_fd, forward_to_tun, forward_raw_socket, forward_device --
 * that encoded a tri-state (TUN / IPPROTO_RAW / nothing) with the file
 * descriptor ownership left to the caller (CLI or worker). That made it
 * impossible to add new egress targets (e.g. raw AF_PACKET write to a NIC)
 * without touching every caller, and it leaked lifecycle bugs like the
 * "TUN never brought up" black hole that silently dropped forwarded
 * packets. Chunk 3 of the refactor removed those fields entirely; every
 * caller now populates Config::egress before driving the pipeline.
 *
 * The PacketSink interface replaces that tri-state with a single
 * polymorphic object. Pipeline stages call write(packet); the concrete
 * sink decides how the bytes leave the box. Ownership of any underlying
 * fd / handle is internal to the sink, which is opened via a factory from
 * a declarative EgressConfig (itself parsed from YAML).
 */

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace openpenny {
namespace net {
struct PacketView;
}

namespace egress {

/**
 * @brief Enumerates the egress targets the pipeline knows how to drive.
 *
 * Additional kinds (GRE tunnel, UDP encap, etc.) can be added here
 * without touching the pipeline stages -- a new Kind just needs a new
 * concrete PacketSink implementation and a branch in make_packet_sink().
 */
enum class EgressKind {
    None,       ///< Drop matched packets; only increment counters.
    Tun,        ///< Write layer-3 bytes into a TUN device (IFF_TUN, IFF_NO_PI).
    RawSocket,  ///< Write layer-3 bytes into an IPPROTO_RAW socket.
    RawNic,     ///< Write layer-3 bytes out an AF_PACKET raw socket on a NIC.
};

/**
 * @brief Declarative egress configuration parsed from YAML.
 *
 * Fields are documented individually; only the subset relevant to the
 * selected kind is consulted by the factory. Invalid combinations
 * (e.g. Tun with empty device) are logged and cause factory failure
 * rather than silent fallback to a different kind.
 */
struct EgressConfig {
    EgressKind kind = EgressKind::None;

    /// Interface name to attach to (TUN name, or NIC name for RawNic/RawSocket).
    std::string device;

    /// TUN-only: enable IFF_MULTI_QUEUE so one TUN supports N workers.
    bool tun_multi_queue = true;
    /// TUN-only: MTU to apply after creating the device (0 skips SIOCSIFMTU).
    int tun_mtu = 9000;
    /// TUN-only: transmit queue length to apply (0 skips SIOCSIFTXQLEN).
    int tun_txqlen = 10000;
    /// TUN-only: bring device up administratively. Leave true unless you
    /// specifically need to run it down for external tooling to tune it.
    bool tun_bring_up = true;
    /// TUN-only: set /proc/sys/net/ipv4/conf/<tun>/rp_filter to 2 (loose) on
    /// open. Required for reinjection to work in practice: packets we write
    /// to the TUN still carry the ORIGINAL remote source IP, but the route
    /// back to that IP lives on the physical NIC, so strict reverse-path
    /// filtering (rp_filter=1) silently drops them before local delivery.
    /// Loose mode (2) accepts the packet as long as a route exists via any
    /// interface. Set false only if you manage rp_filter externally.
    bool tun_rp_filter_loose = true;

    /// RawNic-only: if true, the socket is bound to `device` via SO_BINDTODEVICE
    /// and the caller is responsible for ensuring the NIC can TX layer-3 frames.
    bool raw_nic_bind_device = true;

    /**
     * @brief True if the pipeline should actually attempt egress.
     *
     * Kept as a helper so callers don't have to know the enum values.
     */
    bool enabled() const noexcept { return kind != EgressKind::None; }
};

/**
 * @brief Thread-safe counter pair reported by every sink.
 *
 * Sinks increment `forwarded` or `errors` for every write. The pipeline
 * reads these atomically and rolls them into ModeResult at shutdown.
 */
struct SinkStats {
    std::atomic<std::uint64_t> forwarded{0};
    std::atomic<std::uint64_t> errors{0};

    std::uint64_t forwarded_load() const noexcept {
        return forwarded.load(std::memory_order_relaxed);
    }
    std::uint64_t errors_load() const noexcept {
        return errors.load(std::memory_order_relaxed);
    }
};

/**
 * @brief Abstract packet sink.
 *
 * A sink is opened once at pipeline start and shared across all worker
 * threads (via shared_ptr). write() must be thread-safe -- concrete
 * implementations that use blocking syscalls (write(2), sendto(2)) are
 * naturally so on Linux, but any internal state must be synchronised.
 *
 * Sinks own any underlying resource (fd, socket) and close it in the
 * destructor so the pipeline never leaks descriptors on the error path.
 */
class PacketSink {
public:
    virtual ~PacketSink() = default;

    /**
     * @brief One-time setup. Returns false on failure; caller should log
     *        errno / dmesg and treat the sink as unusable.
     */
    virtual bool open() = 0;

    /**
     * @brief Tear down the sink. Called from dtor; safe to call twice.
     */
    virtual void close() noexcept = 0;

    /**
     * @brief Emit a parsed packet. Must be thread-safe.
     *
     * Returns true on a successful write, false on any error. Transient
     * EAGAIN/EWOULDBLOCK are counted as errors==0 (pipeline drops the
     * packet) because the pipeline is not responsible for reliable
     * delivery -- it's a passive mirror.
     */
    virtual bool write(const net::PacketView& packet) = 0;

    /**
     * @brief Human-readable description, for startup logs.
     */
    virtual std::string describe() const = 0;

    /**
     * @brief Kind tag, useful for UX and metrics labels.
     */
    virtual EgressKind kind() const noexcept = 0;

    /**
     * @brief Accessor for the shared counters.
     */
    const SinkStats& stats() const noexcept { return stats_; }

protected:
    SinkStats stats_{}; ///< Updated by concrete implementations under write().
};

using PacketSinkPtr = std::shared_ptr<PacketSink>;

/**
 * @brief Build a PacketSink for @p cfg, opening any underlying resource.
 *
 * Returns nullptr on failure (logs via TCPLOG_*). Callers should treat a
 * null return as a hard error unless cfg.kind == None, in which case a
 * no-op sink is returned instead.
 */
PacketSinkPtr make_packet_sink(const EgressConfig& cfg);

/**
 * @brief Parse an EgressKind from a string. Unknown values return None.
 */
EgressKind parse_egress_kind(const std::string& value);

/**
 * @brief Inverse of parse_egress_kind() for logging / serialisation.
 */
const char* egress_kind_name(EgressKind kind) noexcept;

} // namespace egress
} // namespace openpenny
