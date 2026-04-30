// SPDX-License-Identifier: BSD-2-Clause
/**
 * @file AfPacketMirrorReader.cpp
 * @brief Implementation of the AF_PACKET-based passive mirror reader.
 *
 * The reader is a thin wrapper around a packet socket bound to a single
 * interface via `sockaddr_ll`. `PACKET_OUTGOING` frames are filtered out
 * by default so we only see ingress. All higher-level filtering lives in
 * userspace (the shared `TrafficMatchConfig`) to keep the MVP simple and
 * leave room for a future kernel-side cBPF fast path.
 */

#include "openpenny/ingress/af_packet/AfPacketMirrorReader.h"

#include "openpenny/log/Log.h"
#include "openpenny/net/PacketParser.h"
#include "openpenny/net/TrafficMatch.h"

#include <cerrno>
#include <chrono>
#include <cstring>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef OPENPENNY_WITH_LIBBPF
extern "C" {
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
}
#endif

namespace openpenny::ingress::af_packet {

namespace {

constexpr std::size_t kMinFrameBuf = 2048;
constexpr std::size_t kDefaultFrameBuf = 9216; // Jumbo + headroom.

std::uint64_t now_nanos() noexcept {
    using clock = std::chrono::steady_clock;
    const auto d = clock::now().time_since_epoch();
    return std::chrono::duration_cast<std::chrono::nanoseconds>(d).count();
}

/// Resolve an interface name to its kernel ifindex.
unsigned resolve_ifindex(const std::string& ifname) noexcept {
    if (ifname.empty()) return 0;
    return if_nametoindex(ifname.c_str());
}

} // namespace

AfPacketMirrorReader::AfPacketMirrorReader() = default;

AfPacketMirrorReader::~AfPacketMirrorReader() {
    AfPacketMirrorReader::close();
}

void AfPacketMirrorReader::configure(const Options& opts) {
    opts_ = opts;
    if (opts_.frame_size < kMinFrameBuf) {
        opts_.frame_size = kDefaultFrameBuf;
    }
    frame_buf_.assign(opts_.frame_size, 0);
}

void AfPacketMirrorReader::configure_from_config(const Config& cfg) {
    Options o;
    o.batch           = cfg.xdp_runtime.batch > 0 ? cfg.xdp_runtime.batch : 256;
    o.poll_timeout_ms = static_cast<int>(cfg.xdp_runtime.poll_timeout_ms);
    // Prefer a generous buffer; the AF_PACKET ring has no zero-copy path so
    // copies dominate and larger frames reduce syscall overhead on jumbos.
    o.frame_size      = cfg.frame_size > 0 ? cfg.frame_size : kDefaultFrameBuf;
    if (o.frame_size < kMinFrameBuf) {
        o.frame_size = kDefaultFrameBuf;
    }
    o.match_config    = cfg.traffic_match;
    configure(o);
}

bool AfPacketMirrorReader::open(const std::string& ifname, unsigned /*queue*/) {
    if (fd_ >= 0) {
        TCPLOG_WARN("AfPacketMirrorReader::open called on already-open socket (fd=%d)", fd_);
        return true;
    }

    if (frame_buf_.size() < kMinFrameBuf) {
        // Caller forgot to configure(); fall back to defaults so we don't
        // silently scribble on a zero-byte buffer.
        frame_buf_.assign(kDefaultFrameBuf, 0);
    }

    const int sock = ::socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK,
                              htons(ETH_P_ALL));
    if (sock < 0) {
        TCPLOG_ERROR("AF_PACKET socket() failed: %s", std::strerror(errno));
        return false;
    }

    const unsigned idx = resolve_ifindex(ifname);
    if (idx == 0) {
        TCPLOG_ERROR("AF_PACKET: unknown interface '%s': %s",
                     ifname.c_str(), std::strerror(errno));
        ::close(sock);
        return false;
    }

    sockaddr_ll addr{};
    addr.sll_family   = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex  = static_cast<int>(idx);
    if (::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        TCPLOG_ERROR("AF_PACKET bind('%s', idx=%u) failed: %s",
                     ifname.c_str(), idx, std::strerror(errno));
        ::close(sock);
        return false;
    }

    if (opts_.rcvbuf_bytes > 0) {
        const int rb = static_cast<int>(opts_.rcvbuf_bytes);
        if (::setsockopt(sock, SOL_SOCKET, SO_RCVBUFFORCE, &rb, sizeof(rb)) != 0 &&
            ::setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb)) != 0) {
            TCPLOG_WARN("AF_PACKET SO_RCVBUF=%d on '%s' failed: %s",
                        rb, ifname.c_str(), std::strerror(errno));
        }
    }

    fd_      = sock;
    ifindex_ = idx;
    ifname_  = ifname;
    TCPLOG_INFO("AfPacketMirrorReader: tapping '%s' (ifindex=%u, fd=%d, frame=%zu)",
                ifname.c_str(), idx, fd_, frame_buf_.size());

    // Detect a leftover XDP program. AF_PACKET runs *after* the XDP
    // hook in the kernel pipeline, so any program already attached
    // (e.g. from a prior active-mode run that didn't clean up) sees
    // packets first and we only see what it returns XDP_PASS for.
    // With a stale "redirect" program from a prior active run, the
    // matched traffic gets redirected away from us and our
    // [afpkt_counters] line stays at rx=0 indefinitely.
    //
    // When libbpf is available, query the netdev directly so the
    // warning is precise (it fires only when there really is a
    // program attached). Otherwise fall back to a generic hint.
#ifdef OPENPENNY_WITH_LIBBPF
    {
        __u32 prog_id = 0;
        const int qrc = bpf_xdp_query_id(static_cast<int>(idx), 0, &prog_id);
        if (qrc == 0 && prog_id != 0) {
            TCPLOG_WARN(
                "AfPacketMirrorReader: an XDP program (id=%u) is "
                "attached on '%s' RIGHT NOW. AF_PACKET runs after XDP, "
                "so any traffic that program redirects or drops will "
                "never reach this passive tap. To detach it and try "
                "again:\n"
                "    sudo ip link set dev %s xdp off\n"
                "    sudo ip link set dev %s xdpgeneric off\n"
                "    sudo ip link set dev %s xdpdrv off\n"
                "    sudo rm -rf /sys/fs/bpf/openpenny*",
                static_cast<unsigned>(prog_id),
                ifname.c_str(),
                ifname.c_str(), ifname.c_str(), ifname.c_str());
        } else {
            TCPLOG_INFO(
                "AfPacketMirrorReader: no XDP program currently attached "
                "on '%s' — AF_PACKET tap should see all traffic the "
                "kernel delivers to this interface.",
                ifname.c_str());
        }
    }
#else
    TCPLOG_INFO("AfPacketMirrorReader: AF_PACKET runs after the XDP hook. "
                "If rx stays at 0, check for a leftover XDP program with "
                "`ip -d link show %s` and clean up via "
                "`sudo ip link set dev %s xdp off && "
                "sudo rm -rf /sys/fs/bpf/openpenny*`",
                ifname.c_str(), ifname.c_str());
#endif
    return true;
}

void AfPacketMirrorReader::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    ifindex_ = 0;
    ifname_.clear();
}

bool AfPacketMirrorReader::poll(const net::PacketHandler& handler, std::size_t budget) {
    if (fd_ < 0) return false;

    // Optional blocking wait. Non-blocking callers keep poll_timeout_ms=0
    // so they can busy-loop their own scheduler.
    if (opts_.poll_timeout_ms > 0) {
        pollfd pfd{fd_, POLLIN, 0};
        const int rc = ::poll(&pfd, 1, opts_.poll_timeout_ms);
        if (rc <= 0) {
            // rc==0: timeout; rc<0 with EINTR: signal, just retry next poll.
            return true;
        }
    }

    // Honour the IPipelineStrategy contract: a budget of 0 means "use the
    // source's own default". PassiveTestPipelineRunner doesn't override
    // poll_budget(), so it always passes 0 here; treating that literally as
    // std::min(0, opts_.batch) collapsed cap to 0 and the recvfrom loop
    // below never ran -- the AF_PACKET tap drained zero packets per poll,
    // so nothing reached the strategy (no stats bumped, nothing forwarded
    // through opts_.sink). Fall back to opts_.batch when no explicit
    // budget is supplied; otherwise clamp the caller's budget to it.
    const std::size_t cap = budget == 0 ? opts_.batch
                                        : std::min(budget, opts_.batch);
    std::size_t drained = 0;

    while (drained < cap) {
        sockaddr_ll from{};
        socklen_t from_len = sizeof(from);

        const ssize_t n = ::recvfrom(fd_,
                                     frame_buf_.data(),
                                     frame_buf_.size(),
                                     0,
                                     reinterpret_cast<sockaddr*>(&from),
                                     &from_len);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                break;
            }
            TCPLOG_WARN("AF_PACKET recvfrom failed on '%s': %s",
                        ifname_.c_str(), std::strerror(errno));
            break;
        }
        if (n == 0) {
            break;
        }

        ++rx_packets_;

        if (opts_.drop_outgoing && from.sll_pkttype == PACKET_OUTGOING) {
            ++outgoing_skipped_;
            continue;
        }

        net::PacketView view{};
        if (!net::PacketParser::decode(frame_buf_.data(),
                                       static_cast<std::size_t>(n),
                                       view)) {
            ++decode_failures_;
            continue;
        }
        view.timestamp_ns = now_nanos();
        // Surface the original L2 frame (Ethernet header included) so
        // sinks like RawNicSink can forward via SOCK_RAW without losing
        // the original src/dst MAC addresses.
        view.layer2_ptr = frame_buf_.data();
        view.layer2_length = static_cast<std::uint32_t>(n);

        if (!opts_.match_config.empty() &&
            !net::traffic_matches_packet(opts_.match_config, view)) {
            ++filter_rejects_;
            continue;
        }

        ++handler_invocations_;
        if (handler) handler(view);
        ++drained;
    }

    // Periodic diagnostic, same 5s cadence as XDP's [xdp_counters]. Helps
    // pinpoint where packets disappear in the passive path:
    //   rx == 0          -> AF_PACKET socket isn't receiving anything
    //                       (interface down, RSS pre-filtering, or a
    //                        prior XDP program is intercepting all
    //                        traffic before AF_PACKET sees it).
    //   rx > 0, decode_fail close to rx -> non-IPv4 / truncated frames.
    //   rx > 0, filter_reject close to rx -> live traffic doesn't match
    //                                        the configured policy
    //                                        (rule-vs-traffic mismatch).
    //   handler == 0 with rx > 0 -> matches above two; nothing reaches
    //                               the pipeline.
    {
        const auto now = std::chrono::steady_clock::now();
        const bool first = last_counter_log_.time_since_epoch().count() == 0;
        if (first || now - last_counter_log_ >= std::chrono::seconds(5)) {
            last_counter_log_ = now;
            TCPLOG_INFO("[afpkt_counters] rx=%llu decode_fail=%llu "
                        "outgoing_skipped=%llu filter_rejected=%llu "
                        "handler_calls=%llu",
                        static_cast<unsigned long long>(rx_packets_),
                        static_cast<unsigned long long>(decode_failures_),
                        static_cast<unsigned long long>(outgoing_skipped_),
                        static_cast<unsigned long long>(filter_rejects_),
                        static_cast<unsigned long long>(handler_invocations_));
        }
    }
    return true;
}

bool AfPacketMirrorReader::update_match_rules(const net::TrafficMatchConfig& config) {
    opts_.match_config = config;
    return true;
}

} // namespace openpenny::ingress::af_packet
