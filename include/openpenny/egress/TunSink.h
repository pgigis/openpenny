// SPDX-License-Identifier: BSD-2-Clause

#pragma once
/**
 * @file TunSink.h
 * @brief PacketSink that writes layer-3 packets into a TUN device
 *        (IFF_TUN | IFF_NO_PI), optionally multi-queue.
 *
 * The sink always brings the device administratively UP at open time;
 * leaving it DOWN black-holes every forwarded packet without warning.
 */

#include "openpenny/egress/PacketSink.h"

#include <atomic>
#include <mutex>
#include <vector>

namespace openpenny::egress {

class TunSink : public PacketSink {
public:
    explicit TunSink(EgressConfig cfg);
    ~TunSink() override;

    bool open() override;
    void close() noexcept override;
    bool write(const net::PacketView& packet) override;
    std::string describe() const override;
    EgressKind kind() const noexcept override { return EgressKind::Tun; }

private:
    bool tune_link(const std::string& name) const;

    /// Return the fd this calling thread should write to. With
    /// `IFF_MULTI_QUEUE` we open one extra fd per writer thread so the
    /// kernel can give each its own internal queue, avoiding a single
    /// shared TUN queue-lock when many workers write concurrently. The
    /// first call from a thread opens its fd; subsequent calls return
    /// the cached value via `thread_local` storage.
    int thread_fd();

    EgressConfig cfg_{};
    /// Master fd: opened by `open()`, used for the link-control ioctls
    /// (mtu / txqlen / IFF_UP) and for sysctl tweaks. Also used as the
    /// fallback target if a per-thread fd ever fails to open.
    int fd_ = -1;

    /// Extra fds opened lazily on first `write()` from each worker
    /// thread; tracked so `close()` can release them all on shutdown.
    /// Only ever appended-to (no removals during a run), so reads via
    /// the `thread_local` cache are lock-free after the first call.
    std::mutex fds_mtx_;
    std::vector<int> additional_fds_;
    std::atomic<bool> backpressure_logged_{false};
};

} // namespace openpenny::egress
