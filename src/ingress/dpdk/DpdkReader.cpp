// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/ingress/dpdk/DpdkReader.h"

#include "openpenny/log/Log.h"
#include "openpenny/net/PacketParser.h"
#include "openpenny/net/TrafficMatch.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <vector>

#if defined(OPENPENNY_WITH_DPDK)
extern "C" {
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
}
#endif

namespace openpenny {

namespace {

#if defined(OPENPENNY_WITH_DPDK)
uint64_t now_ns() {
    return std::chrono::duration_cast<std::chrono::nanoseconds>(
               std::chrono::steady_clock::now().time_since_epoch())
        .count();
}

struct DpdkGlobalState {
    bool eal_ready{false};
    bool eal_failed{false};
    rte_mempool* pool{nullptr};
};

DpdkGlobalState& dpdk_state() {
    static DpdkGlobalState state;
    return state;
}

bool ensure_eal() {
    auto& st = dpdk_state();
    if (st.eal_ready || st.eal_failed) return st.eal_ready;

    // rte_eal_init may scribble on argv entries (it has historically rewritten
    // them when consuming flags). Pass mutable buffers backed by std::string
    // instead of pointers to read-only literals.
    static const std::array<std::string, 5> kArgs{
        "openpenny_dpdk", "-l", "0", "-n", "4"};
    std::array<std::vector<char>, kArgs.size()> arg_storage;
    std::array<char*, kArgs.size()> argv{};
    for (std::size_t i = 0; i < kArgs.size(); ++i) {
        arg_storage[i].assign(kArgs[i].begin(), kArgs[i].end());
        arg_storage[i].push_back('\0');
        argv[i] = arg_storage[i].data();
    }
    int argc = static_cast<int>(argv.size());
    int rc = rte_eal_init(argc, argv.data());
    if (rc < 0) {
        TCPLOG_ERROR("rte_eal_init failed: %s", rte_strerror(rte_errno));
        st.eal_failed = true;
        return false;
    }

    // Pool large enough to back a 4096-deep RX ring with headroom for the
    // descriptors held by the application during burst processing.
    st.pool = rte_pktmbuf_pool_create("penny_pool",
                                      8192,
                                      256,
                                      0,
                                      RTE_MBUF_DEFAULT_BUF_SIZE,
                                      rte_socket_id());
    if (!st.pool) {
        TCPLOG_ERROR("Failed to create DPDK mbuf pool: %s", rte_strerror(rte_errno));
        st.eal_failed = true;
        return false;
    }

    st.eal_ready = true;
    return true;
}
#endif

} // namespace

bool DpdkReader::open(const std::string& ifname, unsigned queue) {
    if (opened_) return true;
    if (!configured_) {
        configure(Options{});
    }

    ifname_ = ifname;
    queue_ = queue;

#if !defined(OPENPENNY_WITH_DPDK)
    TCPLOG_ERROR("DPDK reader selected but OPENPENNY_WITH_DPDK was not set at build time.");
    return false;
#else
    if (!opts_.enable) {
        TCPLOG_ERROR("DPDK reader disabled in configuration.");
        return false;
    }

    if (!ensure_eal()) return false;
    auto& st = dpdk_state();

    uint16_t port_id = 0;
    if (rte_eth_dev_get_port_by_name(ifname.c_str(), &port_id) != 0) {
        TCPLOG_ERROR("DPDK could not find port for interface %s "
                     "(DPDK port names are PCI ids like '0000:01:00.0' or "
                     "vdev names like 'net_tap0', not Linux ifnames).",
                     ifname.c_str());
        return false;
    }

    rte_eth_conf port_conf{};
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;

    rte_eth_dev_info dev_info{};
    if (rte_eth_dev_info_get(port_id, &dev_info) != 0) {
        TCPLOG_ERROR("DPDK rte_eth_dev_info_get failed for port %u", port_id);
        return false;
    }

    // We must configure at least (queue + 1) RX queues so that
    // rte_eth_rx_queue_setup() with the requested queue index is valid. The
    // previous version always asked for nb_rx_queue=1 which made any non-zero
    // queue index fail with -EINVAL.
    const uint16_t nb_rx_queues = static_cast<uint16_t>(queue + 1);
    if (rte_eth_dev_configure(port_id, nb_rx_queues, 0, &port_conf) != 0) {
        TCPLOG_ERROR("DPDK configure failed for port %u (nb_rx_queues=%u)",
                     port_id, nb_rx_queues);
        return false;
    }

    // Let the PMD clamp rx_desc into its valid range; otherwise some drivers
    // (mlx5, ice, ...) reject the setup outright.
    uint16_t rx_desc = 1024;
    uint16_t tx_desc = 0;
    if (rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &rx_desc, &tx_desc) != 0) {
        TCPLOG_ERROR("DPDK rte_eth_dev_adjust_nb_rx_tx_desc failed for port %u",
                     port_id);
        return false;
    }

    if (rte_eth_rx_queue_setup(port_id,
                               queue,
                               rx_desc,
                               rte_eth_dev_socket_id(port_id),
                               nullptr,
                               st.pool) != 0) {
        TCPLOG_ERROR("DPDK rx_queue_setup failed for port %u queue %u", port_id, queue);
        return false;
    }

    if (rte_eth_dev_start(port_id) != 0) {
        TCPLOG_ERROR("DPDK start failed for port %u", port_id);
        return false;
    }

    // Without promiscuous mode the NIC silently drops every frame whose dst
    // MAC isn't ours, which makes a tap-style ingest see effectively nothing.
    // Treat failure as a warning: some virtual PMDs (TAP, ring) don't support
    // it, and we'd still receive locally addressed traffic.
    const int prom_rc = rte_eth_promiscuous_enable(port_id);
    if (prom_rc != 0) {
        TCPLOG_WARN("DPDK promiscuous_enable failed for port %u (rc=%d, %s); "
                    "the reader will only see frames addressed to this port's MAC.",
                    port_id, prom_rc, rte_strerror(-prom_rc));
    }

    port_id_ = port_id;
    opened_ = true;
    TCPLOG_INFO("DpdkReader: opened port %u (name='%s') queue=%u rx_desc=%u",
                port_id, ifname.c_str(), queue,
                static_cast<unsigned>(rx_desc));
    return true;
#endif
}

void DpdkReader::close() {
#if defined(OPENPENNY_WITH_DPDK)
    if (opened_) {
        rte_eth_promiscuous_disable(port_id_);
        rte_eth_dev_stop(port_id_);
    }
    port_id_ = 0;
#endif
    opened_ = false;
}

bool DpdkReader::poll(const net::PacketHandler& handler, std::size_t budget) {
#if !defined(OPENPENNY_WITH_DPDK)
    (void)handler;
    (void)budget;
    return false;
#else
    if (!opened_) return false;

    // Honour the IPipelineStrategy contract: a budget of 0 means "use the
    // source's own default", matching AfPacketMirrorReader semantics.
    const uint16_t configured_burst =
        opts_.burst > 0 ? static_cast<uint16_t>(opts_.burst) : uint16_t{32};
    const uint16_t burst = budget == 0
        ? configured_burst
        : static_cast<uint16_t>(
              std::min<std::size_t>(budget, configured_burst));
    if (burst == 0) return true;

    rte_mbuf* bufs[256];
    const uint16_t capped_burst = std::min<uint16_t>(
        burst, static_cast<uint16_t>(RTE_DIM(bufs)));
    const uint16_t received =
        rte_eth_rx_burst(port_id_, queue_, bufs, capped_burst);

    // Linearization buffer for chained mbufs. Most production NICs deliver
    // single-segment buffers for typical MTUs, so this stays empty in the hot
    // path; only jumbo / scattered RX hits the slow path.
    std::vector<uint8_t> linear;

    for (uint16_t i = 0; i < received; ++i) {
        rte_mbuf* mbuf = bufs[i];

        const uint8_t* data = nullptr;
        uint32_t len = 0;
        if (mbuf->nb_segs <= 1) {
            // Fast path: single segment, mtod points at the whole frame.
            data = rte_pktmbuf_mtod(mbuf, const uint8_t*);
            len  = rte_pktmbuf_data_len(mbuf);
        } else {
            // Slow path: copy the chained segments into a contiguous buffer
            // before handing it to PacketParser, otherwise the parser would
            // walk past the first segment's data.
            const uint32_t total = rte_pktmbuf_pkt_len(mbuf);
            linear.resize(total);
            uint32_t off = 0;
            for (rte_mbuf* seg = mbuf; seg != nullptr; seg = seg->next) {
                const uint16_t seg_len = rte_pktmbuf_data_len(seg);
                if (off + seg_len > total) break; // defensive
                std::memcpy(linear.data() + off,
                            rte_pktmbuf_mtod(seg, const uint8_t*),
                            seg_len);
                off += seg_len;
            }
            data = linear.data();
            len  = off;
        }

        net::PacketView packet{};
        if (net::PacketParser::decode(data, len, packet)) {
            if (!opts_.match_config.empty() &&
                !net::traffic_matches_packet(opts_.match_config, packet)) {
                rte_pktmbuf_free(mbuf);
                continue;
            }
            packet.timestamp_ns = now_ns();
            // Surface the original L2 frame for L2-level egress paths
            // (RawNicSink with SOCK_RAW needs the Ethernet header).
            packet.layer2_ptr = data;
            packet.layer2_length = len;
            if (handler) handler(packet);
        }
        rte_pktmbuf_free(mbuf);
    }

    return true;
#endif
}

} // namespace openpenny
