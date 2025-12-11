// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/sources/dpdk/DpdkReader.h"

#include "openpenny/log/Log.h"
#include "openpenny/net/PacketParser.h"

#include <chrono>
#include <cstring>
#include <algorithm>

#if defined(OPENPENNY_WITH_DPDK)
extern "C" {
#include <rte_common.h>
#include <rte_eal.h>
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

    const char* argv_init[] = {"openpenny_dpdk", "-l", "0", "-n", "4"};
    int argc = static_cast<int>(sizeof(argv_init) / sizeof(argv_init[0]));
    int rc = rte_eal_init(argc, const_cast<char**>(argv_init));
    if (rc < 0) {
        TCPLOG_ERROR("rte_eal_init failed");
        st.eal_failed = true;
        return false;
    }

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
        TCPLOG_ERROR("DPDK could not find port for interface %s", ifname.c_str());
        return false;
    }

    rte_eth_conf port_conf{};
    port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;

    rte_eth_dev_info dev_info{};
    rte_eth_dev_info_get(port_id, &dev_info);

    if (rte_eth_dev_configure(port_id, 1, 0, &port_conf) != 0) {
        TCPLOG_ERROR("DPDK configure failed for port %u", port_id);
        return false;
    }

    const uint16_t rx_desc = 1024;
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

    port_id_ = port_id;
    opened_ = true;
    return true;
#endif
}

void DpdkReader::close() {
#if defined(OPENPENNY_WITH_DPDK)
    if (opened_) {
        rte_eth_dev_stop(port_id_);
    }
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

    const uint16_t burst = static_cast<uint16_t>(
        budget ? std::min<std::size_t>(budget, opts_.burst) : opts_.burst);
    if (burst == 0) return true;

    rte_mbuf* bufs[256];
    const uint16_t capped_burst = std::min<uint16_t>(burst, static_cast<uint16_t>(RTE_DIM(bufs)));
    const uint16_t received = rte_eth_rx_burst(port_id_, queue_, bufs, capped_burst);
    for (uint16_t i = 0; i < received; ++i) {
        rte_mbuf* mbuf = bufs[i];
        const uint8_t* data = rte_pktmbuf_mtod(mbuf, const uint8_t*);
        const uint32_t len = rte_pktmbuf_pkt_len(mbuf);
        net::PacketView packet{};
        if (net::PacketParser::decode(data, len, packet)) {
            packet.timestamp_ns = now_ns();
            handler(packet);
        }
        rte_pktmbuf_free(mbuf);
    }

    return true;
#endif
}

} // namespace openpenny
