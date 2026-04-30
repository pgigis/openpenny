// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/utils/FlowDebug.h"

#include <sstream>

namespace openpenny {

namespace {

std::string proto_label(std::uint8_t proto) {
    switch (proto) {
    case 6:
        return "tcp";
    case 17:
        return "udp";
    default:
        return std::to_string(static_cast<unsigned>(proto));
    }
}

} // namespace

std::string to_ipv4_string(uint32_t host_order_ip) {
    std::ostringstream out;
    out << ((host_order_ip >> 24) & 0xff) << '.'
        << ((host_order_ip >> 16) & 0xff) << '.'
        << ((host_order_ip >> 8) & 0xff) << '.'
        << (host_order_ip & 0xff);
    return out.str();
}

std::string flow_debug_details(const FlowKey& flow) {
    const auto src_ip = to_ipv4_string(flow.src);
    const auto dst_ip = to_ipv4_string(flow.dst);
    const bool have_proto = flow.ip_proto != 0;
    std::string tag;
    tag.reserve(src_ip.size() + dst_ip.size() + (have_proto ? 24 : 16));
    tag.push_back('{');
    if (have_proto) {
        tag.append(proto_label(flow.ip_proto));
        tag.push_back('-');
    }
    tag.append(src_ip);
    tag.push_back('-');
    tag.append(dst_ip);
    tag.push_back('-');
    tag.append(std::to_string(flow.sport));
    tag.push_back('-');
    tag.append(std::to_string(flow.dport));
    tag.push_back('}');
    return tag;
}

} // namespace openpenny
