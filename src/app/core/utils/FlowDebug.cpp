// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/utils/FlowDebug.h"

#include <sstream>

namespace openpenny {

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
    std::string tag;
    tag.reserve(src_ip.size() + dst_ip.size() + 16);
    tag.push_back('{');
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
