// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/net/TrafficMatch.h"
#include "openpenny/net/Packet.h"

#include <cassert>

int main() {
    openpenny::net::TrafficMatchConfig cfg{};
    openpenny::net::TrafficMatchRule src_ip_rule{};
    src_ip_rule.src_ip = openpenny::net::TrafficIpPrefix{0x0a010200u, 0xffffff00u};
    src_ip_rule.label = "source-prefix";
    cfg.rules.push_back(src_ip_rule);

    openpenny::FlowKey matching{};
    matching.src = 0x0a010203u;
    matching.dst = 0xc0000201u;
    matching.sport = 12345;
    matching.dport = 443;
    matching.ip_proto = 6;

    openpenny::FlowKey non_matching = matching;
    non_matching.src = 0x0a020203u;

    assert(openpenny::net::traffic_matches_flow(cfg, matching));
    assert(!openpenny::net::traffic_matches_flow(cfg, non_matching));

    openpenny::net::TrafficMatchRule combined{};
    combined.src_ip = openpenny::net::TrafficIpPrefix{0x0a010203u, 0xffffffffu};
    combined.dst_ip = openpenny::net::TrafficIpPrefix{0xc0000200u, 0xffffff00u};
    combined.src_port = 12345;
    combined.dst_port = 443;
    cfg.rules.clear();
    cfg.rules.push_back(combined);

    assert(openpenny::net::traffic_matches_flow(cfg, matching));

    auto wrong_dst = matching;
    wrong_dst.dst = 0xc0000301u;
    assert(!openpenny::net::traffic_matches_flow(cfg, wrong_dst));

    auto wrong_src_port = matching;
    wrong_src_port.sport = 50000;
    assert(!openpenny::net::traffic_matches_flow(cfg, wrong_src_port));

    openpenny::net::TrafficMatchRule dst_port_only{};
    dst_port_only.dst_port = 443;
    cfg.rules.clear();
    cfg.rules.push_back(dst_port_only);
    assert(openpenny::net::traffic_matches_flow(cfg, matching));
    auto wrong_dst_port = matching;
    wrong_dst_port.dport = 80;
    assert(!openpenny::net::traffic_matches_flow(cfg, wrong_dst_port));

    openpenny::net::TrafficMatchRule tcp_https{};
    tcp_https.ip_proto = 6;
    tcp_https.dst_port = 443;
    cfg.rules.clear();
    cfg.rules.push_back(tcp_https);

    assert(openpenny::net::traffic_matches_flow(cfg, matching));
    auto wrong_proto = matching;
    wrong_proto.ip_proto = 17;
    assert(!openpenny::net::traffic_matches_flow(cfg, wrong_proto));

    openpenny::net::PacketView packet{};
    packet.flow = matching;
    packet.ip_proto = 6;
    assert(openpenny::net::traffic_matches_packet(cfg, packet));

    packet.ip_proto = 17;
    packet.flow.ip_proto = 17;
    assert(!openpenny::net::traffic_matches_packet(cfg, packet));

    cfg.default_action = openpenny::net::TrafficRuleAction::RedirectToUserspace;
    assert(openpenny::net::traffic_matches_packet(cfg, packet));

    return 0;
}
