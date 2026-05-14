// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: traffic_matches_flow() / traffic_matches_packet() respect
// the per-rule fields they were given, and the default_action acts as
// a catch-all when no rule matches.
//
// Each scenario rebuilds the rule set and checks both a matching and a
// non-matching flow.

#include "openpenny/net/Packet.h"
#include "openpenny/net/TrafficMatch.h"

#include <cassert>
#include <iostream>

namespace {

openpenny::FlowKey make_match_target() {
    openpenny::FlowKey k{};
    k.src      = 0x0a010203u; // 10.1.2.3
    k.dst      = 0xc0000201u; // 192.0.2.1
    k.sport    = 12345;
    k.dport    = 443;
    k.ip_proto = 6; // TCP
    return k;
}

} // namespace

int main() {
    using openpenny::net::TrafficIpPrefix;
    using openpenny::net::TrafficMatchConfig;
    using openpenny::net::TrafficMatchRule;
    using openpenny::net::TrafficRuleAction;
    using openpenny::net::traffic_matches_flow;
    using openpenny::net::traffic_matches_packet;

    const openpenny::FlowKey match = make_match_target();
    TrafficMatchConfig cfg{};

    {
        std::cout << "scenario: src_ip /24 prefix match\n";
        cfg.rules.clear();
        TrafficMatchRule r{};
        r.src_ip = TrafficIpPrefix{0x0a010200u, 0xffffff00u};
        r.label  = "source-prefix";
        cfg.rules.push_back(r);

        assert(traffic_matches_flow(cfg, match));

        auto outside = match;
        outside.src = 0x0a020203u;
        assert(!traffic_matches_flow(cfg, outside));
    }

    {
        std::cout << "scenario: combined 5-tuple match (src/dst/port/port)\n";
        cfg.rules.clear();
        TrafficMatchRule r{};
        r.src_ip   = TrafficIpPrefix{0x0a010203u, 0xffffffffu};
        r.dst_ip   = TrafficIpPrefix{0xc0000200u, 0xffffff00u};
        r.src_port = 12345;
        r.dst_port = 443;
        cfg.rules.push_back(r);

        assert(traffic_matches_flow(cfg, match));

        auto wrong_dst = match;
        wrong_dst.dst = 0xc0000301u;
        assert(!traffic_matches_flow(cfg, wrong_dst));

        auto wrong_sport = match;
        wrong_sport.sport = 50000;
        assert(!traffic_matches_flow(cfg, wrong_sport));
    }

    {
        std::cout << "scenario: dst_port-only rule\n";
        cfg.rules.clear();
        TrafficMatchRule r{};
        r.dst_port = 443;
        cfg.rules.push_back(r);

        assert(traffic_matches_flow(cfg, match));

        auto wrong_dport = match;
        wrong_dport.dport = 80;
        assert(!traffic_matches_flow(cfg, wrong_dport));
    }

    {
        std::cout << "scenario: protocol + dst_port rule\n";
        cfg.rules.clear();
        TrafficMatchRule r{};
        r.ip_proto = 6;
        r.dst_port = 443;
        cfg.rules.push_back(r);

        assert(traffic_matches_flow(cfg, match));

        auto wrong_proto = match;
        wrong_proto.ip_proto = 17; // UDP
        assert(!traffic_matches_flow(cfg, wrong_proto));
    }

    {
        std::cout << "scenario: PacketView path agrees with flow path\n";
        openpenny::net::PacketView pkt{};
        pkt.flow     = match;
        pkt.ip_proto = 6;
        assert(traffic_matches_packet(cfg, pkt));

        pkt.ip_proto      = 17; // UDP — current rule is TCP only
        pkt.flow.ip_proto = 17;
        assert(!traffic_matches_packet(cfg, pkt));
    }

    {
        std::cout << "scenario: default_action = RedirectToUserspace acts as catch-all\n";
        cfg.default_action = TrafficRuleAction::RedirectToUserspace;
        openpenny::net::PacketView pkt{};
        pkt.flow     = match;
        pkt.ip_proto = 17;
        pkt.flow.ip_proto = 17;
        assert(traffic_matches_packet(cfg, pkt));
    }

    return 0;
}
