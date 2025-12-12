// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/penny/flow/engine/FlowEvaluation.h"

#include <algorithm>
#include <cmath>
#include <stdexcept>

namespace openpenny::penny {

FlowEvaluationResult evaluate_flow_decision(const PennyStats& stats,
                                            double retransmission_miss_probability,
                                            double max_duplicate_fraction) {
    const double miss_prob = std::clamp(retransmission_miss_probability, 0.0, 1.0);

    auto duplicate_packets = stats.duplicate_packets();
    if (duplicate_packets == 0) duplicate_packets = 1;
    if (stats.data_packets() == 0) {
        // Not enough evidence; return a neutral decision.
        return FlowEvaluationResult{
            FlowEngine::FlowDecision::FINISHED_NO_DECISION,
            0.0,
            0.0,
            0.0,
            0.0};
    }
    const double dup_ratio =
        static_cast<double>(duplicate_packets) /
        static_cast<double>(stats.data_packets());

    if (max_duplicate_fraction > 0.0 && dup_ratio > max_duplicate_fraction) {
        return FlowEvaluationResult{
            FlowEngine::FlowDecision::FINISHED_DUPLICATE_EXCEEDED,
            0.0,
            1.0,
            0.0,
            dup_ratio};
    }

    const double p_closed = (stats.non_retransmitted_packets() == 0)
        ? 1.0
        : std::pow(
              miss_prob,
              static_cast<double>(stats.non_retransmitted_packets()));

    const double p_not_closed =
        (stats.retransmitted_packets() == 0)
            ? 1.0
            : std::pow(
                  dup_ratio,
                  static_cast<double>(stats.retransmitted_packets()));

    const double denom = p_closed + p_not_closed;
    const double closed_weight =
        (denom > 0.0) ? (p_closed / denom) : 0.0;

    FlowEngine::FlowDecision decision = FlowEngine::FlowDecision::FINISHED_NO_DECISION;
    if (closed_weight > 0.99) {
        decision = FlowEngine::FlowDecision::FINISHED_CLOSED_LOOP;
    } else if (closed_weight < 0.01) {
        decision = FlowEngine::FlowDecision::FINISHED_NOT_CLOSED_LOOP;
    }

    return FlowEvaluationResult{
        decision,
        p_closed,
        p_not_closed,
        closed_weight,
        dup_ratio};
}

const char* flow_decision_to_string(FlowEngine::FlowDecision decision) noexcept {
    switch (decision) {
        case FlowEngine::FlowDecision::PENDING:
            return "PENDING";
        case FlowEngine::FlowDecision::FINISHED_CLOSED_LOOP:
            return "FINISHED_CLOSED_LOOP";
        case FlowEngine::FlowDecision::FINISHED_NOT_CLOSED_LOOP:
            return "FINISHED_NOT_CLOSED_LOOP";
        case FlowEngine::FlowDecision::FINISHED_DUPLICATE_EXCEEDED:
            return "FINISHED_DUPLICATE_EXCEEDED";
        case FlowEngine::FlowDecision::FINISHED_NO_DECISION:
            return "FINISHED_NO_DECISION";
    }
    return "UNKNOWN";
}

} // namespace openpenny::penny
