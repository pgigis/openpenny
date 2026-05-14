// SPDX-License-Identifier: BSD-2-Clause
//
// Pins down: the cross-thread aggregate drop budget reservation
// (`try_reserve_aggregate_drop`) is global across worker threads:
//   - reservations from different per-thread shards each count toward
//     the same shared total;
//   - once the budget is consumed, further reservations are rejected;
//   - re-initialising the per-thread counters resets the budget so a
//     fresh pipeline run does not inherit drops from a previous one.
//
// If this fails: aggregate drop-cap enforcement double-counts or
// leaks state across runs.

#include "test_helpers.h"

#include "openpenny/app/core/PerThreadStats.h"

#include <cassert>

int main() {
    using namespace openpenny::app;
    using openpenny::test::Section;

    {
        Section _{"three shards share one budget of 2"};
        init_thread_counters(3);
        assert(aggregate_drop_budget_drops() == 0);

        set_thread_counter_index(0);
        assert(try_reserve_aggregate_drop(2));
        assert(aggregate_drop_budget_drops() == 1);

        set_thread_counter_index(1);
        assert(try_reserve_aggregate_drop(2));
        assert(aggregate_drop_budget_drops() == 2);

        set_thread_counter_index(2);
        assert(!try_reserve_aggregate_drop(2)); // budget exhausted
        assert(aggregate_drop_budget_drops() == 2);
    }

    {
        Section _{"init_thread_counters() resets the budget for a fresh run"};
        init_thread_counters(2);
        set_thread_counter_index(0);
        assert(aggregate_drop_budget_drops() == 0);
        assert(try_reserve_aggregate_drop(1));

        set_thread_counter_index(1);
        assert(!try_reserve_aggregate_drop(1)); // budget = 1 already consumed
        assert(aggregate_drop_budget_drops() == 1);
    }

    return 0;
}
