// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/PerThreadStats.h"

#include <cassert>
#include <cstdint>

int main() {
    using namespace openpenny::app;

    init_thread_counters(3);
    assert(aggregate_drop_budget_drops() == 0);

    set_thread_counter_index(0);
    assert(try_reserve_aggregate_drop(2));
    assert(aggregate_drop_budget_drops() == 1);

    set_thread_counter_index(1);
    assert(try_reserve_aggregate_drop(2));
    assert(aggregate_drop_budget_drops() == 2);

    set_thread_counter_index(2);
    assert(!try_reserve_aggregate_drop(2));
    assert(aggregate_drop_budget_drops() == 2);

    // Initialisation should reset the dedicated aggregate-drop budget so a
    // fresh pipeline run does not inherit drops from the previous one.
    init_thread_counters(2);
    set_thread_counter_index(0);
    assert(aggregate_drop_budget_drops() == 0);
    assert(try_reserve_aggregate_drop(1));

    set_thread_counter_index(1);
    assert(!try_reserve_aggregate_drop(1));
    assert(aggregate_drop_budget_drops() == 1);

    return 0;
}
