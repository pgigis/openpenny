// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/dataplane/Session.h"

namespace openpenny {
struct Config;
}

namespace openpenny::dataplane {

/**
 * @brief Factory that compiles stable config into a backend session instance.
 *
 * The caller supplies high-level/compiled config, and the factory returns a
 * concrete AF_XDP or DPDK session without exposing those implementation
 * details to Penny runtime code.
 */
class IFactory {
public:
    virtual ~IFactory() = default;
    virtual SessionPtr create(const Config& cfg) const = 0;
};

class DefaultFactory : public IFactory {
public:
    SessionPtr create(const Config& cfg) const override;
};

SessionPtr create_session(const Config& cfg);
const IFactory& default_factory();
void set_factory_for_tests(const IFactory* factory);

} // namespace openpenny::dataplane
