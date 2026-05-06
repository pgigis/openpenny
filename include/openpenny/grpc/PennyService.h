// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/control/Policy.h"
#include "penny.grpc.pb.h"

#include <memory>
#include <mutex>
#include <string>

namespace openpenny::grpc_service {

/**
 * @brief Concrete implementation of the gRPC control service for Penny tests.
 *
 * Server-side handler for the PennyService interface generated from
 * `proto/penny.proto`. Translates RPC requests into pipeline driver
 * options. The service owns no packet or flow state itself; all test
 * state is delegated to the pipeline driver.
 */
class PennyServiceImpl final :
    public openpenny::api::PennyService::Service {
public:
    // -------------------------------------------------------------------------
    // Lifecycle / configuration
    // -------------------------------------------------------------------------

    /**
     * @brief Construct the Penny gRPC service implementation.
     *
     * @param defaults     Default Config applied to new tests when request fields are unset.
     * @param config_path  Path to the configuration file used to bootstrap workers.
     *
     * Side effects:
     *  - Stores default Config for future use.
     *  - Saves the config path for BPF / UMEM / timeout initialisation during tests.
     */
    PennyServiceImpl(const Config& defaults, std::string config_path);

    // -------------------------------------------------------------------------
    // RPC handlers
    // -------------------------------------------------------------------------

    /**
     * @brief Start a new Penny test based on a gRPC request.
     *
     * This method:
     *  1. Validates the request, returning gRPC errors on malformed input.
     *  2. Merges default settings into missing request fields.
     *  3. Generates pipeline options to run the test worker.
     *  4. Returns success via the out-parameter @p response.
     *
     * This call is thread-safe, stateless, and may be invoked concurrently by gRPC worker threads.
     *
     * @param context  gRPC request context (e.g., cancellation, deadlines).
     * @param request  gRPC StartTest request from the orchestrator.
     * @param response Output structure filled with success status and execution details.
     *
     * @return grpc::Status OK on success.
     * @return grpc::Status non-OK (with details) on failure.
     */
    ::grpc::Status StartTest(::grpc::ServerContext* context,
                             const openpenny::api::StartTestRequest* request,
                             openpenny::api::StartTestResponse* response) override;

    ::grpc::Status ApplyConfig(::grpc::ServerContext* context,
                               const openpenny::api::ApplyConfigRequest* request,
                               openpenny::api::ConfigResponse* response) override;

    ::grpc::Status SetTrafficPolicy(::grpc::ServerContext* context,
                                    const openpenny::api::SetTrafficPolicyRequest* request,
                                    openpenny::api::ConfigResponse* response) override;

    ::grpc::Status SetRuntimePolicy(::grpc::ServerContext* context,
                                    const openpenny::api::SetRuntimePolicyRequest* request,
                                    openpenny::api::ConfigResponse* response) override;

    ::grpc::Status SetMode(::grpc::ServerContext* context,
                           const openpenny::api::SetModeRequest* request,
                           openpenny::api::ConfigResponse* response) override;

    ::grpc::Status GetDesiredConfig(::grpc::ServerContext* context,
                                    const openpenny::api::GetConfigRequest* request,
                                    openpenny::api::ConfigResponse* response) override;

    ::grpc::Status GetEffectiveConfig(::grpc::ServerContext* context,
                                      const openpenny::api::GetConfigRequest* request,
                                      openpenny::api::ConfigResponse* response) override;

    ::grpc::Status ReloadConfig(::grpc::ServerContext* context,
                                const openpenny::api::ReloadConfigRequest* request,
                                openpenny::api::ConfigResponse* response) override;

    ::grpc::Status Stop(::grpc::ServerContext* context,
                        const openpenny::api::StopRequest* request,
                        openpenny::api::ConfigResponse* response) override;

    ::grpc::Status GetRuntimeStatus(::grpc::ServerContext* context,
                                    const openpenny::api::RuntimeStatusRequest* request,
                                    openpenny::api::RuntimeStatusResponse* response) override;

private:
    // -------------------------------------------------------------------------
    // Helpers for default merging and option construction
    // -------------------------------------------------------------------------

    /**
     * @brief Load default configuration.
     *
     * This method is intentionally kept simple; it may:
     *  - read default Config from disk (via config_path_),
     *  - or return the in-memory defaults_ object,
     *  depending on the intended test bootstrap policy.
     */
    Config load_defaults() const;

    /**
     * @brief Translate a validated gRPC request into pipeline options for a test.
     *
     * This helper extracts tunables from the request and builds a concrete
     * PipelineOptions structure expected by the pipeline driver.
     *
     * @param req gRPC request containing test tunables.
     * @return Concrete PipelineOptions derived from request fields + defaults.
     * @throws std::runtime_error if no translation is possible for this test mode.
     */
    PipelineOptions make_options(const openpenny::api::StartTestRequest& req) const;

    // -------------------------------------------------------------------------
    // Internal state
    // -------------------------------------------------------------------------

    Config defaults_{};         ///< Default test configuration used for missing request fields.
    std::string config_path_{}; ///< Location of configuration file for test worker bootstrap.
    mutable std::mutex config_mutex_{};
    control::DesiredConfig desired_config_{};
    control::EffectiveConfig effective_config_{};
    bool desired_config_override_active_{false};
    
    /// Default binary path/name for test workers (may be overridden later).
    std::string worker_bin_{"penny_worker"};
};

} // namespace openpenny::grpc_service
