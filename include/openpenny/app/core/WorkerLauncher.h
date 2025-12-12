// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/app/core/OpenpennyPipelineDriver.h"

#include <string>

namespace openpenny::app {

/**
 * @brief Configuration parameters used to launch a worker process.
 *
 * This structure bundles all runtime options required when spawning
 * a Penny worker instance. These values are typically supplied by the
 * control plane or derived from user-provided test parameters.
 */
struct WorkerLaunchConfig {
    /// Executable name or path of the worker binary.
    std::string worker_bin{"penny_worker"};

    /// Path to the configuration file that the worker should load.
    std::string config_path{"openpenny.yaml"};

    /// Identifier for the test instance, passed to the worker for logging or tagging.
    std::string test_id{"default"};

    /// Whether matched packets should be forwarded to a TUN interface.
    bool forward_to_tun{true};

    /// Whether raw-socket forwarding is enabled instead of (or in addition to) TUN.
    bool forward_raw_socket{false};

    /// Name of the TUN interface used for forwarding when enabled.
    std::string tun_name{"xdp-tu"};

    /// Name of the device to which packets should be forwarded via raw-socket mode.
    std::string forward_device{};

    /// Enable multi-queue mode for the TUN interface, if supported.
    bool tun_multi_queue{true};

    /// MTU to configure on the TUN interface.
    int tun_mtu{9000};
};

/**
 * @brief Result of a worker spawn attempt.
 *
 * Holds both the exit status and the captured output (stdout + stderr)
 * from the worker process.
 */
struct WorkerSpawnResult {
    /// Exit status returned by the child process, or -1 on failure.
    int status{-1};

    /// Combined stdout and stderr output captured during execution.
    std::string output;
};

/**
 * @brief Launch the Penny worker process with the given configuration and options.
 *
 * This function starts a new worker subprocess, passing the necessary arguments
 * derived from the supplied WorkerLaunchConfig and PipelineOptions. It waits for
 * the process to complete and returns its exit status and captured output.
 *
 * @param cfg  Worker launch parameters.
 * @param opts Pipeline options generated for the test.
 * @return WorkerSpawnResult containing exit code and process output.
 */
WorkerSpawnResult spawn_worker_process(const WorkerLaunchConfig& cfg,
                                       const PipelineOptions& opts);

} // namespace openpenny::app
