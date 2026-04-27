// SPDX-License-Identifier: BSD-2-Clause

#pragma once

#include "openpenny/app/core/OpenpennyPipelineDriver.h"
#include "openpenny/egress/PacketSink.h"

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

    /**
     * @brief Declarative egress block handed to the worker subprocess.
     *
     * Maps 1:1 onto Config::egress in the spawned worker via CLI flags.
     * When kind == None, the launcher asks the worker to run without an
     * egress sink (drop matched packets). When kind == Tun the launcher
     * passes --egress tun with the device name and the tun-specific
     * knobs; similar for RawSocket / RawNic.
     */
    egress::EgressConfig egress{};

    /**
     * @brief Optional prefix override forwarded as --prefix / --mask-bits.
     *
     * These live on the launch config (not on PipelineOptions) because
     * they're a CLI-shaped shorthand for "overlay this prefix onto the
     * worker's xdp_runtime filter config". The pipeline runtime itself
     * reads the prefix from Config::xdp_runtime, not from PipelineOptions.
     */
    std::string prefix_ip{};
    int mask_bits{0};
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
