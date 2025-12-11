// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/WorkerLauncher.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>
#include <vector>

namespace openpenny::app {

namespace {

std::vector<std::string> build_worker_argv(const WorkerLaunchConfig& cfg,
                                           const PipelineOptions& opts) {
    std::vector<std::string> args;
    auto add = [&](std::string v) { args.push_back(std::move(v)); };

    add(cfg.worker_bin);
    add("--config");
    add(cfg.config_path);

    if (!opts.prefix_ip.empty() && opts.mask_bits > 0) {
        add("--prefix");
        add(opts.prefix_ip);
        add("--mask-bits");
        add(std::to_string(opts.mask_bits));
    }

    add("--test-id");
    add(cfg.test_id);

    add("--mode");
    add(opts.mode == PipelineOptions::Mode::Passive ? "passive" : "active");

    if (opts.queue_count > 1) {
        add("--queues");
        add(std::to_string(opts.queue_count));
    }

    if (opts.forward_raw_socket) {
        add("--forward-raw-socket");
    }

    if (opts.forward_to_tun && !opts.forward_raw_socket) {
        add("--forward-to-tun");
    } else {
        add("--no-forward-to-tun");
    }

    add("--tun-name");
    add(cfg.tun_name);

    if (!cfg.forward_device.empty()) {
        add("--forward-device");
        add(cfg.forward_device);
    }

    if (!cfg.tun_multi_queue) {
        add("--no-tun-multi-queue");
    }

    if (cfg.tun_mtu > 0) {
        add("--tun-mtu");
        add(std::to_string(cfg.tun_mtu));
    }

    if (!opts.stats_socket_path.empty()) {
        add("--stats-sock");
        add(opts.stats_socket_path);
    }

    return args;
}

} // namespace

WorkerSpawnResult spawn_worker_process(const WorkerLaunchConfig& cfg,
                                       const PipelineOptions& opts) {
    int pipefd[2];
    WorkerSpawnResult result;

    if (pipe(pipefd) != 0) {
        result.status = -1;
        return result;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        result.status = -1;
        return result;
    }

    if (pid == 0) {
        // Child: redirect stdout to pipe and exec worker.
        dup2(pipefd[1], STDOUT_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);

        const auto argv_storage = build_worker_argv(cfg, opts);
        std::vector<char*> argv;
        argv.reserve(argv_storage.size() + 1);
        for (const auto& s : argv_storage) {
            argv.push_back(const_cast<char*>(s.c_str()));
        }
        argv.push_back(nullptr);

        execvp(cfg.worker_bin.c_str(), argv.data());
        _exit(127);
    }

    close(pipefd[1]);
    char buf[512];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
        result.output.append(buf, static_cast<size_t>(n));
    }
    close(pipefd[0]);

    int status = 0;
    waitpid(pid, &status, 0);
    result.status = status;
    return result;
}

} // namespace openpenny::app
