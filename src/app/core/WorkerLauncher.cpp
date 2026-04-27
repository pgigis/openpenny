// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/app/core/WorkerLauncher.h"

#include "openpenny/egress/PacketSink.h"

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

    if (!cfg.prefix_ip.empty() && cfg.mask_bits > 0) {
        add("--prefix");
        add(cfg.prefix_ip);
        add("--mask-bits");
        add(std::to_string(cfg.mask_bits));
    }

    add("--test-id");
    add(cfg.test_id);

    add("--mode");
    add(opts.mode == PipelineOptions::Mode::Passive ? "passive" : "active");

    if (opts.queue_count > 1) {
        add("--queues");
        add(std::to_string(opts.queue_count));
    }

    // Egress translation: the worker accepts a declarative --egress
    // <kind> plus --egress-device and TUN-specific knobs. This keeps
    // the launcher in sync with the EgressConfig contract without
    // having to hand-roll a parallel tri-state for each new sink kind.
    add("--egress");
    add(openpenny::egress::egress_kind_name(cfg.egress.kind));
    if (!cfg.egress.device.empty()) {
        add("--egress-device");
        add(cfg.egress.device);
    }
    if (cfg.egress.kind == openpenny::egress::EgressKind::Tun) {
        if (!cfg.egress.tun_multi_queue) {
            add("--no-tun-multi-queue");
        }
        if (cfg.egress.tun_mtu > 0) {
            add("--tun-mtu");
            add(std::to_string(cfg.egress.tun_mtu));
        }
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
