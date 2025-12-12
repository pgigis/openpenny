// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/config/Config.h"
#include "openpenny/grpc/PennyService.h"
#include "openpenny/log/Log.h"
#include "openpenny/penny/flow/timer/ThreadFlowEventTimer.h"
#include "openpenny/app/core/WorkerLauncher.h"

#include <grpcpp/grpcpp.h>

#include <iostream>
#include <memory>
#include <string>
#include <vector>
#include <signal.h>
#include <thread>

namespace {

struct DaemonArgs {
    std::string config_path{"openpenny.yaml"};
    std::string listen{"0.0.0.0:50051"};
    openpenny::LogLevel log_level{openpenny::LogLevel::INFO};
};

DaemonArgs parse_args(int argc, char** argv) {
    DaemonArgs args;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-c" || arg == "--config") && i + 1 < argc) {
            args.config_path = argv[++i];
        } else if ((arg == "-l" || arg == "--listen") && i + 1 < argc) {
            args.listen = argv[++i];
        } else if (arg == "--log" && i + 1 < argc) {
            std::string lvl = argv[++i];
            if (lvl == "trace") args.log_level = openpenny::LogLevel::TRACE;
            else if (lvl == "debug") args.log_level = openpenny::LogLevel::DEBUG;
            else if (lvl == "info") args.log_level = openpenny::LogLevel::INFO;
            else if (lvl == "warn") args.log_level = openpenny::LogLevel::WARN;
            else if (lvl == "error") args.log_level = openpenny::LogLevel::ERROR;
        }
    }
    return args;
}

} // namespace

int main(int argc, char** argv) {
    auto args = parse_args(argc, argv);

    openpenny::Logger::init({.level = args.log_level});

    auto cfg = openpenny::Config::from_file(args.config_path);
    if (!cfg) {
        TCPLOG_WARN("Failed to load config at %s, using defaults", args.config_path.c_str());
        cfg = openpenny::Config{};
    }

    openpenny::grpc_service::PennyServiceImpl service(*cfg, args.config_path);

    ::grpc::ServerBuilder builder;
    builder.AddListeningPort(args.listen, ::grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    std::unique_ptr<::grpc::Server> server(builder.BuildAndStart());
    if (!server) {
        TCPLOG_ERROR("Failed to start penny daemon gRPC server on %s", args.listen.c_str());
        return 1;
    }

    TCPLOG_INFO("pennyd listening on %s", args.listen.c_str());
    // Handle SIGINT/SIGTERM for graceful shutdown using sigwait.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &set, nullptr);
    std::thread sig_thread([&]() {
        int sig = 0;
        if (sigwait(&set, &sig) == 0) {
            TCPLOG_INFO("pennyd received signal %d, shutting down...", sig);
            server->Shutdown();
        }
    });

    server->Wait();
    if (sig_thread.joinable()) sig_thread.join();

    // On shutdown: purge timers and ensure worker launches are not lingering.
    openpenny::penny::ThreadFlowEventTimerManager::instance().stop();
    TCPLOG_INFO("pennyd shutdown complete");
    return 0;
}
