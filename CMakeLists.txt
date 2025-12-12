# SPDX-License-Identifier: BSD-2-Clause

cmake_minimum_required(VERSION 3.16)
project(openpenny LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# Allow user to override grpc_cpp_plugin path from the command line, e.g.:
#   -DGRPC_CPP_PLUGIN=/usr/bin/grpc_cpp_plugin
set(GRPC_CPP_PLUGIN "" CACHE FILEPATH "Path to grpc_cpp_plugin executable")

include(cmake/Dependencies.cmake)

# --- Options -------------------------------------------------------------------

option(OPENPENNY_WITH_XDP "Build AF_XDP reader" ON)
option(OPENPENNY_WITH_DPDK "Build DPDK reader" OFF)

# --- Core library --------------------------------------------------------------

set(openpenny_sources
    src/agg/Stats.cpp
    src/config/Config.cpp
    src/log/Log.cpp
    src/app/cli/cli_helpers.cpp
    src/app/core/AggregatesController.cpp
    src/app/core/active/ActiveTestPipeline.cpp
    src/app/core/DropCollectorBinding.cpp
    src/app/core/OpenpennyPipelineDriver.cpp
    src/app/core/passive/PassiveTestPipeline.cpp
    src/app/core/utils/FlowDebug.cpp
    src/app/core/WorkerLauncher.cpp
    src/app/core/PerThreadStats.cpp
    src/app/core/RuntimeSetup.cpp
    src/penny/flow/timer/ThreadFlowEventTimer.cpp
    src/penny/flow/state/PennyStats.cpp
    src/penny/flow/engine/FlowEvaluation.cpp
    src/penny/flow/engine/FlowEngine.cpp
    src/penny/flow/manager/ThreadFlowManager.cpp
    src/net/PacketParser.cpp
    src/net/PacketSourceFactory.cpp
)

if(OPENPENNY_WITH_XDP)
    list(APPEND openpenny_sources src/sources/xdp/XdpReader.cpp)
endif()

if(OPENPENNY_WITH_DPDK)
    list(APPEND openpenny_sources src/sources/dpdk/DpdkReader.cpp)
endif()

add_library(openpenny ${openpenny_sources})
target_include_directories(openpenny PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(openpenny PRIVATE -O3 -march=native -Wall -Wextra -Wpedantic)

target_link_libraries(openpenny
    PUBLIC
        yaml-cpp::yaml-cpp
        nlohmann_json::nlohmann_json
        nlohmann_json_schema_validator
)

# Link Protobuf / gRPC to the core library when available.
if(OPENPENNY_PROTOBUF_TARGET AND OPENPENNY_GRPCXX_TARGET)
    target_link_libraries(openpenny PUBLIC ${OPENPENNY_PROTOBUF_TARGET} ${OPENPENNY_GRPCXX_TARGET})
endif()

target_link_libraries(openpenny PUBLIC Boost::boost)

# --- libbpf / libxdp / DPDK via pkg-config ------------------------------------

find_package(PkgConfig QUIET)

if(OPENPENNY_WITH_XDP)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(LIBBPF QUIET libbpf)
        pkg_check_modules(LIBXDP QUIET libxdp)
    endif()

    if(LIBBPF_FOUND)
        target_include_directories(openpenny PUBLIC ${LIBBPF_INCLUDE_DIRS})
        if(TARGET PkgConfig::LIBBPF)
            target_link_libraries(openpenny PUBLIC PkgConfig::LIBBPF)
        else()
            target_link_libraries(openpenny PUBLIC ${LIBBPF_LIBRARIES})
        endif()
        target_compile_definitions(openpenny PRIVATE OPENPENNY_WITH_LIBBPF=1)
    else()
        message(WARNING "Building without libbpf; the XdpReader cannot capture packets (no synthetic fallback)")
    endif()

    if(LIBXDP_FOUND)
        if(TARGET PkgConfig::LIBXDP)
            target_link_libraries(openpenny PUBLIC PkgConfig::LIBXDP)
        else()
            target_link_libraries(openpenny PUBLIC ${LIBXDP_LIBRARIES})
        endif()
    endif()

    target_compile_definitions(openpenny PRIVATE OPENPENNY_WITH_XDP=1)
endif()

if(OPENPENNY_WITH_DPDK)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(DPDK QUIET libdpdk)
    endif()

    if(DPDK_FOUND)
        target_include_directories(openpenny PUBLIC ${DPDK_INCLUDE_DIRS})
        target_link_libraries(openpenny PUBLIC ${DPDK_LIBRARIES})
        target_compile_definitions(openpenny PRIVATE OPENPENNY_WITH_DPDK=1)
    else()
        message(WARNING "DPDK requested but libdpdk not found; DPDK reader will be unavailable.")
    endif()
endif()

# --- CLI -----------------------------------------------------------------------

add_executable(openpenny_cli
    src/app/cli/penny_cli.cpp
    src/app/cli/source_setup.cpp
)
target_link_libraries(openpenny_cli PRIVATE openpenny)

# --- Tests ---------------------------------------------------------------------

enable_testing()

add_executable(test_initial_flow_monitoring tests/test_initial_flow_monitoring.cpp)
target_link_libraries(test_initial_flow_monitoring PRIVATE openpenny)
add_test(NAME initial_flow_monitoring COMMAND test_initial_flow_monitoring)

add_executable(test_gap_management tests/test_gap_management.cpp)
target_link_libraries(test_gap_management PRIVATE openpenny)
add_test(NAME gap_management COMMAND test_gap_management)

add_executable(test_sequence_ordering tests/test_sequence_ordering.cpp)
target_link_libraries(test_sequence_ordering PRIVATE openpenny)
add_test(NAME sequence_ordering COMMAND test_sequence_ordering)

add_executable(test_drop_timer tests/test_drop_timer.cpp)
target_link_libraries(test_drop_timer PRIVATE openpenny)
add_test(NAME drop_timer COMMAND test_drop_timer)

add_executable(test_flow_thresholds tests/test_flow_thresholds.cpp)
target_link_libraries(test_flow_thresholds PRIVATE openpenny)
add_test(NAME flow_thresholds COMMAND test_flow_thresholds)

add_executable(test_cli_options tests/test_cli_options.cpp)
target_link_libraries(test_cli_options PRIVATE openpenny)
add_test(NAME cli_options COMMAND test_cli_options)

# --- XDP build helper ----------------------------------------------------------

add_custom_target(xdp_bpf
    COMMAND ${CMAKE_COMMAND} -E env "PATH=$ENV{PATH}" make -C ${CMAKE_CURRENT_SOURCE_DIR}/xdp-fw xdp_redirect_dstprefix.o
    BYPRODUCTS ${CMAKE_CURRENT_SOURCE_DIR}/xdp-fw/xdp_redirect_dstprefix.o
    COMMENT "Building XDP program (xdp-fw/xdp_redirect_dstprefix.o)"
)

# --- gRPC daemon / worker (only if Protobuf & gRPC really usable) --------------

if(OPENPENNY_PROTOBUF_TARGET AND OPENPENNY_GRPCXX_TARGET AND Protobuf_PROTOC_EXECUTABLE)
    # Locate grpc_cpp_plugin if available.
    set(GRPC_CPP_PLUGIN_PATH "")

    # 1. User override (from -DGRPC_CPP_PLUGIN=...)
    if(GRPC_CPP_PLUGIN)
        set(GRPC_CPP_PLUGIN_PATH "${GRPC_CPP_PLUGIN}")
    # 2. Imported CMake target, if present
    elseif(TARGET gRPC::grpc_cpp_plugin)
        get_target_property(_grpc_cpp_plugin_path gRPC::grpc_cpp_plugin IMPORTED_LOCATION)
        if(_grpc_cpp_plugin_path)
            set(GRPC_CPP_PLUGIN_PATH "${_grpc_cpp_plugin_path}")
        endif()
    # 3. Fallback: search in PATH
    else()
        find_program(_grpc_cpp_plugin_exe NAMES grpc_cpp_plugin)
        if(_grpc_cpp_plugin_exe)
            set(GRPC_CPP_PLUGIN_PATH "${_grpc_cpp_plugin_exe}")
        endif()
    endif()

    if(NOT GRPC_CPP_PLUGIN_PATH)
        message(WARNING "grpc_cpp_plugin not found; 'pennyd' daemon will not be built.")
    else()
        message(STATUS "Using grpc_cpp_plugin: ${GRPC_CPP_PLUGIN_PATH}")

        # Proto generation
        set(penny_proto ${CMAKE_CURRENT_SOURCE_DIR}/proto/penny.proto)
        set(penny_proto_src ${CMAKE_CURRENT_BINARY_DIR}/penny.pb.cc)
        set(penny_proto_hdr ${CMAKE_CURRENT_BINARY_DIR}/penny.pb.h)
        set(penny_grpc_src ${CMAKE_CURRENT_BINARY_DIR}/penny.grpc.pb.cc)
        set(penny_grpc_hdr ${CMAKE_CURRENT_BINARY_DIR}/penny.grpc.pb.h)

        add_custom_command(
            OUTPUT
                ${penny_proto_src}
                ${penny_proto_hdr}
                ${penny_grpc_src}
                ${penny_grpc_hdr}
            COMMAND ${Protobuf_PROTOC_EXECUTABLE}
                    --experimental_allow_proto3_optional
                    --grpc_out ${CMAKE_CURRENT_BINARY_DIR}
                    --cpp_out ${CMAKE_CURRENT_BINARY_DIR}
                    --plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_PATH}
                    -I ${CMAKE_CURRENT_SOURCE_DIR}/proto
                    ${penny_proto}
            DEPENDS ${penny_proto}
            COMMENT "Generating gRPC / Protobuf sources from ${penny_proto}"
        )

        add_library(penny_proto STATIC ${penny_proto_src} ${penny_grpc_src})
        target_include_directories(penny_proto PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
        target_link_libraries(penny_proto PUBLIC ${OPENPENNY_PROTOBUF_TARGET} ${OPENPENNY_GRPCXX_TARGET})

        target_include_directories(openpenny PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
        target_link_libraries(openpenny PUBLIC penny_proto)

        if(OPENPENNY_GRPC_C_TARGET)
            add_executable(pennyd
                src/app/grpc/pennyd.cpp
                src/grpc/PennyService.cpp
            )
            target_include_directories(pennyd PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
            target_link_libraries(pennyd
                PRIVATE
                    openpenny
                    penny_proto
                    ${OPENPENNY_PROTOBUF_TARGET}
                    ${OPENPENNY_GRPCXX_TARGET}
                    ${OPENPENNY_GRPC_C_TARGET}
            )
        else()
            message(WARNING "gRPC C library target not found; 'pennyd' daemon will not be built.")
        endif()

        add_executable(penny_worker
            src/app/worker/penny_worker.cpp
        )
        target_link_libraries(penny_worker PRIVATE openpenny)
    endif()
else()
    message(WARNING "gRPC/Protobuf not fully available (libraries, protoc or grpc_cpp_plugin missing); penny daemon will not be built")
endif()
