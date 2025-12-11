# SPDX-License-Identifier: BSD-2-Clause

include_guard(GLOBAL)

# --- Protobuf / gRPC detection -------------------------------------------------

# Try config-mode first (preferred on many distros), then fallback.
find_package(Protobuf CONFIG QUIET)
if(NOT Protobuf_FOUND)
    find_package(Protobuf QUIET)
endif()

find_package(gRPC CONFIG QUIET)
if(NOT gRPC_FOUND)
    find_package(gRPC QUIET)
endif()

if(Protobuf_FOUND)
    message(STATUS "Found Protobuf: ${Protobuf_VERSION}")
    # Ensure we know how to call protoc.
    if(NOT Protobuf_PROTOC_EXECUTABLE)
        find_program(Protobuf_PROTOC_EXECUTABLE protoc)
    endif()
endif()

if(gRPC_FOUND)
    message(STATUS "Found gRPC")
endif()

# Normalise target names for Protobuf / gRPC (distros differ slightly).
set(OPENPENNY_PROTOBUF_TARGET "")
if(TARGET protobuf::libprotobuf)
    set(OPENPENNY_PROTOBUF_TARGET protobuf::libprotobuf)
elseif(TARGET protobuf::protobuf)
    set(OPENPENNY_PROTOBUF_TARGET protobuf::protobuf)
elseif(TARGET Protobuf::libprotobuf)
    set(OPENPENNY_PROTOBUF_TARGET Protobuf::libprotobuf)
elseif(TARGET Protobuf::protobuf)
    set(OPENPENNY_PROTOBUF_TARGET Protobuf::protobuf)
endif()

set(OPENPENNY_GRPCXX_TARGET "")
if(TARGET gRPC::grpc++)
    set(OPENPENNY_GRPCXX_TARGET gRPC::grpc++)
elseif(TARGET grpc++)
    set(OPENPENNY_GRPCXX_TARGET grpc++)
endif()

set(OPENPENNY_GRPC_C_TARGET "")
if(TARGET gRPC::grpc)
    set(OPENPENNY_GRPC_C_TARGET gRPC::grpc)
elseif(TARGET grpc)
    set(OPENPENNY_GRPC_C_TARGET grpc)
endif()

# --- yaml-cpp / JSON libs ------------------------------------------------------

find_package(yaml-cpp QUIET)
if(NOT yaml-cpp_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        yaml-cpp
        GIT_REPOSITORY https://github.com/jbeder/yaml-cpp.git
        GIT_TAG master
        GIT_SHALLOW FALSE
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(yaml-cpp)
endif()

find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json
        URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json)
endif()

find_package(nlohmann_json_schema_validator QUIET)
if(NOT nlohmann_json_schema_validator_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        nlohmann_json_schema_validator
        GIT_REPOSITORY https://github.com/pboettch/json-schema-validator.git
        GIT_TAG 2.3.0
        GIT_SHALLOW TRUE
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(nlohmann_json_schema_validator)
endif()

# --- Boost ---------------------------------------------------------------------

find_package(Boost QUIET)
if(NOT Boost_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        boost
        URL https://archives.boost.io/release/1.83.0/source/boost_1_83_0.tar.gz
        URL_HASH SHA256=c0685b68dd44cc46574cce86c4e17c0f611b15e195be9848dfd0769a0a207628
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_GetProperties(boost)
    if(NOT boost_POPULATED)
        FetchContent_Populate(boost)
        add_library(boost_headers INTERFACE)
        target_include_directories(boost_headers INTERFACE ${boost_SOURCE_DIR})
        add_library(Boost::boost ALIAS boost_headers)
    endif()
endif()
