// SPDX-License-Identifier: BSD-2-Clause

#pragma once
/**
 * @file Log.h
 * @brief Tiny thread-safe logger with levels and backends (console/file).
 *
 * Usage:
 *   openpenny::Logger::init({ .level = LogLevel::INFO,
 *                             .mode  = LogMode::Console,
 *                             .file_path = "app.log" });
 *
 *   TCPLOG_INFO("Hello %s", "world");
 *
 * Levels: TRACE < DEBUG < INFO < WARN < ERROR
 * Modes : Console, File, Silent
 */

#include <algorithm>
#include <atomic>
#include <cstdarg>
#include <cstdio>
#include <mutex>
#include <string>
#include <unistd.h>
#include <ctime>

namespace openpenny {

/**
 * @brief Logging severity levels in increasing order.
 */
enum class LogLevel {
    TRACE = 0,
    DEBUG = 1,
    INFO  = 2,
    WARN  = 3,
    ERROR = 4
};

/**
 * @brief Output backends supported by the logger.
 */
enum class LogMode {
    Console,  ///< Log to stdout / stderr (depending on implementation).
    File,     ///< Log to a configured FILE* handle.
    Silent    ///< Discard all log messages.
};

/**
 * @brief Initial configuration passed to Logger::init().
 */
struct LoggerConfig {
    LogLevel level = LogLevel::INFO;      ///< Minimum severity to emit.
    LogMode  mode  = LogMode::Console;    ///< Output backend.
    std::string file_path{};              ///< Used when mode == File.
};

/**
 * @brief Tiny thread-safe logger providing leveled printf-style helpers.
 *
 * Design notes:
 *  - A static log level is stored as an atomic to allow fast read access and
 *    cheap level checks from hot paths.
 *  - The actual emission (fprintf/fwrite) is protected by a mutex to prevent
 *    interleaved lines across threads.
 */
class Logger {
public:
    /**
     * @brief Initialise the logging backend and minimum level.
     *
     * If mode == File, this will attempt to open the configured file path.
     * Calling init() more than once is allowed, but the behaviour should be
     * treated as "reconfigure" rather than incremental.
     */
    static void init(const LoggerConfig& cfg);

    /**
     * @brief Override the effective global log level.
     *
     * This is safe to call concurrently from multiple threads.
     */
    static void set_level(LogLevel lvl);

    /**
     * @brief Query the current global log level.
     */
    static LogLevel level();

    /**
     * @brief Emit a formatted log message.
     *
     * This is a printf-style function; callers must ensure the format string
     * matches the arguments. It is safe to call from multiple threads.
     *
     * Example:
     *   Logger::log(LogLevel::INFO, "Listening on %s:%u", host, port);
     */
    static void log(LogLevel lvl, const char* fmt, ...);

private:
    /// vprintf-style helper called by log().
    static void vlog(LogLevel lvl, const char* fmt, va_list ap);

    /// Map a LogLevel to its string label (e.g., "INFO").
    static const char* level_str(LogLevel lvl);

    static std::mutex mtx_;            ///< Serialises writes to the backend.
    static std::atomic<int> level_;    ///< Current minimum level as an int.
    static LogMode mode_;              ///< Current output mode.
    static FILE* file_;                ///< Owned FILE* when mode == File.
};

// -----------------------------------------------------------------------------
// Convenience macros
// -----------------------------------------------------------------------------

/**
 * @brief Quick check to see whether a given level is currently enabled.
 *
 * This avoids building strings or formatting arguments when the log level is
 * below the configured threshold.
 */
#define TCPLOG_ENABLED(lvl) \
    (static_cast<int>(openpenny::Logger::level()) <= static_cast<int>(openpenny::LogLevel::lvl))

/**
 * @brief TRACE level logging via Logger::log().
 *
 * Logger::vlog will prepend timestamp and [TRACE] and ensure a trailing '\n'.
 */
#define TCPLOG_TRACE(fmt, ...) \
    do { \
        if (TCPLOG_ENABLED(TRACE)) { \
            openpenny::Logger::log(openpenny::LogLevel::TRACE, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

/**
 * @brief DEBUG logging with an inlined, timestamped fast path to stdout.
 *
 * This bypasses Logger::log() entirely to avoid indirect calls and extra
 * locking overhead in debug-heavy paths. It still respects the global log
 * level via TCPLOG_ENABLED(DEBUG).
 *
 * Format:
 *   HH:MM:SS.mmm and a [DEBUG ...] prefix are included here directly.
 */
#define TCPLOG_DEBUG(fmt, ...) \
    do { \
        if (TCPLOG_ENABLED(DEBUG)) { \
            struct timespec _tcp_ts; \
            clock_gettime(CLOCK_REALTIME, &_tcp_ts); \
            std::tm _tcp_tm; \
            localtime_r(&_tcp_ts.tv_sec, &_tcp_tm); \
            char _tcp_time[16]; \
            int _tcp_ms = static_cast<int>(_tcp_ts.tv_nsec / 1000000L); \
            if (_tcp_ms < 0) _tcp_ms = 0; \
            else if (_tcp_ms > 999) _tcp_ms = _tcp_ms % 1000; \
            std::snprintf(_tcp_time, sizeof(_tcp_time), "%02d:%02d:%02d.%03d", \
                          _tcp_tm.tm_hour, _tcp_tm.tm_min, _tcp_tm.tm_sec, _tcp_ms); \
            char _tcpdbg_buf[576]; \
            int _tcpdbg_len = std::snprintf(_tcpdbg_buf, sizeof(_tcpdbg_buf), \
                                            "[DEBUG %s] " fmt "\n", _tcp_time, ##__VA_ARGS__); \
            if (_tcpdbg_len > 0) { \
                std::size_t _tcpdbg_size = static_cast<std::size_t>( \
                    std::min<int>(_tcpdbg_len, static_cast<int>(sizeof(_tcpdbg_buf) - 1))); \
                ::write(STDOUT_FILENO, _tcpdbg_buf, _tcpdbg_size); \
            } \
        } \
    } while (0)

/**
 * @brief INFO level logging via Logger::log().
 *
 * Logger::vlog will prepend timestamp and [INFO] and ensure a trailing '\n'.
 */
#define TCPLOG_INFO(fmt, ...) \
    do { \
        if (TCPLOG_ENABLED(INFO)) { \
            openpenny::Logger::log(openpenny::LogLevel::INFO, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

/**
 * @brief WARN level logging via Logger::log().
 */
#define TCPLOG_WARN(fmt, ...) \
    do { \
        if (TCPLOG_ENABLED(WARN)) { \
            openpenny::Logger::log(openpenny::LogLevel::WARN, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

/**
 * @brief ERROR level logging via Logger::log().
 */
#define TCPLOG_ERROR(fmt, ...) \
    do { \
        if (TCPLOG_ENABLED(ERROR)) { \
            openpenny::Logger::log(openpenny::LogLevel::ERROR, fmt, ##__VA_ARGS__); \
        } \
    } while (0)

} // namespace openpenny
