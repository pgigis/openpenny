// SPDX-License-Identifier: BSD-2-Clause

#include "openpenny/log/Log.h"

#include <algorithm>
#include <ctime>
#include <cstdio>
#include <cstring>
#include <atomic>

namespace openpenny {

// Global mutex to prevent interleaved printing between threads
std::mutex Logger::mtx_{};

// Global logging level stored as an integer (atomic for fast filtering)
std::atomic<int> Logger::level_{static_cast<int>(LogLevel::DEBUG)};

// Current output mode (console, file, or silent)
LogMode Logger::mode_ = LogMode::Console;

// File pointer for appending logs when File mode is enabled
FILE* Logger::file_ = nullptr;

/**
 * Initialise the logger.
 * This sets the minimum log level and configures the output backend.
 * If file mode is requested but the file cannot open, we fall back to stderr.
 */
void Logger::init(const LoggerConfig& cfg) {
    std::lock_guard<std::mutex> lk(mtx_);

    // Make stdout unbuffered so logs show up immediately when debugging
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    // Set the global minimum log level (relaxed ordering is fine here)
    level_.store(static_cast<int>(cfg.level), std::memory_order_relaxed);

    // Set output mode (console / file / silent)
    mode_ = cfg.mode;

    // If a log file was used before, close it cleanly
    if (file_) {
        std::fclose(file_);
        file_ = nullptr;
    }

    // Try to open the new log file if File mode is requested
    if (mode_ == LogMode::File) {
        file_ = std::fopen(cfg.file_path.c_str(), "a");
        if (!file_) {
            // Failed to open → revert to console logging via stderr
            mode_ = LogMode::Console;
        }
    }
}

/**
 * Change minimum log level without touching the backend.
 * This is atomic, so safe to call at runtime.
 */
void Logger::set_level(LogLevel lvl) {
    level_.store(static_cast<int>(lvl), std::memory_order_relaxed);
}

/**
 * Read the current minimum log level.
 * Used when making filtering decisions.
 */
LogLevel Logger::level() {
    return static_cast<LogLevel>(level_.load(std::memory_order_relaxed));
}

/**
 * Convert a log level enum into a string.
 * No padding or extra spaces are added.
 * This function is only used for printing the human log level label.
 */
const char* Logger::level_str(LogLevel lvl) {
    switch (lvl) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO";
        case LogLevel::WARN:  return "WARN";
        case LogLevel::ERROR: return "ERROR";
    }
    return "?"; // fallback for unknown enum path
}

static const char* level_color(LogLevel lvl) {
    switch (lvl) {
        case LogLevel::TRACE: return "\033[37m"; // white
        case LogLevel::DEBUG: return "\033[36m"; // cyan
        case LogLevel::INFO:  return "\033[32m"; // green
        case LogLevel::WARN:  return "\033[33m"; // yellow
        case LogLevel::ERROR: return "\033[31m"; // red
    }
    return "\033[0m";
}

/**
 * Log a formatted line if the severity is ≥ global minimum level.
 * This is the main entry point (called by macros).
 */
void Logger::log(LogLevel lvl, const char* fmt, ...) {
    // Fast path filter: skip log if below the active threshold
    if (static_cast<int>(lvl) < level_.load(std::memory_order_relaxed)) {
        return;
    }

    // Start printing, forward to `vlog`
    va_list ap;
    va_start(ap, fmt);
    vlog(lvl, fmt, ap);
    va_end(ap);
}

/**
 * Render and print a single log line.
 * Thread-safe: timestamp + formatted message + newline.
 * Output is sent to the active file if available, otherwise stderr.
 */
void Logger::vlog(LogLevel lvl, const char* fmt, va_list ap) {
    // Do nothing if Silent mode is explicitly selected
    if (mode_ == LogMode::Silent) {
        return;
    }

    // Choose file target if File mode and open succeeded, otherwise stderr
    FILE* out = (mode_ == LogMode::File && file_) ? file_ : stderr;

    // Create current local timestamp in the form: YYYY-MM-DD HH:MM:SS
    std::time_t t = std::time(nullptr);
    std::tm tm{};

#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif

    char ts[32];
    const int year = std::clamp(tm.tm_year + 1900, 0, 9999);
    const int mon  = std::clamp(tm.tm_mon + 1,     1,   12);
    const int day  = std::clamp(tm.tm_mday,        0,   31);
    const int hour = std::clamp(tm.tm_hour,        0,   23);
    const int min  = std::clamp(tm.tm_min,         0,   59);
    const int sec  = std::clamp(tm.tm_sec,         0,   59);

    std::snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d",
                  year, mon, day, hour, min, sec);

    // Lock to avoid mixed writes from different threads
    std::lock_guard<std::mutex> lk(mtx_);

    const char* color = (mode_ == LogMode::Console) ? level_color(lvl) : "";
    const char* reset = (mode_ == LogMode::Console) ? "\033[0m" : "";

    // Print `[INFO]`, `[DEBUG]`, etc once, no extra whitespace
    std::fprintf(out, "%s %s[%s]%s ", ts, color, level_str(lvl), reset);

    // Print actual formatted message
    std::vfprintf(out, fmt, ap);

    // Add newline if the log call format string did not include one
    const std::size_t len = std::strlen(fmt);
    if (len == 0 || fmt[len - 1] != '\n') {
        std::fputc('\n', out);
    }

    // Flush immediately so logs are not stuck in buffers during debugging
    std::fflush(out);
}

} // namespace openpenny
