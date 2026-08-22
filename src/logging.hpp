#pragma once

#include <dave/logger.h>

#include "binding_core.hpp"

namespace nb = nanobind;

int map_logging_level(discord::dave::LoggingSeverity sev) {
    switch (sev) {
        case discord::dave::LoggingSeverity::LS_VERBOSE:
            return 10;  // logging.DEBUG
        case discord::dave::LoggingSeverity::LS_INFO:
            // n.b. this is not a typo.
            // libdave's INFO logs are rather verbose (the LS_VERBOSE level is barely used),
            // so just turn them into debug logs.
            return 10;  // logging.DEBUG
        case discord::dave::LoggingSeverity::LS_WARNING:
            return 30;  // logging.WARNING
        case discord::dave::LoggingSeverity::LS_ERROR:
            return 40;  // logging.ERROR
        case discord::dave::LoggingSeverity::LS_NONE:
        default:
            return 0;
    }
}

void log_sink(
    discord::dave::LoggingSeverity severity, const char* file, int line, const std::string& message
) {
    nb::gil_scoped_acquire guard;
    if (!guard.is_valid()) return;

    // get logger instance
    auto logging = nb::module_::import_("logging");
    auto logger = logging.attr("getLogger")("dave");

    // check if level is enabled
    auto level = map_logging_level(severity);
    if (!nb::cast<bool>(logger.attr("isEnabledFor")(level))) {
        return;
    }

    // create + emit LogRecord
    auto record = logger.attr("makeRecord")(
        "dave",       // name
        level,        // level
        file,         // pathname
        line,         // lineno
        message,      // msg
        nb::tuple(),  // args
        nb::none()    // exc_info
    );
    logger.attr("handle")(record);
}

void init_logging() { discord::dave::SetLogSink(log_sink); }
