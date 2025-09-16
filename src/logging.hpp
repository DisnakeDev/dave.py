#include <nanobind/nanobind.h>
#include <nanobind/stl/string.h>

#include <dave/logger.h>

namespace nb = nanobind;

int map_logging_level(discord::dave::LoggingSeverity sev) {
    switch (sev) {
        case discord::dave::LoggingSeverity::LS_VERBOSE:
            return 10;
        case discord::dave::LoggingSeverity::LS_INFO:
            return 20;
        case discord::dave::LoggingSeverity::LS_WARNING:
            return 30;
        case discord::dave::LoggingSeverity::LS_ERROR:
            return 40;
        case discord::dave::LoggingSeverity::LS_NONE:
        default:
            return 0;
    }
}

void log_sink(
    discord::dave::LoggingSeverity severity,
    const char* file,
    int line,
    const std::string& message
) {
    nb::gil_scoped_acquire acquire;

    // get logger instance
    // TODO: cache this in a std::atomic or something
    auto logging = nb::module_::import_("logging");
    // TODO: make logger name configurable from python?
    auto logger = logging.attr("getLogger")("libdave");

    // check if level is enabled
    auto level = map_logging_level(severity);
    if (!nb::cast<bool>(logger.attr("isEnabledFor")(level))) {
        return;
    }

    // create + emit LogRecord
    auto record = logger.attr("makeRecord")(
        "libdave",  // name
        level,  // level
        file,  // pathname
        line,  // lineno
        message,  // msg
        nb::tuple(),  // args
        nb::none()  // exc_info
    );
    logger.attr("handle")(record);
}

void init_logging() {
    discord::dave::SetLogSink(log_sink);
}
