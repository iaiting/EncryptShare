#include "IClangAPI.h"

#include "utils/log.h"

SDK_API void LOG_TEST() {
    log_trace("Hello %s", "world");
	log_trace("Enter LOG_TEST:");

    return ;
}