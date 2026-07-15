#pragma once

#include <cstddef>

namespace watchdog
{
    void register_hook(void* target, const char* name);
    void start();
    void stop();
}
