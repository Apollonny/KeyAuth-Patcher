#pragma once

namespace logger
{
    void open();
    void close();
    void write(const char* format, ...);
}
