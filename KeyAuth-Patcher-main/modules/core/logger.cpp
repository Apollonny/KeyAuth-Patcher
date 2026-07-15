#include "logger.hpp"

#include "../config/config.hpp"
#include "../obfuscation/xor_str.hpp"

#include <Windows.h>

#include <cstdarg>
#include <cstdio>
#include <cstring>

namespace
{
    HANDLE           g_console  = INVALID_HANDLE_VALUE;
    HANDLE           g_log_file = INVALID_HANDLE_VALUE;
    CRITICAL_SECTION g_lock{};
    bool             g_lock_init = false;

    bool build_log_path(wchar_t* out, DWORD cap)
    {
        const DWORD len = GetTempPathW(cap, out);
        if (len == 0 || len >= cap)
            return false;
        const std::size_t name_len = std::wcslen(config::log_filename);
        if (len + name_len >= cap)
            return false;
        std::wcscpy(out + len, config::log_filename);
        return true;
    }

    void emit(HANDLE h, const char* text, DWORD length)
    {
        if (h == INVALID_HANDLE_VALUE)
            return;
        DWORD written = 0;
        WriteFile(h, text, length, &written, nullptr);
    }
}

void logger::open()
{
    if (!g_lock_init)
    {
        InitializeCriticalSection(&g_lock);
        g_lock_init = true;
    }

    if constexpr (config::show_console)
    {
        if (GetConsoleWindow() == nullptr)
            AllocConsole();
        SetConsoleTitleW(config::console_title);
        g_console = CreateFileW(L"CONOUT$",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, 0, nullptr);
    }

    if constexpr (config::log_to_file)
    {
        wchar_t path[MAX_PATH]{};
        if (build_log_path(path, MAX_PATH))
        {
            g_log_file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ,
                nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (g_log_file != INVALID_HANDLE_VALUE)
                SetFilePointer(g_log_file, 0, nullptr, FILE_END);
        }
    }

    write(XS("init"));
}

void logger::close()
{
    write(XS("shutdown"));

    if (g_log_file != INVALID_HANDLE_VALUE)
    {
        FlushFileBuffers(g_log_file);
        CloseHandle(g_log_file);
        g_log_file = INVALID_HANDLE_VALUE;
    }

    if (g_console != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_console);
        g_console = INVALID_HANDLE_VALUE;
    }

    if constexpr (config::show_console)
        FreeConsole();

    if (g_lock_init)
    {
        DeleteCriticalSection(&g_lock);
        g_lock_init = false;
    }
}

void logger::write(const char* format, ...)
{
    char msg[2048]{};
    va_list args;
    va_start(args, format);
    std::vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);

    SYSTEMTIME t{};
    GetLocalTime(&t);

    char line[2304]{};
    const int n = std::snprintf(
        line, sizeof(line),
        "[%02u:%02u:%02u.%03u] [T%lu] %s\r\n",
        t.wHour, t.wMinute, t.wSecond, t.wMilliseconds,
        GetCurrentThreadId(), msg);

    if (n <= 0)
        return;

    const DWORD len = static_cast<DWORD>(n);

    if (g_lock_init) EnterCriticalSection(&g_lock);
    emit(g_console,  line, len);
    emit(g_log_file, line, len);
    OutputDebugStringA(line);
    if (g_lock_init) LeaveCriticalSection(&g_lock);
}
