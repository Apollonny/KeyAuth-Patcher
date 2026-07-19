#include "hook_guard.hpp"

#include "../core/logger.hpp"
#include "../obfuscation/xor_str.hpp"

#include <MinHook.h>
#include <Windows.h>

#include <cstring>
#include <vector>

namespace
{
    constexpr std::size_t snapshot_size  = 14;
    constexpr DWORD       check_interval = 2000;

    struct WatchEntry
    {
        void*   target{};
        uint8_t expected[snapshot_size]{};
        char    name[64]{};
    };

    std::vector<WatchEntry> g_entries;
    HANDLE                  g_stop_event = nullptr;
    HANDLE                  g_thread     = nullptr;

    bool safe_read(const void* src, uint8_t* dst, std::size_t n)
    {
        __try
        {
            std::memcpy(dst, src, n);
            return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return false;
        }
    }

    void snapshot(WatchEntry& entry)
    {
        safe_read(entry.target, entry.expected, snapshot_size);
    }

    void restore_hook(WatchEntry& entry)
    {
        logger::write(XS("watchdog: tamper — %s"), entry.name);
        MH_DisableHook(entry.target);
        const MH_STATUS s = MH_EnableHook(entry.target);
        if (s == MH_OK)
        {
            snapshot(entry);
            logger::write(XS("watchdog: restored — %s"), entry.name);
        }
        else
        {
            logger::write(XS("watchdog: restore failed — %s (%s)"), entry.name, MH_StatusToString(s));
        }
    }

    DWORD WINAPI watchdog_thread(void*)
    {
        logger::write(XS("watchdog: running, %zu hooks"), g_entries.size());

        for (;;)
        {
            if (WaitForSingleObject(g_stop_event, check_interval) == WAIT_OBJECT_0)
                break;

            for (auto& entry : g_entries)
            {
                uint8_t current[snapshot_size]{};
                if (!safe_read(entry.target, current, snapshot_size))
                    continue;
                if (std::memcmp(current, entry.expected, snapshot_size) != 0)
                    restore_hook(entry);
            }
        }

        logger::write(XS("watchdog: exit"));
        return 0;
    }
}

void watchdog::register_hook(void* target, const char* name)
{
    if (target == nullptr)
        return;

    WatchEntry entry{};
    entry.target = target;
    std::strncpy(entry.name, name ? name : "", sizeof(entry.name) - 1);
    snapshot(entry);
    g_entries.push_back(entry);

    logger::write(XS("watchdog: +%s"), entry.name);
}

void watchdog::start()
{
    if (g_stop_event != nullptr || g_entries.empty())
        return;

    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_stop_event == nullptr)
    {
        logger::write(XS("watchdog: event failed (%lu)"), GetLastError());
        return;
    }

    g_thread = CreateThread(nullptr, 0, watchdog_thread, nullptr, 0, nullptr);
    if (g_thread == nullptr)
    {
        logger::write(XS("watchdog: thread failed (%lu)"), GetLastError());
        CloseHandle(g_stop_event);
        g_stop_event = nullptr;
    }
}

void watchdog::stop()
{
    if (g_stop_event == nullptr)
        return;

    SetEvent(g_stop_event);

    if (g_thread != nullptr)
    {
        WaitForSingleObject(g_thread, 3000);
        CloseHandle(g_thread);
        g_thread = nullptr;
    }

    CloseHandle(g_stop_event);
    g_stop_event = nullptr;
    g_entries.clear();

    logger::write(XS("watchdog: stopped"));
}
