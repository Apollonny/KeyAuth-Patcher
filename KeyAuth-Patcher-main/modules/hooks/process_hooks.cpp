#include "process_hooks.hpp"

#include "../core/logger.hpp"
#include "../obfuscation/xor_str.hpp"

#include <MinHook.h>
#include <Windows.h>

namespace
{
    using QueryFullProcessImageNameW_t = BOOL(WINAPI*)(HANDLE, DWORD, PWSTR, PDWORD);
    QueryFullProcessImageNameW_t original_queryfull{};

    HANDLE g_stop_event = nullptr;

    BOOL WINAPI queryfull_hook(HANDLE hProcess, DWORD dwFlags, PWSTR lpExeName, PDWORD lpdwSize)
    {
        if (hProcess == GetCurrentProcess() && dwFlags == 0)
        {
            if (g_stop_event != nullptr)
                WaitForSingleObject(g_stop_event, INFINITE);
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
        return original_queryfull(hProcess, dwFlags, lpExeName, lpdwSize);
    }
}

bool hooks::install_spoof()
{
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (g_stop_event == nullptr)
    {
        logger::write(XS("spoof: event failed (%lu)"), GetLastError());
        return false;
    }

    const auto mod = GetModuleHandleW(L"kernel32.dll");
    if (!mod)
    {
        logger::write(XS("spoof: kernel32 not found"));
        return false;
    }

    const auto target = GetProcAddress(mod, "QueryFullProcessImageNameW");
    if (!target)
    {
        logger::write(XS("spoof: target not found"));
        return false;
    }

    const MH_STATUS init = MH_Initialize();
    if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED)
    {
        logger::write(XS("spoof: minhook: %s"), MH_StatusToString(init));
        return false;
    }

    const MH_STATUS created = MH_CreateHook(
        target,
        reinterpret_cast<void*>(&queryfull_hook),
        reinterpret_cast<void**>(&original_queryfull));

    if (created != MH_OK)
    {
        logger::write(XS("spoof: create: %s"), MH_StatusToString(created));
        return false;
    }

    const MH_STATUS enabled = MH_EnableHook(target);
    logger::write(XS("spoof: %s"), MH_StatusToString(enabled));
    return enabled == MH_OK;
}

void hooks::uninstall_spoof()
{
    if (g_stop_event != nullptr)
    {
        SetEvent(g_stop_event);
        Sleep(50);
    }

    const auto mod = GetModuleHandleW(L"kernel32.dll");
    if (mod)
    {
        const auto target = GetProcAddress(mod, "QueryFullProcessImageNameW");
        if (target)
        {
            MH_DisableHook(target);
            MH_RemoveHook(target);
        }
    }

    if (g_stop_event != nullptr)
    {
        CloseHandle(g_stop_event);
        g_stop_event = nullptr;
    }

    logger::write(XS("spoof: uninstalled"));
}
