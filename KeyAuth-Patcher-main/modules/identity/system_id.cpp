#include "system_id.hpp"

#include "../core/logger.hpp"
#include "../obfuscation/xor_str.hpp"

#include <Windows.h>
#include <iphlpapi.h>

#include <cstdio>
#include <cstdint>
#include <cstring>

namespace
{
    char g_hwid[64]{};
    char g_ip[46]{};
    char g_last_login[24]{};
    char g_created_at[24]{};
    bool g_init = false;

    DWORD volume_serial()
    {
        DWORD serial = 0;
        char root[4] = { 'C', ':', '\\', '\0' };
        char win[MAX_PATH]{};
        if (GetWindowsDirectoryA(win, MAX_PATH) > 0)
            root[0] = win[0];
        GetVolumeInformationA(root, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0);
        return serial;
    }

    std::uint32_t machine_guid_hash()
    {
        HKEY key = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                          "SOFTWARE\\Microsoft\\Cryptography",
                          0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS)
        {
            return 0xDEADBEEF;
        }

        char guid[64]{};
        DWORD size = sizeof(guid);
        DWORD type = REG_SZ;
        const LSTATUS st = RegQueryValueExA(key, "MachineGuid", nullptr, &type,
                                            reinterpret_cast<LPBYTE>(guid), &size);
        RegCloseKey(key);

        if (st != ERROR_SUCCESS)
            return 0xCAFEBABE;

        std::uint32_t h = 2166136261u;
        for (char* p = guid; *p; ++p) { h ^= static_cast<std::uint8_t>(*p); h *= 16777619u; }
        return h;
    }

    void build_hwid()
    {
        const DWORD     serial = volume_serial();
        const uint32_t  guid_h = machine_guid_hash();
        const uint32_t  mixed  = (serial ^ guid_h) * 2654435761u;
        std::snprintf(g_hwid, sizeof(g_hwid), "%08X-%08X-%08X", serial, guid_h, mixed);
    }

    void build_ip()
    {
        std::snprintf(g_ip, sizeof(g_ip), "127.0.0.1");

        std::uint8_t buf[16384]{};
        ULONG size = sizeof(buf);
        auto* info = reinterpret_cast<IP_ADAPTER_INFO*>(buf);

        if (GetAdaptersInfo(info, &size) != ERROR_SUCCESS)
            return;

        for (const auto* a = info; a; a = a->Next)
        {
            if (a->Type == MIB_IF_TYPE_LOOPBACK)
                continue;
            const char* addr = a->IpAddressList.IpAddress.String;
            if (addr && std::strcmp(addr, "0.0.0.0") != 0)
            {
                std::snprintf(g_ip, sizeof(g_ip), "%s", addr);
                break;
            }
        }
    }

    std::int64_t unix_now()
    {
        FILETIME ft{};
        GetSystemTimeAsFileTime(&ft);
        ULARGE_INTEGER li{};
        li.LowPart  = ft.dwLowDateTime;
        li.HighPart = ft.dwHighDateTime;
        return static_cast<std::int64_t>(li.QuadPart / 10000000ULL - 11644473600ULL);
    }

    std::int64_t created_from_hwid(std::int64_t now)
    {
        std::uint32_t h = 2166136261u;
        for (const char* p = g_hwid; *p; ++p) { h ^= static_cast<std::uint8_t>(*p); h *= 16777619u; }
        return now - static_cast<std::int64_t>(30 + h % 1050u) * 86400LL;
    }
}

void identity::init()
{
    if (g_init)
        return;

    build_hwid();
    build_ip();

    const std::int64_t now = unix_now();
    std::snprintf(g_last_login, sizeof(g_last_login), "%I64d", now);
    std::snprintf(g_created_at, sizeof(g_created_at), "%I64d", created_from_hwid(now));

    g_init = true;

    // Never write hardware identifiers or local network addresses to logs.
    logger::write(XS("identity initialized"));
}

const char* identity::hwid()       { return g_hwid;       }
const char* identity::ip()         { return g_ip;         }
const char* identity::last_login() { return g_last_login; }
const char* identity::created_at() { return g_created_at; }
