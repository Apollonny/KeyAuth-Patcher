#pragma once

#include <Windows.h>
#include <cstdint>
#include <cstring>

namespace api
{
    consteval std::uint32_t fnv1a(const char* str, std::size_t i = 0,
                                   std::uint32_t h = 2166136261u) noexcept
    {
        return str[i] == '\0'
            ? h
            : fnv1a(str, i + 1, (h ^ static_cast<std::uint8_t>(str[i])) * 16777619u);
    }

    [[nodiscard]] inline std::uint32_t fnv1a_rt(const char* str) noexcept
    {
        std::uint32_t h = 2166136261u;
        while (*str)
        {
            h ^= static_cast<std::uint8_t>(*str++);
            h *= 16777619u;
        }
        return h;
    }

    template<typename FnPtr = void*>
    [[nodiscard]] FnPtr resolve(HMODULE module, std::uint32_t target_hash) noexcept
    {
        if (module == nullptr)
            return nullptr;

        const auto* base = reinterpret_cast<const std::uint8_t*>(module);

        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE)
            return nullptr;

        const auto* nt =
            reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;

        const auto& exp_dir =
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (exp_dir.VirtualAddress == 0 || exp_dir.Size == 0)
            return nullptr;

        const auto* exports =
            reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
                base + exp_dir.VirtualAddress);

        const auto* names =
            reinterpret_cast<const DWORD*>(base + exports->AddressOfNames);
        const auto* ordinals =
            reinterpret_cast<const WORD*>(base + exports->AddressOfNameOrdinals);
        const auto* functions =
            reinterpret_cast<const DWORD*>(base + exports->AddressOfFunctions);

        for (DWORD i = 0; i < exports->NumberOfNames; ++i)
        {
            const char* name =
                reinterpret_cast<const char*>(base + names[i]);
            if (fnv1a_rt(name) != target_hash)
                continue;

            const DWORD rva = functions[ordinals[i]];

            if (rva >= exp_dir.VirtualAddress &&
                rva < exp_dir.VirtualAddress + exp_dir.Size)
            {
                return nullptr;
            }

            return reinterpret_cast<FnPtr>(
                const_cast<std::uint8_t*>(base) + rva);
        }

        return nullptr;
    }
}

#define API_HASH(str) (api::fnv1a(str))
