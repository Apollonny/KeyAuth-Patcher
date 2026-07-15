#pragma once

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace memory
{
    struct Section
    {
        std::uint8_t* begin{};
        std::size_t   size{};
        DWORD         characteristics{};

        [[nodiscard]] bool executable() const;
        [[nodiscard]] bool contains(const void* address) const;
    };

    class ProcessImage
    {
    public:
        explicit ProcessImage(HMODULE module = GetModuleHandleW(nullptr));

        [[nodiscard]] bool                              valid() const;
        [[nodiscard]] std::uint8_t*                     base() const;
        [[nodiscard]] std::size_t                       size() const;
        [[nodiscard]] IMAGE_NT_HEADERS64*               headers() const;
        [[nodiscard]] const std::vector<Section>&       sections() const;
        [[nodiscard]] bool                              contains(const void* address) const;
        [[nodiscard]] std::optional<std::uintptr_t>     find_ascii(std::string_view text) const;
        [[nodiscard]] std::vector<std::uintptr_t>       find_all_ascii(std::string_view text) const;

    private:
        std::uint8_t*       base_{};
        std::size_t         size_{};
        IMAGE_NT_HEADERS64* headers_{};
        std::vector<Section> sections_;
    };
}
