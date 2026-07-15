#pragma once

#include "process_image.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <unordered_map>
#include <vector>

namespace memory
{
    struct Function
    {
        std::uint8_t* begin{};
        std::uint8_t* end{};

        [[nodiscard]] std::size_t size() const;
        [[nodiscard]] std::span<const std::uint8_t> bytes() const;
    };

    class FunctionCatalog
    {
    public:
        explicit FunctionCatalog(const ProcessImage& image);

        [[nodiscard]] const std::vector<Function>&            functions() const;
        [[nodiscard]] std::vector<std::uintptr_t>             direct_calls(const Function& function) const;
        [[nodiscard]] bool                                    calls(const Function& function, const void* target) const;
        [[nodiscard]] std::size_t                             caller_count(const void* target) const;
        [[nodiscard]] bool                                    calls_import(const Function& function, const void* target) const;
        [[nodiscard]] bool                                    references(const Function& function, std::uintptr_t address) const;
        [[nodiscard]] bool                                    contains(const Function& function, std::span<const std::uint8_t> bytes) const;
        [[nodiscard]] const std::vector<std::uint32_t>&       member_displacements(const Function& function) const;
        [[nodiscard]] std::vector<std::uint32_t>              zero_qword_compares(const Function& function) const;

    private:
        [[nodiscard]] std::vector<std::uint32_t> compute_member_displacements(const Function& function) const;

        const ProcessImage&  image_;
        std::vector<Function> functions_;
        mutable std::unordered_map<const std::uint8_t*, std::vector<std::uint32_t>> displacement_cache_;
    };
}
