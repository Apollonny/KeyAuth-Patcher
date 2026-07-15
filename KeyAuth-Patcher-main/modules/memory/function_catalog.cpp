#include "function_catalog.hpp"

#include <algorithm>
#include <cstring>

namespace
{
    std::int32_t read_i32(const std::uint8_t* address)
    {
        std::int32_t value = 0;
        std::memcpy(&value, address, sizeof(value));
        return value;
    }

    std::uint32_t read_u32(const std::uint8_t* address)
    {
        std::uint32_t value = 0;
        std::memcpy(&value, address, sizeof(value));
        return value;
    }

    std::size_t modrm_displacement_offset(
        const std::uint8_t* instruction,
        std::size_t available)
    {
        if (available < 3)
            return 0;

        std::size_t cursor = 0;

        if ((instruction[cursor] & 0xF0) == 0x40)
            ++cursor;

        if (cursor >= available)
            return 0;

        if (instruction[cursor] == 0x0F)
        {
            if (cursor + 2 >= available)
                return 0;
            cursor += 2;
        }
        else
        {
            switch (instruction[cursor])
            {
            case 0x80: case 0x81: case 0x83:
            case 0x88: case 0x89: case 0x8A: case 0x8B: case 0x8D:
            case 0xC6: case 0xC7:
                ++cursor;
                break;
            default:
                return 0;
            }
        }

        if (cursor >= available)
            return 0;

        const std::uint8_t modrm = instruction[cursor++];
        if ((modrm >> 6) != 2)
            return 0;

        if ((modrm & 7) == 4)
        {
            if (cursor >= available)
                return 0;
            ++cursor;
        }

        return cursor + sizeof(std::uint32_t) <= available ? cursor : 0;
    }
}

std::size_t memory::Function::size() const
{
    return static_cast<std::size_t>(end - begin);
}

std::span<const std::uint8_t> memory::Function::bytes() const
{
    return { begin, size() };
}

memory::FunctionCatalog::FunctionCatalog(const ProcessImage& image)
    : image_(image)
{
    if (!image.valid())
        return;

    const auto& directory =
        image.headers()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (directory.VirtualAddress == 0 || directory.Size < sizeof(RUNTIME_FUNCTION))
        return;

    const auto* table = reinterpret_cast<const RUNTIME_FUNCTION*>(
        image.base() + directory.VirtualAddress);
    const std::size_t count = directory.Size / sizeof(RUNTIME_FUNCTION);
    functions_.reserve(count);

    for (std::size_t i = 0; i < count; ++i)
    {
        if (table[i].BeginAddress >= table[i].EndAddress)
            continue;
        functions_.push_back({
            image.base() + table[i].BeginAddress,
            image.base() + table[i].EndAddress
        });
    }

    std::sort(functions_.begin(), functions_.end(), [](const Function& a, const Function& b)
    {
        return a.begin < b.begin;
    });

    functions_.erase(
        std::unique(functions_.begin(), functions_.end(), [](const Function& a, const Function& b)
        {
            return a.begin == b.begin;
        }),
        functions_.end());

    displacement_cache_.reserve(functions_.size());
}

const std::vector<memory::Function>& memory::FunctionCatalog::functions() const
{
    return functions_;
}

std::vector<std::uintptr_t> memory::FunctionCatalog::direct_calls(
    const Function& function) const
{
    std::vector<std::uintptr_t> targets;
    const auto bytes = function.bytes();

    for (std::size_t offset = 0; offset + 5 <= bytes.size(); ++offset)
    {
        if (bytes[offset] != 0xE8)
            continue;

        const auto target =
            reinterpret_cast<std::uintptr_t>(function.begin + offset + 5) +
            read_i32(function.begin + offset + 1);
        if (image_.contains(reinterpret_cast<const void*>(target)))
            targets.push_back(target);
    }

    return targets;
}

bool memory::FunctionCatalog::calls(const Function& function, const void* target) const
{
    const auto wanted  = reinterpret_cast<std::uintptr_t>(target);
    const auto targets = direct_calls(function);
    return std::find(targets.begin(), targets.end(), wanted) != targets.end();
}

std::size_t memory::FunctionCatalog::caller_count(const void* target) const
{
    std::size_t count = 0;
    for (const auto& fn : functions_)
        count += calls(fn, target) ? 1u : 0u;
    return count;
}

bool memory::FunctionCatalog::calls_import(const Function& function, const void* target) const
{
    const auto bytes = function.bytes();

    for (std::size_t offset = 0; offset + 6 <= bytes.size(); ++offset)
    {
        if (bytes[offset] != 0xFF || bytes[offset + 1] != 0x15)
            continue;

        const auto slot_address =
            reinterpret_cast<std::uintptr_t>(function.begin + offset + 6) +
            read_i32(function.begin + offset + 2);
        const auto* slot = reinterpret_cast<const void* const*>(slot_address);
        if (image_.contains(slot) && *slot == target)
            return true;
    }

    return false;
}

bool memory::FunctionCatalog::references(
    const Function& function,
    std::uintptr_t address) const
{
    const auto bytes = function.bytes();

    for (std::size_t offset = 0; offset + 7 <= bytes.size(); ++offset)
    {
        if ((bytes[offset] != 0x48 && bytes[offset] != 0x4C) ||
            bytes[offset + 1] != 0x8D ||
            (bytes[offset + 2] & 0xC7) != 0x05)
        {
            continue;
        }

        const auto target =
            reinterpret_cast<std::uintptr_t>(function.begin + offset + 7) +
            read_i32(function.begin + offset + 3);
        if (target == address)
            return true;
    }

    return false;
}

bool memory::FunctionCatalog::contains(
    const Function& function,
    std::span<const std::uint8_t> bytes) const
{
    if (bytes.empty() || function.size() < bytes.size())
        return false;

    return std::search(
        function.begin, function.end,
        bytes.begin(), bytes.end()) != function.end;
}

const std::vector<std::uint32_t>& memory::FunctionCatalog::member_displacements(
    const Function& function) const
{
    auto it = displacement_cache_.find(function.begin);
    if (it != displacement_cache_.end())
        return it->second;

    auto [pos, ok] = displacement_cache_.emplace(
        function.begin, compute_member_displacements(function));
    return pos->second;
}

std::vector<std::uint32_t> memory::FunctionCatalog::compute_member_displacements(
    const Function& function) const
{
    std::vector<std::uint32_t> values;

    for (std::size_t offset = 0; offset + 8 <= function.size(); ++offset)
    {
        const auto disp =
            modrm_displacement_offset(function.begin + offset, function.size() - offset);
        if (disp == 0)
            continue;

        const auto value = read_u32(function.begin + offset + disp);
        if (value > 0 && value < 0x2000)
            values.push_back(value);
    }

    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}

std::vector<std::uint32_t> memory::FunctionCatalog::zero_qword_compares(
    const Function& function) const
{
    std::vector<std::uint32_t> values;

    for (std::size_t offset = 0; offset + 8 <= function.size(); ++offset)
    {
        const auto* b = function.begin + offset;
        if ((b[0] & 0xF0) != 0x40 || b[1] != 0x83)
            continue;

        const std::uint8_t modrm  = b[2];
        const bool         disp32 = (modrm & 0xC0) == 0x80;
        const bool         cmp    = (modrm & 0x38) == 0x38;
        if (!disp32 || !cmp)
            continue;

        std::size_t displacement = 3;
        if ((modrm & 7) == 4)
            ++displacement;

        if (offset + displacement + 5 > function.size() || b[displacement + 4] != 0)
            continue;

        const auto value = read_u32(b + displacement);
        if (value > 0 && value < 0x2000)
            values.push_back(value);
    }

    std::sort(values.begin(), values.end());
    values.erase(std::unique(values.begin(), values.end()), values.end());
    return values;
}
