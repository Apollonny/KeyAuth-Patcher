#include "process_image.hpp"

#include <algorithm>
#include <cstring>

bool memory::Section::executable() const
{
    return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
}

bool memory::Section::contains(const void* address) const
{
    const auto value = reinterpret_cast<std::uintptr_t>(address);
    const auto first = reinterpret_cast<std::uintptr_t>(begin);
    return value >= first && value < first + size;
}

memory::ProcessImage::ProcessImage(HMODULE module)
{
    base_ = reinterpret_cast<std::uint8_t*>(module);
    if (base_ == nullptr)
        return;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base_);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        base_ = nullptr;
        return;
    }

    headers_ = reinterpret_cast<IMAGE_NT_HEADERS64*>(base_ + dos->e_lfanew);
    if (headers_->Signature != IMAGE_NT_SIGNATURE ||
        headers_->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        base_ = nullptr;
        headers_ = nullptr;
        return;
    }

    size_ = headers_->OptionalHeader.SizeOfImage;
    auto* section = IMAGE_FIRST_SECTION(headers_);
    sections_.reserve(headers_->FileHeader.NumberOfSections);

    for (WORD index = 0; index < headers_->FileHeader.NumberOfSections; ++index, ++section)
    {
        sections_.push_back({
            base_ + section->VirtualAddress,
            static_cast<std::size_t>(section->Misc.VirtualSize),
            section->Characteristics
        });
    }
}

bool memory::ProcessImage::valid() const
{
    return base_ != nullptr && headers_ != nullptr;
}

std::uint8_t* memory::ProcessImage::base() const
{
    return base_;
}

std::size_t memory::ProcessImage::size() const
{
    return size_;
}

IMAGE_NT_HEADERS64* memory::ProcessImage::headers() const
{
    return headers_;
}

const std::vector<memory::Section>& memory::ProcessImage::sections() const
{
    return sections_;
}

bool memory::ProcessImage::contains(const void* address) const
{
    if (!valid())
        return false;

    const auto value = reinterpret_cast<std::uintptr_t>(address);
    const auto first = reinterpret_cast<std::uintptr_t>(base_);
    return value >= first && value < first + size_;
}

std::optional<std::uintptr_t> memory::ProcessImage::find_ascii(std::string_view text) const
{
    const auto matches = find_all_ascii(text);
    return matches.empty()
        ? std::nullopt
        : std::optional<std::uintptr_t>{ matches.front() };
}

std::vector<std::uintptr_t> memory::ProcessImage::find_all_ascii(std::string_view text) const
{
    std::vector<std::uintptr_t> matches;
    if (text.empty())
        return matches;

    for (const auto& section : sections_)
    {
        if (section.executable() || section.size < text.size())
            continue;

        const auto* cursor = section.begin;
        const auto* end = section.begin + section.size;
        while (cursor + text.size() <= end)
        {
            const auto* found = std::search(cursor, end, text.begin(), text.end());
            if (found == end)
                break;

            matches.push_back(reinterpret_cast<std::uintptr_t>(found));
            cursor = found + text.size();
        }
    }

    return matches;
}
