#include "auth_resolver.hpp"

#include "../core/logger.hpp"
#include "../obfuscation/xor_str.hpp"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <limits>
#include <string_view>
#include <vector>

namespace
{
    struct Candidate
    {
        const memory::Function* function{};
        int score{};
    };

    bool has_value(const std::vector<std::uint32_t>& values, std::uint32_t value)
    {
        return std::binary_search(values.begin(), values.end(), value);
    }

    std::optional<std::array<std::uint32_t, 3>> find_response_layout(
        const std::vector<std::uint32_t>& values)
    {
        for (const auto success : values)
        {
            if (has_value(values, success + 8) && has_value(values, success + 40))
                return std::array{ success, success + 8, success + 40 };
        }
        return std::nullopt;
    }

    std::optional<std::array<std::uint32_t, 3>> find_auth_seal_layout(
        const std::vector<std::uint32_t>& values,
        std::uint32_t after)
    {
        std::optional<std::array<std::uint32_t, 3>> result;
        for (const auto first : values)
        {
            if (first <= after)
                continue;
            if (has_value(values, first + 8) && has_value(values, first + 16))
                result = std::array{ first, first + 8, first + 16 };
        }
        return result;
    }

    bool contains_u32(
        const memory::FunctionCatalog& functions,
        const memory::Function& function,
        std::uint32_t value)
    {
        const std::array<std::uint8_t, 4> bytes{
            static_cast<std::uint8_t>(value),
            static_cast<std::uint8_t>(value >> 8),
            static_cast<std::uint8_t>(value >> 16),
            static_cast<std::uint8_t>(value >> 24)
        };
        return functions.contains(function, bytes);
    }

    const memory::Function* choose(
        std::vector<Candidate> candidates,
        const char* label,
        int minimum_score,
        int minimum_margin = 2)
    {
        std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b)
        {
            return a.score > b.score;
        });

        const std::size_t shown = (std::min)(std::size_t{ 3 }, candidates.size());
        for (std::size_t i = 0; i < shown; ++i)
        {
            logger::write(XS("%s #%zu: %p score=%d size=%zu"),
                label, i + 1,
                candidates[i].function->begin,
                candidates[i].score,
                candidates[i].function->size());
        }

        if (candidates.empty() || candidates.front().score < minimum_score)
        {
            logger::write(XS("%s: below threshold"), label);
            return nullptr;
        }

        if (candidates.size() > 1 &&
            candidates.front().score - candidates[1].score < minimum_margin)
        {
            logger::write(XS("%s: ambiguous"), label);
            return nullptr;
        }

        logger::write(XS("%s: %p"), label, candidates.front().function->begin);
        return candidates.front().function;
    }

    void* imported(const wchar_t* module_name, const char* function_name)
    {
        const HMODULE mod = GetModuleHandleW(module_name);
        return mod == nullptr
            ? nullptr
            : reinterpret_cast<void*>(GetProcAddress(mod, function_name));
    }
}

resolver::AuthResolver::AuthResolver(
    const memory::ProcessImage& image,
    const memory::FunctionCatalog& functions)
    : image_(image),
      functions_(functions)
{
}

std::optional<resolver::AuthTargets> resolver::AuthResolver::resolve() const
{
    static constexpr std::array<std::uint8_t, 4> success_chunk{ 0x73, 0x75, 0x63, 0x63 };
    static constexpr std::array<std::uint8_t, 4> role_chunk   { 0x72, 0x6F, 0x6C, 0x65 };
    static constexpr std::array<std::uint8_t, 4> tester_chunk { 0x74, 0x65, 0x73, 0x74 };
    static constexpr std::array<std::uint8_t, 4> not_chunk    { 0x6E, 0x6F, 0x74, 0x5F };
    static constexpr std::array<std::uint8_t, 4> checked_chunk{ 0x63, 0x68, 0x65, 0x63 };

    const auto message_strings = image_.find_all_ascii("message");
    std::vector<Candidate> response_candidates;

    for (const auto& function : functions_.functions())
    {
        if (function.size() < 80 || function.size() > 3000)
            continue;

        int score = 0;
        score += functions_.contains(function, success_chunk) ? 4 : 0;
        score += functions_.contains(function, role_chunk)    ? 5 : 0;
        score += functions_.contains(function, tester_chunk)  ? 5 : 0;
        score += functions_.contains(function, not_chunk)     ? 4 : 0;
        score += functions_.contains(function, checked_chunk) ? 4 : 0;

        const bool refs_message = std::any_of(
            message_strings.begin(), message_strings.end(),
            [&function, this](std::uintptr_t address)
            {
                return functions_.references(function, address);
            });
        score += refs_message ? 6 : 0;

        const auto& displacements = functions_.member_displacements(function);
        const bool  has_layout    = find_response_layout(displacements).has_value();
        score += has_layout ? 20 : 0;

        if (has_layout)
        {
            const std::size_t callers = functions_.caller_count(function.begin);
            score += static_cast<int>((std::min)(callers, std::size_t{ 10 }) * 3);
        }

        if (score > 0)
            response_candidates.push_back({ &function, score });
    }

    const auto* response = choose(std::move(response_candidates), "load_response", 23, 3);
    if (response == nullptr)
        return std::nullopt;

    const auto response_fields =
        find_response_layout(functions_.member_displacements(*response));
    if (!response_fields)
    {
        logger::write(XS("response layout failed"));
        return std::nullopt;
    }

    ObjectLayout layout{};
    layout.response_success = (*response_fields)[0];
    layout.response_message = (*response_fields)[1];
    layout.response_paid    = (*response_fields)[2];

    std::vector<Candidate> local_candidates;
    for (const auto& function : functions_.functions())
    {
        if (function.size() < 40 || function.size() > 800)
            continue;

        const auto& displacements   = functions_.member_displacements(function);
        const auto  zero_compares   = functions_.zero_qword_compares(function);

        const bool has_user_check = std::any_of(
            zero_compares.begin(), zero_compares.end(),
            [&layout](std::uint32_t v)
            {
                return v >= 0x10 && v < static_cast<std::uint32_t>(layout.response_success);
            });
        const bool has_session_check = std::any_of(
            zero_compares.begin(), zero_compares.end(),
            [&layout](std::uint32_t v)
            {
                return v > static_cast<std::uint32_t>(layout.response_paid);
            });
        const bool has_paid_ref =
            has_value(displacements, static_cast<std::uint32_t>(layout.response_paid)) ||
            contains_u32(functions_, function, static_cast<std::uint32_t>(layout.response_paid));

        int score = 0;
        score += has_paid_ref     ? 12 : 0;
        score += zero_compares.size() >= 2 ? 8 : 0;
        score += has_user_check   ?  6 : 0;
        score += has_session_check ?  6 : 0;
        score += find_auth_seal_layout(displacements,
            static_cast<std::uint32_t>(layout.response_paid)) ? 10 : 0;
        score += function.size() < 400 ? 2 : 0;

        if (score > 0)
            local_candidates.push_back({ &function, score });
    }

    const auto* local_auth = choose(std::move(local_candidates), "local_auth", 32, 5);
    if (local_auth == nullptr)
        return std::nullopt;

    const auto zero_compares = functions_.zero_qword_compares(*local_auth);
    const auto username_size = std::find_if(
        zero_compares.begin(), zero_compares.end(),
        [&layout](std::uint32_t v)
        {
            return v >= 0x10 && v < static_cast<std::uint32_t>(layout.response_success);
        });

    if (username_size == zero_compares.end())
    {
        logger::write(XS("username layout failed"));
        return std::nullopt;
    }

    layout.username      = *username_size - 0x10;
    layout.ip            = layout.username + 0x20;
    layout.hwid          = layout.username + 0x40;
    layout.created_at    = layout.username + 0x60;
    layout.last_login    = layout.username + 0x80;
    layout.subscriptions = layout.username + 0xA0;

    const auto seal_fields = find_auth_seal_layout(
        functions_.member_displacements(*local_auth),
        static_cast<std::uint32_t>(layout.response_paid));
    if (!seal_fields)
    {
        logger::write(XS("seal layout failed"));
        return std::nullopt;
    }

    std::vector<Candidate> check_candidates;
    for (const auto& function : functions_.functions())
    {
        int score = 0;
        score += functions_.calls(function, response->begin)   ? 12 : 0;
        score += functions_.calls(function, local_auth->begin) ? 14 : 0;

        const auto& displacements = functions_.member_displacements(function);
        score += has_value(displacements, static_cast<std::uint32_t>(layout.response_success)) ? 3 : 0;
        score += has_value(displacements, static_cast<std::uint32_t>(layout.response_paid))    ? 3 : 0;

        if (score > 0)
            check_candidates.push_back({ &function, score });
    }

    const auto* check = choose(std::move(check_candidates), "api_check", 26, 4);
    if (check == nullptr)
        return std::nullopt;

    const void* query_image_name = imported(L"kernel32.dll", "QueryFullProcessImageNameW");
    const void* create_file      = imported(L"kernel32.dll", "CreateFileW");
    const void* create_mapping   = imported(L"kernel32.dll", "CreateFileMappingW");
    const void* map_view         = imported(L"kernel32.dll", "MapViewOfFile");
    const void* virtual_protect  = imported(L"kernel32.dll", "VirtualProtect");

    std::vector<Candidate> integrity_candidates;
    for (const auto& function : functions_.functions())
    {
        int score = 0;
        score += query_image_name && functions_.calls_import(function, query_image_name) ? 5 : 0;
        score += create_file      && functions_.calls_import(function, create_file)      ? 5 : 0;
        score += create_mapping   && functions_.calls_import(function, create_mapping)   ? 5 : 0;
        score += map_view         && functions_.calls_import(function, map_view)         ? 5 : 0;
        score += virtual_protect  && functions_.calls_import(function, virtual_protect)  ? 4 : 0;

        if (score > 0)
            integrity_candidates.push_back({ &function, score });
    }

    const auto* integrity = choose(std::move(integrity_candidates), "integrity", 18, 4);
    if (integrity == nullptr)
        return std::nullopt;

    std::vector<const memory::Function*> response_callers;
    for (const auto& function : functions_.functions())
    {
        if (functions_.calls(function, response->begin))
            response_callers.push_back(&function);
    }

    std::vector<Candidate> commit_candidates;
    for (const auto& function : functions_.functions())
    {
        const auto& displacements = functions_.member_displacements(function);
        int score = 0;
        score += has_value(displacements, (*seal_fields)[0]) ? 5 : 0;
        score += has_value(displacements, (*seal_fields)[1]) ? 5 : 0;
        score += has_value(displacements, (*seal_fields)[2]) ? 5 : 0;

        std::size_t auth_caller_count = 0;
        for (const auto* caller : response_callers)
            auth_caller_count += functions_.calls(*caller, function.begin) ? 1u : 0u;

        score += static_cast<int>((std::min)(auth_caller_count, std::size_t{ 4 }) * 5);
        if (function.size() >= 50 && function.size() <= 1500)
            score += 2;

        if (score > 0)
            commit_candidates.push_back({ &function, score });
    }

    const auto* commit = choose(std::move(commit_candidates), "commit", 25, 3);
    if (commit == nullptr)
        return std::nullopt;

    logger::write(XS("layout: user=%#tx subs=%#tx resp={%#tx,%#tx,%#tx}"),
        layout.username, layout.subscriptions,
        layout.response_success, layout.response_message, layout.response_paid);

    return AuthTargets{
        response->begin,
        check->begin,
        local_auth->begin,
        integrity->begin,
        commit->begin,
        layout
    };
}
