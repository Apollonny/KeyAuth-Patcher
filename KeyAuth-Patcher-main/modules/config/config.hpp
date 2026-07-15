#pragma once

#include <cstdint>

namespace config
{
    inline constexpr std::uint8_t obfuscation_key = 0xA7;

    inline constexpr const char* username         = "User";

    struct SubscriptionEntry
    {
        const char* name;
        const char* expiry;
    };

    inline constexpr SubscriptionEntry subscriptions[] = {
        { "default", "9999999999" },
    };

    inline constexpr const char* response_message = "Authenticated";

    inline constexpr bool          log_to_file   = true;
    inline constexpr const wchar_t* log_filename  = L"keyauth_patch.log";
    inline constexpr bool          show_console  = false;
    inline constexpr const wchar_t* console_title = L"Debug Output";
}
