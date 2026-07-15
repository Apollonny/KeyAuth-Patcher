#pragma once

#include "../config/config.hpp"

#include <array>
#include <cstdint>

namespace obfuscation
{
    template<std::size_t N>
    struct XorString
    {
        std::array<char, N> data{};

        consteval XorString(const char (&str)[N])
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                const auto k = static_cast<char>(
                    config::obfuscation_key ^ static_cast<uint8_t>(i * 13u));
                data[i] = static_cast<char>(str[i] ^ k);
            }
        }
    };

    template<std::size_t N>
    class XorDecrypt
    {
        char buf_[N]{};

    public:
        constexpr explicit XorDecrypt(const XorString<N>& xs) noexcept
        {
            for (std::size_t i = 0; i < N; ++i)
            {
                const auto k = static_cast<char>(
                    config::obfuscation_key ^ static_cast<uint8_t>(i * 13u));
                buf_[i] = static_cast<char>(xs.data[i] ^ k);
            }
        }

        operator const char*() const noexcept { return buf_; }
        const char* c_str()    const noexcept { return buf_; }
    };
}

#define XS(str) \
    (obfuscation::XorDecrypt<sizeof(str)>{ \
        []() consteval -> obfuscation::XorString<sizeof(str)> { \
            return obfuscation::XorString<sizeof(str)>{ str }; \
        }() \
    })
