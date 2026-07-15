#pragma once

#include "../memory/function_catalog.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace resolver
{
    struct ObjectLayout
    {
        std::ptrdiff_t owner_id = 0x20;
        std::ptrdiff_t username{};
        std::ptrdiff_t ip{};
        std::ptrdiff_t hwid{};
        std::ptrdiff_t created_at{};
        std::ptrdiff_t last_login{};
        std::ptrdiff_t subscriptions{};
        std::ptrdiff_t response_success{};
        std::ptrdiff_t response_message{};
        std::ptrdiff_t response_paid{};
    };

    struct AuthTargets
    {
        void* load_response{};
        void* check{};
        void* local_auth_valid{};
        void* integrity_check{};
        void* authentication_commit{};
        ObjectLayout layout{};
    };

    class AuthResolver
    {
    public:
        AuthResolver(
            const memory::ProcessImage& image,
            const memory::FunctionCatalog& functions);

        [[nodiscard]] std::optional<AuthTargets> resolve() const;

    private:
        const memory::ProcessImage&    image_;
        const memory::FunctionCatalog& functions_;
    };
}
