#pragma once

#include "../resolver/auth_resolver.hpp"

namespace auth
{
    class Profile
    {
    public:
        explicit Profile(resolver::ObjectLayout layout);

        [[nodiscard]] bool ready() const;

        void apply_response(void* instance) const;
        void apply_identity(void* instance) const;
        void keep_owner_atom(void* instance) const;

    private:
        using Malloc = void* (__cdecl*)(std::size_t);

        bool write_string(void* object, const char* value, const char* field) const;
        bool initialize_small_string(void* object, const char* value) const;
        void apply_subscriptions(void* instance) const;

        resolver::ObjectLayout layout_{};
        Malloc                 allocate_{};
    };
}
