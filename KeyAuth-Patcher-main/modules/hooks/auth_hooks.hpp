#pragma once

#include "../auth/profile.hpp"
#include "../resolver/auth_resolver.hpp"

namespace hooks
{
    bool install(const resolver::AuthTargets& targets, auth::Profile& profile);
    void uninstall();
}
