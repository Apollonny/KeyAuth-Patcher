#include "bootstrap.hpp"

#include "../auth/profile.hpp"
#include "../core/logger.hpp"
#include "../hooks/auth_hooks.hpp"
#include "../hooks/process_hooks.hpp"
#include "../identity/system_id.hpp"
#include "../memory/function_catalog.hpp"
#include "../memory/process_image.hpp"
#include "../obfuscation/xor_str.hpp"
#include "../resolver/auth_resolver.hpp"
#include "../watchdog/hook_guard.hpp"

#include <memory>

namespace
{
    std::unique_ptr<auth::Profile> profile;
}

DWORD WINAPI runtime::start(void*)
{
    logger::open();
    identity::init();

    const memory::ProcessImage image;
    if (!image.valid())
    {
        logger::write(XS("image invalid"));
        return 1;
    }

    const memory::FunctionCatalog functions(image);
    logger::write(XS("image ready size=%#zx fns=%zu"),
                  image.size(), functions.functions().size());

    const resolver::AuthResolver resolver(image, functions);
    const auto targets = resolver.resolve();
    if (!targets)
    {
        logger::write(XS("resolve failed"));
        return 2;
    }

    profile = std::make_unique<auth::Profile>(targets->layout);
    if (!profile->ready())
    {
        logger::write(XS("allocator not found"));
        return 3;
    }

    if (!hooks::install(*targets, *profile))
    {
        logger::write(XS("hook install failed"));
        return 4;
    }

    watchdog::start();

    if (!hooks::install_spoof())
        logger::write(XS("spoof failed"));

    logger::write(XS("ready"));
    return 0;
}

void runtime::stop()
{
    logger::write(XS("stopping"));
    watchdog::stop();
    hooks::uninstall_spoof();
    hooks::uninstall();
    profile.reset();
    logger::close();
}
