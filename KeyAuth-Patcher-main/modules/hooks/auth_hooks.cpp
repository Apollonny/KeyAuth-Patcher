#include "auth_hooks.hpp"

#include "../core/logger.hpp"
#include "../obfuscation/xor_str.hpp"
#include "../watchdog/hook_guard.hpp"

#include <MinHook.h>

namespace
{
    using LoadResponse         = void(__fastcall*)(void*, void*);
    using Check                = void(__fastcall*)(void*, bool);
    using LocalAuthValid       = bool(__fastcall*)(void*, bool);
    using IntegrityCheck       = bool(__fastcall*)(const char*, bool);
    using AuthenticationCommit = void(__fastcall*)(void*);

    LoadResponse         original_load_response{};
    Check                original_check{};
    AuthenticationCommit original_commit{};
    auth::Profile*       active_profile{};

    void* target_load_response{};
    void* target_check{};
    void* target_local_auth{};
    void* target_integrity{};
    void* target_commit{};

    void __fastcall load_response_hook(void* instance, void* json)
    {
        original_load_response(instance, json);
        active_profile->apply_response(instance);
        active_profile->apply_identity(instance);
    }

    void __fastcall check_hook(void* instance, bool paid)
    {
        original_check(instance, paid);
        active_profile->apply_response(instance);
        active_profile->keep_owner_atom(instance);
    }

    bool __fastcall local_auth_hook(void*, bool) { return true; }

    bool __fastcall integrity_hook(const char*, bool) { return false; }

    void __fastcall commit_hook(void* instance)
    {
        original_commit(instance);
        active_profile->apply_response(instance);
        active_profile->apply_identity(instance);
        active_profile->keep_owner_atom(instance);
    }

    template<typename Original, typename Detour>
    bool create(void* target, Detour detour, Original& original, const char* name)
    {
        const MH_STATUS s = MH_CreateHook(
            target,
            reinterpret_cast<void*>(detour),
            reinterpret_cast<void**>(&original));
        logger::write(XS("%s: %s"), name, MH_StatusToString(s));
        return s == MH_OK;
    }

    void remove_hook(void* target, const char* name)
    {
        if (target == nullptr)
            return;
        MH_DisableHook(target);
        const MH_STATUS s = MH_RemoveHook(target);
        logger::write(XS("%s removed: %s"), name, MH_StatusToString(s));
    }
}

bool hooks::install(const resolver::AuthTargets& targets, auth::Profile& profile)
{
    active_profile       = &profile;
    target_load_response = targets.load_response;
    target_check         = targets.check;
    target_local_auth    = targets.local_auth_valid;
    target_integrity     = targets.integrity_check;
    target_commit        = targets.authentication_commit;

    const MH_STATUS init = MH_Initialize();
    if (init != MH_OK && init != MH_ERROR_ALREADY_INITIALIZED)
    {
        logger::write(XS("minhook init: %s"), MH_StatusToString(init));
        return false;
    }

    LocalAuthValid ignored_local{};
    IntegrityCheck ignored_integrity{};

    if (!create(targets.load_response, &load_response_hook, original_load_response, "load_response") ||
        !create(targets.check, &check_hook, original_check, "api_check") ||
        !create(targets.local_auth_valid, &local_auth_hook, ignored_local, "local_auth") ||
        !create(targets.integrity_check, &integrity_hook, ignored_integrity, "integrity") ||
        !create(targets.authentication_commit, &commit_hook, original_commit, "commit"))
    {
        return false;
    }

    const MH_STATUS enabled = MH_EnableHook(MH_ALL_HOOKS);
    logger::write(XS("hooks enabled: %s"), MH_StatusToString(enabled));

    if (enabled != MH_OK)
        return false;

    watchdog::register_hook(targets.load_response,         "load_response");
    watchdog::register_hook(targets.check,                 "api_check");
    watchdog::register_hook(targets.local_auth_valid,      "local_auth");
    watchdog::register_hook(targets.integrity_check,       "integrity");
    watchdog::register_hook(targets.authentication_commit, "commit");

    return true;
}

void hooks::uninstall()
{
    remove_hook(target_load_response, "load_response");
    remove_hook(target_check,         "api_check");
    remove_hook(target_local_auth,    "local_auth");
    remove_hook(target_integrity,     "integrity");
    remove_hook(target_commit,        "commit");

    MH_Uninitialize();
    logger::write(XS("hooks uninstalled"));
}
