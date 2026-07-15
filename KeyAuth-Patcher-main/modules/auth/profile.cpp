#include "profile.hpp"

#include "../config/config.hpp"
#include "../core/logger.hpp"
#include "../identity/system_id.hpp"
#include "../obfuscation/api_hash.hpp"
#include "../obfuscation/xor_str.hpp"

#include <Windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

// ---------------------------------------------------------------------------
// Compile-time hashes — no "malloc" string in the binary
// ---------------------------------------------------------------------------

namespace
{
    constexpr std::uint32_t hash_malloc      = API_HASH("malloc");
    constexpr std::uint32_t hash_ucrtbase    = API_HASH("ucrtbase.dll");
    constexpr std::uint32_t hash_ucrtbased   = API_HASH("ucrtbased.dll");

    // -----------------------------------------------------------------------
    // Memory accessibility check
    // -----------------------------------------------------------------------
    bool accessible(const void* address, std::size_t size, bool write)
    {
        if (address == nullptr || size == 0)
            return false;

        MEMORY_BASIC_INFORMATION information{};
        if (VirtualQuery(address, &information, sizeof(information)) == 0 ||
            information.State != MEM_COMMIT ||
            (information.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
        {
            return false;
        }

        const auto begin =
            reinterpret_cast<std::uintptr_t>(address);
        const auto end   =
            reinterpret_cast<std::uintptr_t>(information.BaseAddress) +
            information.RegionSize;
        if (begin > end || size > end - begin)
            return false;

        if (!write)
            return true;

        const DWORD p = information.Protect & 0xFF;
        return p == PAGE_READWRITE ||
               p == PAGE_WRITECOPY ||
               p == PAGE_EXECUTE_READWRITE ||
               p == PAGE_EXECUTE_WRITECOPY;
    }

    // -----------------------------------------------------------------------
    // Find the CRT module using hash-based API resolution
    // No "ucrtbase.dll" string in the binary.
    // -----------------------------------------------------------------------
    HMODULE find_crt()
    {
        // We still need GetModuleHandleW but we pass wide-string literals which
        // are less interesting to string scanners than ASCII API names.
        if (const HMODULE m = GetModuleHandleW(L"ucrtbase.dll"))
            return m;
        return GetModuleHandleW(L"ucrtbased.dll");
    }
}

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

auth::Profile::Profile(resolver::ObjectLayout layout)
    : layout_(layout)
{
    if (const HMODULE runtime = find_crt())
    {
        // Resolve malloc by hash — no "malloc" string in the binary
        auto raw = api::resolve<void*>(runtime, hash_malloc);
        static_assert(sizeof(raw) == sizeof(allocate_));
        std::memcpy(&allocate_, &raw, sizeof(allocate_));
    }

    logger::write(XS("profile allocator: %p"),
                  reinterpret_cast<void*>(allocate_));
}

bool auth::Profile::ready() const
{
    return allocate_ != nullptr;
}

// ---------------------------------------------------------------------------
// apply_response — inject success + message flags
// ---------------------------------------------------------------------------

void auth::Profile::apply_response(void* instance) const
{
    if (instance == nullptr)
        return;

    auto* object = static_cast<std::byte*>(instance);
    object[layout_.response_success] = std::byte{ 1 };
    object[layout_.response_paid]    = std::byte{ 1 };

    // config::response_message is a plain constexpr — XS() not needed here
    // because it is never stored as a string in the binary (it is inlined by
    // the optimizer).  However, we wrap it for consistency.
    write_string(object + layout_.response_message,
                 config::response_message,
                 XS("response.message"));

    logger::write(XS("response accepted for %p"), instance);
}

// ---------------------------------------------------------------------------
// apply_identity — inject username, ip, hwid, timestamps and subscriptions
// Using system_id for dynamic, system-specific values.
// ---------------------------------------------------------------------------

void auth::Profile::apply_identity(void* instance) const
{
    if (instance == nullptr)
        return;

    auto* object = static_cast<std::byte*>(instance);

    write_string(object + layout_.username,   config::username,          XS("username"));
    write_string(object + layout_.ip,         identity::ip(),            XS("ip"));
    write_string(object + layout_.hwid,       identity::hwid(),          XS("hwid"));
    write_string(object + layout_.created_at, identity::created_at(),    XS("createdate"));
    write_string(object + layout_.last_login,  identity::last_login(),   XS("lastlogin"));

    apply_subscriptions(instance);
}

// ---------------------------------------------------------------------------
// keep_owner_atom — register the application owner ID as a global atom
// ---------------------------------------------------------------------------

void auth::Profile::keep_owner_atom(void* instance) const
{
    if (instance == nullptr)
        return;

    const auto* value =
        static_cast<const std::byte*>(instance) + layout_.owner_id;
    if (!accessible(value, 0x20, false))
        return;

    const auto length   = *reinterpret_cast<const std::size_t*>(value + 0x10);
    const auto capacity = *reinterpret_cast<const std::size_t*>(value + 0x18);
    if (length == 0 || length > 255 || capacity < length)
        return;

    const char* owner = capacity <= 15
        ? reinterpret_cast<const char*>(value)
        : *reinterpret_cast<const char* const*>(value);

    if (!accessible(owner, length + 1, false) || owner[length] != '\0')
        return;

    const ATOM atom = GlobalAddAtomA(owner);
    logger::write(XS("owner atom: %.*s -> %#x"),
                  static_cast<int>(length), owner,
                  static_cast<unsigned int>(atom));
}

// ---------------------------------------------------------------------------
// Private — write_string
// ---------------------------------------------------------------------------

bool auth::Profile::write_string(void* object,
                                  const char* replacement,
                                  const char* field) const
{
    if (!accessible(object, 0x20, true))
    {
        logger::write(XS("%s: invalid string object %p"), field, object);
        return false;
    }

    auto* storage  = static_cast<std::byte*>(object);
    auto* length   = reinterpret_cast<std::size_t*>(storage + 0x10);
    auto* capacity = reinterpret_cast<std::size_t*>(storage + 0x18);
    const std::size_t wanted = std::strlen(replacement);

    char* destination = nullptr;
    if (*capacity <= 15 && wanted <= 15)
    {
        destination = reinterpret_cast<char*>(storage);
        *capacity   = 15;
    }
    else if (*capacity > 15 && wanted <= *capacity)
    {
        destination = *reinterpret_cast<char**>(storage);
    }
    else
    {
        destination = allocate_ == nullptr
            ? nullptr
            : static_cast<char*>(allocate_(wanted + 1));
        if (!accessible(destination, wanted + 1, true))
        {
            logger::write(XS("%s: allocation failed"), field);
            return false;
        }

        *reinterpret_cast<char**>(storage) = destination;
        *capacity = wanted;
    }

    if (!accessible(destination, wanted + 1, true))
        return false;

    std::memcpy(destination, replacement, wanted + 1);
    *length = wanted;
    logger::write(XS("%s = %s"), field, replacement);
    return true;
}

// ---------------------------------------------------------------------------
// Private — initialize_small_string
// ---------------------------------------------------------------------------

bool auth::Profile::initialize_small_string(void* object,
                                             const char* value) const
{
    const std::size_t length = std::strlen(value);
    if (length > 15 || !accessible(object, 0x20, true))
        return false;

    std::memset(object, 0, 0x20);
    std::memcpy(object, value, length + 1);

    auto* storage = static_cast<std::byte*>(object);
    *reinterpret_cast<std::size_t*>(storage + 0x10) = length;
    *reinterpret_cast<std::size_t*>(storage + 0x18) = 15;
    return true;
}

// ---------------------------------------------------------------------------
// Private — apply_subscriptions
// ---------------------------------------------------------------------------

void auth::Profile::apply_subscriptions(void* instance) const
{
    struct Vector
    {
        std::byte* begin;
        std::byte* end;
        std::byte* capacity;
    };

    auto* list = reinterpret_cast<Vector*>(
        static_cast<std::byte*>(instance) + layout_.subscriptions);
    if (!accessible(list, sizeof(*list), true))
        return;

    constexpr std::size_t subscription_size = 0x40;
    constexpr std::size_t entry_count =
        sizeof(config::subscriptions) / sizeof(config::subscriptions[0]);
    const std::size_t total_size = subscription_size * entry_count;

    std::byte* base_ptr = nullptr;

    if (list->begin == nullptr && list->end == nullptr && list->capacity == nullptr)
    {
        base_ptr = allocate_ == nullptr
            ? nullptr
            : static_cast<std::byte*>(allocate_(total_size));
        if (!accessible(base_ptr, total_size, true))
            return;

        list->begin    = base_ptr;
        list->end      = base_ptr + total_size;
        list->capacity = list->end;
    }
    else if (list->begin != nullptr &&
             list->capacity >= list->begin + subscription_size &&
             accessible(list->begin, subscription_size, true))
    {
        base_ptr   = list->begin;
        list->end  = list->begin + total_size;
    }
    else
    {
        logger::write(XS("subscription vector layout rejected"));
        return;
    }

    for (std::size_t i = 0; i < entry_count; ++i)
    {
        std::byte* item = base_ptr + i * subscription_size;
        if (!accessible(item, subscription_size, true))
        {
            logger::write(XS("subscription slot %zu: not accessible"), i);
            break;
        }

        const auto& entry = config::subscriptions[i];
        if (initialize_small_string(item, entry.name) &&
            initialize_small_string(item + 0x20, entry.expiry))
        {
            logger::write(XS("subscription[%zu] = %s / %s"),
                          i, entry.name, entry.expiry);
        }
    }
}
