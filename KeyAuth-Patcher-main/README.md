# KeyAuth Patcher

> Windows x64 DLL — Bypasses the KeyAuth authentication system at runtime.

---

## Features

| Layer | Feature | Description |
|---|---|---|
| 🔴 | **Compile-time String Obfuscation** | All string literals are XOR-encrypted at compile time. Strings like `"Authenticated"`, `"malloc"`, or `"load_response_data"` are invisible in the `.rdata` section. |
| 🟠 | **Hash-based API Resolution** | Replaces standard imports/`GetProcAddress` with FNV-1a hashing + PE export walker. No raw API names exist as strings in the compiled binary. |
| 🟡 | **Dynamic System Identity** | HWID derived from Volume Serial + Machine GUID hash. IP retrieved dynamically from network adapter. `last_login` set to current UNIX timestamp. |
| 🟢 | **Hook Watchdog** | Background guard thread monitors hook prologue integrity every 2 seconds, auto-restoring JMP trampolines if modified. |
| 🔵 | **Clean DLL Lifecycle** | Properly uninstalls hooks, terminates threads, and closes handles during `DLL_PROCESS_DETACH`. |

---

## Architecture

```
DllMain (ATTACH)
  └─ Restore NtProtectVirtualMemory  (api_hash, syscall number derivation)
  └─ Spawn Worker Thread → runtime::start()
       ├─ logger::open()              (thread-safe file/console logging)
       ├─ identity::init()            (generate dynamic HWID / IP / timestamps)
       ├─ ProcessImage + FunctionCatalog  (PE parsing, displacement caching)
       ├─ AuthResolver::resolve()     (heuristic function identification)
       ├─ Profile::Profile()          (resolve malloc via api_hash)
       ├─ hooks::install()            (5 detour installations + watchdog registration)
       ├─ watchdog::start()           (spawn background guard thread)
       └─ hooks::install_spoof()      (QueryFullProcessImageNameW hook)

DllMain (DETACH)
  └─ runtime::stop()
       ├─ watchdog::stop()            (terminate guard thread)
       ├─ hooks::uninstall_spoof()    (signal spoof hook to release threads)
       ├─ hooks::uninstall()          (disable/remove hooks + uninitialize MinHook)
       ├─ profile.reset()
       └─ logger::close()             (flush logs + close handles)
```

---

## Security Layers

### 1. String Obfuscation — `modules/obfuscation/xor_str.hpp`

```cpp
// Before — visible in binary:
logger::write("hook installed");

// After — encrypted, decrypted temporarily on stack:
logger::write(XS("hook installed"));
```

Every string wrapped in the `XS()` macro is XOR-encrypted compile-time and only exists as plain text on the stack frame temporarily.

---

### 2. Hash-based Imports — `modules/obfuscation/api_hash.hpp`

```cpp
// Before — "malloc" visible in imports/strings:
GetProcAddress(crt, "malloc")

// After — only 32-bit hash value exists in binary:
api::resolve<Malloc>(crt, API_HASH("malloc"))   // 0xC70F6907
```

---

### 3. Dynamic Identity — `modules/identity/system_id.hpp`

| Field | Source |
|---|---|
| `hwid` | `GetVolumeInformationA` (serial) + Registry `MachineGuid` → FNV hash |
| `ip` | `GetAdaptersInfo` → first active non-loopback adapter |
| `last_login` | `GetSystemTimeAsFileTime` → UNIX epoch timestamp |
| `created_at` | Deterministially derived based on HWID hash |

Generates unique, realistic, and consistent identity parameters matching the target system.

---

### 4. Hook Watchdog — `modules/watchdog/hook_guard.hpp`

```
[Watchdog Thread]  →  runs every 2 seconds
    for each hook:
        current_bytes = read(target, 14)
        if current_bytes != expected_bytes:
            MH_DisableHook(target)
            MH_EnableHook(target)   ← rewrite JMP trampoline
            expected_bytes = read(target, 14)  ← update snapshot
```

---

## Configuration

**`modules/config/config.hpp`** — central settings file:

```cpp
// Obfuscation XOR key — modify between builds
inline constexpr uint8_t obfuscation_key = 0xA7;

// Subscriptions
inline constexpr SubscriptionEntry subscriptions[] = {
    { "default", "9999999999" },
};

// Console configuration (false = silent mode)
inline constexpr bool show_console = false;
```

---

## Project Directory Structure

```
KeyAuth-Patcher/
├── dllmain.cpp
├── MinHook.h / libMinHook.x64.lib
└── modules/
    ├── config/
    │   └── config.hpp           ⚙️  Central settings
    ├── obfuscation/
    │   ├── xor_str.hpp          🔒 Compile-time string encryption
    │   └── api_hash.hpp         🔒 FNV-1a hashing + PE export walker
    ├── identity/
    │   ├── system_id.hpp        🆔 Identity interface
    │   └── system_id.cpp        🆔 Volume serial / MachineGuid / IP / time
    ├── watchdog/
    │   ├── hook_guard.hpp       🛡️  Watchdog interface
    │   └── hook_guard.cpp       🛡️  Background integrity guard thread
    ├── auth/
    │   ├── profile.hpp/.cpp     Profile handling (system_id + api_hash)
    ├── core/
    │   ├── logger.hpp/.cpp      Thread-safe logging interface
    ├── hooks/
    │   ├── auth_hooks.hpp/.cpp  5 detour hooks + watchdog integration
    │   └── process_hooks.hpp/.cpp  QueryFullProcessImageNameW spoof hook
    ├── memory/
    │   ├── function_catalog.hpp/.cpp  Function parser + caching
    │   └── process_image.hpp/.cpp     PE parser
    ├── native/
    │   └── ntdll_patch.hpp/.cpp  NtProtectVirtualMemory patch (api_hash)
    ├── resolver/
    │   └── auth_resolver.hpp/.cpp  Heuristic function detection
    └── runtime/
        └── bootstrap.hpp/.cpp    Coordination of start() / stop()
```

---

## Build Instructions

**Requirements**
- Visual Studio 2022 (MSVC v143 toolset)
- Windows SDK 10.0
- C++23 Standard

**Steps**

1. Open `KeyAuth.sln` in Visual Studio.
2. Select target platform as `x64` and configuration as `Release`.
3. Press `Ctrl+Shift+B` to build the solution.
4. Output binary will be generated at `x64\Release\KeyAuth.dll`.

**Dependencies**

| Library | Purpose |
|---|---|
| `MinHook` | x64 inline hook engine |
| `iphlpapi.lib` | Network adapter query (`GetAdaptersInfo`) |
| `advapi32.lib` | Registry query (`MachineGuid`) |
| Windows SDK | Win32 API and PE structures |

