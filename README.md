# KeyAuth Runtime Memory Patcher

A sophisticated Windows x64 runtime memory patching library (DLL) designed to bypass KeyAuth authentication checks and simulate a verified session dynamically at runtime. 

Instead of relying on fragile hardcoded memory offsets, the patcher uses heuristic analysis and advanced hooking techniques to identify and manipulate authentication mechanisms on the fly.

---

## Technical Features & Capabilities

### 1. Heuristic Function Resolution
* **Dynamic Memory Scanning:** Scans the target application's memory space (`ProcessImage`) upon injection.
* **Control Flow Analysis:** Analyzes function call graphs and ModRM instruction displacements to dynamically resolve key verification functions (such as `load_response_data` and `api::check`). This ensures compatibility across different application updates.

### 2. Flow Redirection & Memory Spoofing (Inline Hooking)
* **Detour Hooks:** Installs JMP detour trampolines at the prologue of resolved authentication functions using the MinHook engine.
* **Response Manipulation:** Intercepts authentication structures in memory to inject success flags (`success = true`, `paid = true`), bypassing server validation checks.

### 3. Dynamic Identity Spoofing
* **HWID Generation:** Generates a consistent, hardware-locked identifier by hashing the Volume Serial Number and registry `MachineGuid` using FNV-1a.
* **IP Address Spoofing:** Queries network interfaces via `GetAdaptersInfo` to fetch and apply a realistic local IP address.
* **Session Timestamps:** Automatically recalculates and updates login (`last_login`) and creation (`created_at`) times using the current UNIX epoch.

### 4. Hook Integrity Guard (Watchdog Thread)
* **Active Monitoring:** Spawns a background thread that monitors the integrity of patched memory bytes every 2 seconds.
* **Automatic Repair:** If the application or an anti-tamper system attempts to restore or modify the hook trampolines, the watchdog automatically rewrites the detour hooks.

### 5. Reverse Engineering Countermeasures (Hardening)
* **Compile-time String Obfuscation:** Encrypts all internal string literals (such as logging formats) using compile-time XOR encryption. Plaintext strings like `"Authenticated"` or `"malloc"` do not appear in static analysis tools (IDA, Ghidra).
* **Hash-based API Resolution:** Eliminates plaintext Windows API import references. Functions are resolved dynamically by walking the PE Export Directory using precomputed FNV-1a hashes.

### 6. Anti-Tamper & Scan Suppression (Process Spoofing)
* **System API Interception:** Hooks `QueryFullProcessImageNameW` to mask modifications, stalling or spoofing process queries to evade self-integrity checks.
