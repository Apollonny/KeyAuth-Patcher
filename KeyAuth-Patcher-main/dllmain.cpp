#include <Windows.h>

#include "modules/native/ntdll_patch.hpp"
#include "modules/runtime/bootstrap.hpp"

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    switch (reason)
    {
    case DLL_PROCESS_ATTACH:
    {
        DisableThreadLibraryCalls(module);
        native::restore_ntprotect_entry();
        const HANDLE worker = CreateThread(nullptr, 0, runtime::start, nullptr, 0, nullptr);
        if (worker != nullptr)
            CloseHandle(worker);
        break;
    }
    case DLL_PROCESS_DETACH:
        runtime::stop();
        break;
    default:
        break;
    }
    return TRUE;
}
