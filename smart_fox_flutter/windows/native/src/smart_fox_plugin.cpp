#define SMART_FOX_PLUGIN_EXPORTS

#include "smart_fox_plugin.h"
#include "sni_service.h"
#include <memory>

static std::unique_ptr<smartfox::SniService> g_service;

extern "C" {

SMART_FOX_API int smart_fox_init() {
    if (g_service) {
        return 1; // Already initialized
    }
    
    g_service = std::make_unique<smartfox::SniService>();
    return g_service->initialize() ? 1 : 0;
}

SMART_FOX_API int smart_fox_start(SniConfig* config) {
    if (!g_service) {
        return 0;
    }
    return g_service->start(*config) ? 1 : 0;
}

SMART_FOX_API void smart_fox_stop() {
    if (g_service) {
        g_service->stop();
    }
}

SMART_FOX_API void smart_fox_cleanup() {
    if (g_service) {
        g_service->cleanup();
        g_service.reset();
    }
}

SMART_FOX_API int smart_fox_is_admin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2,
            SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    
    return isAdmin ? 1 : 0;
}

SMART_FOX_API int smart_fox_request_admin() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, MAX_PATH)) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;
        
        if (ShellExecuteExW(&sei)) {
            return 1;
        }
    }
    return 0;
}

SMART_FOX_API void smart_fox_set_status_callback(StatusCallback callback) {
    if (g_service) {
        g_service->setStatusCallback(callback);
    }
}

SMART_FOX_API void smart_fox_set_stats_callback(StatsCallback callback) {
    if (g_service) {
        g_service->setStatsCallback(callback);
    }
}

SMART_FOX_API void smart_fox_set_log_callback(LogCallback callback) {
    if (g_service) {
        g_service->setLogCallback(callback);
    }
}

SMART_FOX_API void smart_fox_set_error_callback(ErrorCallback callback) {
    if (g_service) {
        g_service->setErrorCallback(callback);
    }
}

SMART_FOX_API int smart_fox_is_running() {
    return (g_service && g_service->isRunning()) ? 1 : 0;
}

SMART_FOX_API void smart_fox_get_stats(TrafficStats* stats) {
    if (g_service && stats) {
        g_service->getStats(*stats);
    }
}

} // extern "C"

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            smart_fox_cleanup();
            break;
    }
    return TRUE;
}
