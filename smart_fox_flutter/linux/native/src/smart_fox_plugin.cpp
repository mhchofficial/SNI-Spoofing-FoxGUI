#include "smart_fox_plugin.h"
#include "sni_service.h"
#include <cstring>
#include <cstdlib>

using namespace smartfox;

static char* g_lastError = nullptr;
static char* g_statsBuffer = nullptr;

static void setError(const std::string& error) {
    if (g_lastError) {
        free(g_lastError);
    }
    g_lastError = strdup(error.c_str());
}

extern "C" {

SMART_FOX_EXPORT int smart_fox_initialize(void) {
    try {
        if (SniService::instance().initialize()) {
            return 0;
        }
        setError(SniService::instance().getLastError());
        return -1;
    } catch (const std::exception& e) {
        setError(e.what());
        return -1;
    }
}

SMART_FOX_EXPORT void smart_fox_cleanup(void) {
    SniService::instance().stop();
    
    if (g_lastError) {
        free(g_lastError);
        g_lastError = nullptr;
    }
    if (g_statsBuffer) {
        free(g_statsBuffer);
        g_statsBuffer = nullptr;
    }
}

SMART_FOX_EXPORT int smart_fox_start_service(const char* config_json) {
    try {
        auto config = ServiceConfig::fromJson(config_json ? config_json : "{}");
        if (SniService::instance().start(config)) {
            return 0;
        }
        setError(SniService::instance().getLastError());
        return -1;
    } catch (const std::exception& e) {
        setError(e.what());
        return -1;
    }
}

SMART_FOX_EXPORT int smart_fox_stop_service(void) {
    try {
        if (SniService::instance().stop()) {
            return 0;
        }
        setError(SniService::instance().getLastError());
        return -1;
    } catch (const std::exception& e) {
        setError(e.what());
        return -1;
    }
}

SMART_FOX_EXPORT int smart_fox_is_running(void) {
    return SniService::instance().isRunning() ? 1 : 0;
}

SMART_FOX_EXPORT const char* smart_fox_get_stats(void) {
    try {
        auto stats = SniService::instance().getStats();
        std::string json = stats.toJson();
        
        if (g_statsBuffer) {
            free(g_statsBuffer);
        }
        g_statsBuffer = strdup(json.c_str());
        return g_statsBuffer;
    } catch (...) {
        return nullptr;
    }
}

SMART_FOX_EXPORT void smart_fox_free_string(char* str) {
    if (str) {
        free(str);
    }
}

SMART_FOX_EXPORT void smart_fox_set_log_callback(log_callback_t callback) {
    if (callback) {
        SniService::instance().setLogCallback([callback](const std::string& msg) {
            callback(msg.c_str());
        });
    } else {
        SniService::instance().setLogCallback(nullptr);
    }
}

SMART_FOX_EXPORT int smart_fox_test_connection(const char* host, int port) {
    try {
        // Simple TCP connection test
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            setError("Failed to create socket");
            return -1;
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        
        struct hostent* he = gethostbyname(host);
        if (!he) {
            close(sock);
            setError("Failed to resolve hostname");
            return -1;
        }
        
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
        
        // Set timeout
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        
        int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        close(sock);
        
        return result == 0 ? 0 : -1;
    } catch (const std::exception& e) {
        setError(e.what());
        return -1;
    }
}

SMART_FOX_EXPORT const char* smart_fox_get_last_error(void) {
    return g_lastError;
}

} // extern "C"

// Include socket headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
