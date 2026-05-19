#ifndef SMART_FOX_PLUGIN_H
#define SMART_FOX_PLUGIN_H

#include <windows.h>
#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

// Export macros
#ifdef SMART_FOX_PLUGIN_EXPORTS
#define SMART_FOX_API __declspec(dllexport)
#else
#define SMART_FOX_API __declspec(dllimport)
#endif

// Configuration structure
typedef struct {
    const char* listen_host;
    int listen_port;
    const char* connect_ip;
    int connect_port;
    const char* fake_sni;
    int max_connections;
    int max_connections_per_ip;
    double handshake_timeout_sec;
    double relay_idle_timeout_sec;
    double connect_timeout_sec;
    int connect_retry_count;
    double connect_retry_delay_sec;
    int relay_buffer_size;
    int socket_sndbuf;
    int socket_rcvbuf;
    int enable_tcp_nodelay;
} SniConfig;

// Traffic statistics
typedef struct {
    int64_t upload_bps;
    int64_t download_bps;
    int64_t total_upload;
    int64_t total_download;
    int active_connections;
} TrafficStats;

// Callback types
typedef void (*StatusCallback)(const char* status);
typedef void (*StatsCallback)(TrafficStats* stats);
typedef void (*LogCallback)(const char* message);
typedef void (*ErrorCallback)(const char* error);

// Service lifecycle
SMART_FOX_API int smart_fox_init();
SMART_FOX_API int smart_fox_start(SniConfig* config);
SMART_FOX_API void smart_fox_stop();
SMART_FOX_API void smart_fox_cleanup();

// Admin privileges
SMART_FOX_API int smart_fox_is_admin();
SMART_FOX_API int smart_fox_request_admin();

// Callbacks
SMART_FOX_API void smart_fox_set_status_callback(StatusCallback callback);
SMART_FOX_API void smart_fox_set_stats_callback(StatsCallback callback);
SMART_FOX_API void smart_fox_set_log_callback(LogCallback callback);
SMART_FOX_API void smart_fox_set_error_callback(ErrorCallback callback);

// Status
SMART_FOX_API int smart_fox_is_running();
SMART_FOX_API void smart_fox_get_stats(TrafficStats* stats);

#ifdef __cplusplus
}
#endif

#endif // SMART_FOX_PLUGIN_H
