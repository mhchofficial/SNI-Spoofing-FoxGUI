#ifndef SMART_FOX_PLUGIN_H
#define SMART_FOX_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

// Export macros
#define SMART_FOX_EXPORT __attribute__((visibility("default")))

// Initialization and cleanup
SMART_FOX_EXPORT int smart_fox_initialize(void);
SMART_FOX_EXPORT void smart_fox_cleanup(void);

// Service control
SMART_FOX_EXPORT int smart_fox_start_service(const char* config_json);
SMART_FOX_EXPORT int smart_fox_stop_service(void);
SMART_FOX_EXPORT int smart_fox_is_running(void);

// Statistics
SMART_FOX_EXPORT const char* smart_fox_get_stats(void);
SMART_FOX_EXPORT void smart_fox_free_string(char* str);

// Logging
typedef void (*log_callback_t)(const char* message);
SMART_FOX_EXPORT void smart_fox_set_log_callback(log_callback_t callback);

// Testing
SMART_FOX_EXPORT int smart_fox_test_connection(const char* host, int port);

// Error handling
SMART_FOX_EXPORT const char* smart_fox_get_last_error(void);

#ifdef __cplusplus
}
#endif

#endif // SMART_FOX_PLUGIN_H
