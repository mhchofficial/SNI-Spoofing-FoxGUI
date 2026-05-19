#ifndef SNI_SERVICE_H
#define SNI_SERVICE_H

#include <string>
#include <atomic>
#include <thread>
#include <mutex>
#include <unordered_map>
#include <functional>
#include <winsock2.h>
#include <ws2tcpip.h>

#include "smart_fox_plugin.h"

// Forward declarations
struct WINDIVERT_ADDRESS;
typedef void* HANDLE;

namespace smartfox {

class SniService {
public:
    SniService();
    ~SniService();

    bool initialize();
    bool start(const SniConfig& config);
    void stop();
    void cleanup();

    bool isRunning() const { return running_; }
    void getStats(TrafficStats& stats) const;

    // Callbacks
    void setStatusCallback(StatusCallback callback) { statusCallback_ = callback; }
    void setStatsCallback(StatsCallback callback) { statsCallback_ = callback; }
    void setLogCallback(LogCallback callback) { logCallback_ = callback; }
    void setErrorCallback(ErrorCallback callback) { errorCallback_ = callback; }

private:
    void serverThread();
    void injectorThread();
    void statsReporterThread();
    void handleConnection(SOCKET clientSocket, const std::string& clientIp);
    
    void log(const std::string& message);
    void reportError(const std::string& error);
    void updateStatus(const std::string& status);

    // Configuration
    SniConfig config_;
    
    // State
    std::atomic<bool> running_{false};
    std::atomic<bool> initialized_{false};
    
    // Threads
    std::thread serverThread_;
    std::thread injectorThread_;
    std::thread statsThread_;
    
    // Sockets
    SOCKET listenSocket_{INVALID_SOCKET};
    
    // WinDivert handle
    HANDLE windivertHandle_{nullptr};
    
    // Connection tracking
    std::mutex connectionMutex_;
    std::unordered_map<std::string, int> connectionsPerIp_;
    std::atomic<int> activeConnections_{0};
    
    // Traffic stats
    std::atomic<int64_t> totalUpload_{0};
    std::atomic<int64_t> totalDownload_{0};
    std::atomic<int64_t> windowUpload_{0};
    std::atomic<int64_t> windowDownload_{0};
    
    // Local interface
    std::string interfaceIpv4_;
    
    // Callbacks
    StatusCallback statusCallback_{nullptr};
    StatsCallback statsCallback_{nullptr};
    LogCallback logCallback_{nullptr};
    ErrorCallback errorCallback_{nullptr};
};

} // namespace smartfox

#endif // SNI_SERVICE_H
