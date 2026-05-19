#ifndef SNI_SERVICE_H
#define SNI_SERVICE_H

#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>
#include <functional>
#include <cstdint>

namespace smartfox {

// Forward declarations
class TunDevice;
class PacketProcessor;

/**
 * SNI spoofing service configuration
 */
struct ServiceConfig {
    std::string fakeSni = "www.google.com";
    std::string realSni;
    int listenPort = 443;
    int remotePort = 443;
    int bufferSize = 65535;
    int timeout = 30;
    int numWorkers = 4;
    bool enableLogging = true;
    std::string logLevel = "info";
    
    // TCP settings
    bool enableFakeTcpHandshake = false;
    int tcpTtl = 64;
    int tcpMss = 1460;
    int tcpWindowSize = 65535;
    
    // TLS settings
    std::string tlsVersion = "tls12";
    std::string splitMode = "sni";
    std::string injectionMethod = "standard";
    int dpiBypassLevel = 1;
    
    // Fragmentation
    bool enableFragmentation = false;
    int fragmentSize = 100;
    bool randomizeFragments = false;
    
    // Parse from JSON
    static ServiceConfig fromJson(const std::string& json);
};

/**
 * Service statistics
 */
struct ServiceStats {
    uint64_t bytesIn = 0;
    uint64_t bytesOut = 0;
    uint64_t packetsProcessed = 0;
    int activeConnections = 0;
    int64_t uptimeSeconds = 0;
    
    std::string toJson() const;
};

/**
 * Main SNI spoofing service for Linux
 * Uses TUN device and iptables for transparent traffic interception
 */
class SniService {
public:
    using LogCallback = std::function<void(const std::string&)>;
    
    SniService();
    ~SniService();
    
    // Singleton access
    static SniService& instance();
    
    // Service lifecycle
    bool initialize();
    bool start(const ServiceConfig& config);
    bool stop();
    bool isRunning() const { return m_running.load(); }
    
    // Configuration
    const ServiceConfig& getConfig() const { return m_config; }
    
    // Statistics
    ServiceStats getStats() const;
    
    // Logging
    void setLogCallback(LogCallback callback);
    void log(const std::string& message);
    
    // Error handling
    const std::string& getLastError() const { return m_lastError; }

private:
    void workerLoop();
    bool setupIptables();
    bool cleanupIptables();
    
    ServiceConfig m_config;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_initialized{false};
    
    std::unique_ptr<TunDevice> m_tunDevice;
    std::unique_ptr<PacketProcessor> m_packetProcessor;
    
    std::vector<std::thread> m_workers;
    std::mutex m_mutex;
    
    // Statistics
    std::atomic<uint64_t> m_bytesIn{0};
    std::atomic<uint64_t> m_bytesOut{0};
    std::atomic<uint64_t> m_packetsProcessed{0};
    std::atomic<int> m_activeConnections{0};
    std::chrono::steady_clock::time_point m_startTime;
    
    // Logging
    LogCallback m_logCallback;
    std::mutex m_logMutex;
    
    std::string m_lastError;
    bool m_iptablesModified = false;
};

} // namespace smartfox

#endif // SNI_SERVICE_H
