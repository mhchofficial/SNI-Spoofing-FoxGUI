#include "sni_service.h"
#include "tun_device.h"
#include "packet_processor.h"

#include <sstream>
#include <cstring>
#include <cstdlib>
#include <chrono>

namespace smartfox {

// JSON parsing helpers (simple implementation)
static std::string getJsonString(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    
    pos = json.find(":", pos);
    if (pos == std::string::npos) return "";
    
    pos = json.find("\"", pos);
    if (pos == std::string::npos) return "";
    
    size_t start = pos + 1;
    size_t end = json.find("\"", start);
    if (end == std::string::npos) return "";
    
    return json.substr(start, end - start);
}

static int getJsonInt(const std::string& json, const std::string& key, int defaultVal) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return defaultVal;
    
    pos = json.find(":", pos);
    if (pos == std::string::npos) return defaultVal;
    
    pos++;
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    
    return std::atoi(json.c_str() + pos);
}

static bool getJsonBool(const std::string& json, const std::string& key, bool defaultVal) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return defaultVal;
    
    pos = json.find(":", pos);
    if (pos == std::string::npos) return defaultVal;
    
    return json.find("true", pos) < json.find(",", pos);
}

ServiceConfig ServiceConfig::fromJson(const std::string& json) {
    ServiceConfig config;
    
    std::string val = getJsonString(json, "fakeSni");
    if (!val.empty()) config.fakeSni = val;
    
    val = getJsonString(json, "realSni");
    if (!val.empty()) config.realSni = val;
    
    config.listenPort = getJsonInt(json, "listenPort", 443);
    config.remotePort = getJsonInt(json, "remotePort", 443);
    config.bufferSize = getJsonInt(json, "bufferSize", 65535);
    config.timeout = getJsonInt(json, "timeout", 30);
    config.numWorkers = getJsonInt(json, "numWorkers", 4);
    config.enableLogging = getJsonBool(json, "enableLogging", true);
    
    val = getJsonString(json, "logLevel");
    if (!val.empty()) config.logLevel = val;
    
    config.enableFakeTcpHandshake = getJsonBool(json, "enableFakeTcpHandshake", false);
    config.tcpTtl = getJsonInt(json, "tcpTtl", 64);
    config.tcpMss = getJsonInt(json, "tcpMss", 1460);
    config.tcpWindowSize = getJsonInt(json, "tcpWindowSize", 65535);
    
    val = getJsonString(json, "tlsVersion");
    if (!val.empty()) config.tlsVersion = val;
    
    val = getJsonString(json, "splitMode");
    if (!val.empty()) config.splitMode = val;
    
    val = getJsonString(json, "injectionMethod");
    if (!val.empty()) config.injectionMethod = val;
    
    config.dpiBypassLevel = getJsonInt(json, "dpiBypassLevel", 1);
    config.enableFragmentation = getJsonBool(json, "enableFragmentation", false);
    config.fragmentSize = getJsonInt(json, "fragmentSize", 100);
    config.randomizeFragments = getJsonBool(json, "randomizeFragments", false);
    
    return config;
}

std::string ServiceStats::toJson() const {
    std::ostringstream oss;
    oss << "{"
        << "\"bytesIn\":" << bytesIn << ","
        << "\"bytesOut\":" << bytesOut << ","
        << "\"packetsProcessed\":" << packetsProcessed << ","
        << "\"activeConnections\":" << activeConnections << ","
        << "\"uptimeSeconds\":" << uptimeSeconds
        << "}";
    return oss.str();
}

// Singleton instance
SniService& SniService::instance() {
    static SniService instance;
    return instance;
}

SniService::SniService() = default;

SniService::~SniService() {
    stop();
}

bool SniService::initialize() {
    if (m_initialized.load()) {
        return true;
    }
    
    // Check for root privileges
    if (geteuid() != 0) {
        m_lastError = "Root privileges required for TUN device and iptables";
        return false;
    }
    
    // Check for TUN support
    if (access("/dev/net/tun", R_OK | W_OK) != 0) {
        m_lastError = "TUN device not available. Please run: sudo modprobe tun";
        return false;
    }
    
    m_initialized.store(true);
    log("SmartFox SNI Service initialized");
    return true;
}

bool SniService::start(const ServiceConfig& config) {
    if (!m_initialized.load()) {
        m_lastError = "Service not initialized";
        return false;
    }
    
    if (m_running.load()) {
        m_lastError = "Service already running";
        return false;
    }
    
    m_config = config;
    
    // Create TUN device
    m_tunDevice = std::make_unique<TunDevice>();
    if (!m_tunDevice->create("smartfox0")) {
        m_lastError = "Failed to create TUN device: " + m_tunDevice->getLastError();
        return false;
    }
    
    if (!m_tunDevice->configure("10.0.0.1", 1500)) {
        m_lastError = "Failed to configure TUN device: " + m_tunDevice->getLastError();
        return false;
    }
    
    // Create packet processor
    m_packetProcessor = std::make_unique<PacketProcessor>(m_config);
    
    // Set up packet callback
    m_tunDevice->setPacketCallback([this](const std::vector<uint8_t>& packet) {
        // Process outgoing packet
        auto modifiedPackets = m_packetProcessor->processOutgoing(packet);
        
        for (const auto& modPacket : modifiedPackets) {
            m_tunDevice->writePacket(modPacket);
            m_bytesOut.fetch_add(modPacket.size());
        }
        
        m_packetsProcessed.fetch_add(1);
    });
    
    // Set up iptables
    if (!setupIptables()) {
        m_lastError = "Failed to configure iptables";
        return false;
    }
    
    // Start TUN device
    if (!m_tunDevice->start()) {
        m_lastError = "Failed to start TUN device: " + m_tunDevice->getLastError();
        cleanupIptables();
        return false;
    }
    
    m_running.store(true);
    m_startTime = std::chrono::steady_clock::now();
    
    // Reset statistics
    m_bytesIn.store(0);
    m_bytesOut.store(0);
    m_packetsProcessed.store(0);
    
    log("Service started with fake SNI: " + m_config.fakeSni);
    return true;
}

bool SniService::stop() {
    if (!m_running.load()) {
        return true;
    }
    
    m_running.store(false);
    
    // Stop workers
    for (auto& worker : m_workers) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    m_workers.clear();
    
    // Stop TUN device
    if (m_tunDevice) {
        m_tunDevice->stop();
        m_tunDevice.reset();
    }
    
    // Cleanup iptables
    cleanupIptables();
    
    // Cleanup packet processor
    m_packetProcessor.reset();
    
    log("Service stopped");
    return true;
}

ServiceStats SniService::getStats() const {
    ServiceStats stats;
    stats.bytesIn = m_bytesIn.load();
    stats.bytesOut = m_bytesOut.load();
    stats.packetsProcessed = m_packetsProcessed.load();
    stats.activeConnections = m_packetProcessor ? m_packetProcessor->getActiveConnections() : 0;
    
    if (m_running.load()) {
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - m_startTime);
        stats.uptimeSeconds = elapsed.count();
    }
    
    return stats;
}

void SniService::setLogCallback(LogCallback callback) {
    std::lock_guard<std::mutex> lock(m_logMutex);
    m_logCallback = callback;
}

void SniService::log(const std::string& message) {
    std::lock_guard<std::mutex> lock(m_logMutex);
    if (m_logCallback) {
        m_logCallback(message);
    }
}

bool SniService::setupIptables() {
    // Mark HTTPS traffic for routing through TUN
    std::string cmd;
    
    // Mark outgoing HTTPS traffic
    cmd = "iptables -t mangle -A OUTPUT -p tcp --dport 443 -j MARK --set-mark 1 2>/dev/null";
    system(cmd.c_str());
    
    // MASQUERADE for NAT
    cmd = "iptables -t nat -A POSTROUTING -o smartfox0 -j MASQUERADE 2>/dev/null";
    system(cmd.c_str());
    
    // Enable IP forwarding
    cmd = "echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null";
    system(cmd.c_str());
    
    m_iptablesModified = true;
    return true;
}

bool SniService::cleanupIptables() {
    if (!m_iptablesModified) {
        return true;
    }
    
    std::string cmd;
    
    cmd = "iptables -t mangle -D OUTPUT -p tcp --dport 443 -j MARK --set-mark 1 2>/dev/null";
    system(cmd.c_str());
    
    cmd = "iptables -t nat -D POSTROUTING -o smartfox0 -j MASQUERADE 2>/dev/null";
    system(cmd.c_str());
    
    m_iptablesModified = false;
    return true;
}

} // namespace smartfox

// Include for geteuid() and access()
#include <unistd.h>
