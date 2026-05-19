#ifndef TUN_DEVICE_H
#define TUN_DEVICE_H

#include <string>
#include <cstdint>
#include <functional>
#include <vector>
#include <thread>
#include <atomic>

namespace smartfox {

/**
 * TUN device manager for Linux
 * Creates and manages a virtual network interface for packet interception
 */
class TunDevice {
public:
    using PacketCallback = std::function<void(const std::vector<uint8_t>&)>;
    
    TunDevice();
    ~TunDevice();
    
    // Device lifecycle
    bool create(const std::string& name = "smartfox0");
    bool configure(const std::string& ip = "10.0.0.1", int mtu = 1500);
    bool start();
    void stop();
    bool isRunning() const { return m_running.load(); }
    
    // Packet I/O
    void setPacketCallback(PacketCallback callback) { m_callback = callback; }
    bool writePacket(const std::vector<uint8_t>& packet);
    bool writePacket(const uint8_t* data, size_t len);
    
    // Device info
    int getFd() const { return m_fd; }
    const std::string& getName() const { return m_name; }
    const std::string& getLastError() const { return m_lastError; }

private:
    void readLoop();
    bool setupRouting();
    bool cleanupRouting();
    
    int m_fd = -1;
    std::string m_name;
    std::string m_ip;
    int m_mtu = 1500;
    
    std::atomic<bool> m_running{false};
    std::thread m_readThread;
    PacketCallback m_callback;
    
    std::string m_lastError;
    
    // Original routing state for restoration
    bool m_routingModified = false;
};

} // namespace smartfox

#endif // TUN_DEVICE_H
