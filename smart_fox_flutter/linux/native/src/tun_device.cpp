#include "tun_device.h"

#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace smartfox {

TunDevice::TunDevice() = default;

TunDevice::~TunDevice() {
    stop();
    if (m_fd >= 0) {
        close(m_fd);
    }
    cleanupRouting();
}

bool TunDevice::create(const std::string& name) {
    // Open TUN device
    m_fd = open("/dev/net/tun", O_RDWR);
    if (m_fd < 0) {
        m_lastError = "Failed to open /dev/net/tun: " + std::string(strerror(errno));
        return false;
    }
    
    // Configure interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    
    if (!name.empty()) {
        strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    }
    
    if (ioctl(m_fd, TUNSETIFF, &ifr) < 0) {
        m_lastError = "Failed to create TUN interface: " + std::string(strerror(errno));
        close(m_fd);
        m_fd = -1;
        return false;
    }
    
    m_name = ifr.ifr_name;
    
    // Set non-blocking
    int flags = fcntl(m_fd, F_GETFL, 0);
    fcntl(m_fd, F_SETFL, flags | O_NONBLOCK);
    
    return true;
}

bool TunDevice::configure(const std::string& ip, int mtu) {
    if (m_fd < 0) {
        m_lastError = "TUN device not created";
        return false;
    }
    
    m_ip = ip;
    m_mtu = mtu;
    
    // Create socket for ioctl
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        m_lastError = "Failed to create socket for configuration";
        return false;
    }
    
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, m_name.c_str(), IFNAMSIZ - 1);
    
    // Set IP address
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &addr->sin_addr);
    
    if (ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        m_lastError = "Failed to set IP address: " + std::string(strerror(errno));
        close(sock);
        return false;
    }
    
    // Set netmask
    memset(&ifr.ifr_netmask, 0, sizeof(ifr.ifr_netmask));
    addr = (struct sockaddr_in*)&ifr.ifr_netmask;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, "255.255.255.0", &addr->sin_addr);
    
    if (ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        m_lastError = "Failed to set netmask: " + std::string(strerror(errno));
        close(sock);
        return false;
    }
    
    // Set MTU
    ifr.ifr_mtu = mtu;
    if (ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
        m_lastError = "Failed to set MTU: " + std::string(strerror(errno));
        close(sock);
        return false;
    }
    
    // Bring interface up
    ifr.ifr_flags = IFF_UP | IFF_RUNNING;
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        m_lastError = "Failed to bring interface up: " + std::string(strerror(errno));
        close(sock);
        return false;
    }
    
    close(sock);
    return true;
}

bool TunDevice::start() {
    if (m_fd < 0) {
        m_lastError = "TUN device not created";
        return false;
    }
    
    if (m_running.load()) {
        return true;
    }
    
    if (!setupRouting()) {
        return false;
    }
    
    m_running.store(true);
    m_readThread = std::thread(&TunDevice::readLoop, this);
    
    return true;
}

void TunDevice::stop() {
    m_running.store(false);
    
    if (m_readThread.joinable()) {
        m_readThread.join();
    }
    
    cleanupRouting();
}

bool TunDevice::writePacket(const std::vector<uint8_t>& packet) {
    return writePacket(packet.data(), packet.size());
}

bool TunDevice::writePacket(const uint8_t* data, size_t len) {
    if (m_fd < 0 || !m_running.load()) {
        return false;
    }
    
    ssize_t written = write(m_fd, data, len);
    return written == static_cast<ssize_t>(len);
}

void TunDevice::readLoop() {
    std::vector<uint8_t> buffer(65536);
    
    while (m_running.load()) {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(m_fd, &readSet);
        
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 100000; // 100ms timeout
        
        int ret = select(m_fd + 1, &readSet, nullptr, nullptr, &tv);
        
        if (ret > 0 && FD_ISSET(m_fd, &readSet)) {
            ssize_t len = read(m_fd, buffer.data(), buffer.size());
            
            if (len > 0 && m_callback) {
                std::vector<uint8_t> packet(buffer.begin(), buffer.begin() + len);
                m_callback(packet);
            }
        }
    }
}

bool TunDevice::setupRouting() {
    // Add default route through TUN device
    // This redirects all traffic through our interface
    
    std::string cmd = "ip route add default dev " + m_name + " table 100 2>/dev/null";
    int ret = system(cmd.c_str());
    
    // Add ip rule to use our routing table for marked packets
    cmd = "ip rule add fwmark 1 table 100 2>/dev/null";
    ret = system(cmd.c_str());
    
    m_routingModified = true;
    return true; // Best effort
}

bool TunDevice::cleanupRouting() {
    if (!m_routingModified) {
        return true;
    }
    
    // Remove routing rules
    std::string cmd = "ip rule del fwmark 1 table 100 2>/dev/null";
    system(cmd.c_str());
    
    cmd = "ip route del default dev " + m_name + " table 100 2>/dev/null";
    system(cmd.c_str());
    
    m_routingModified = false;
    return true;
}

} // namespace smartfox
