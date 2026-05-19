#ifndef PACKET_INJECTOR_H
#define PACKET_INJECTOR_H

#include <cstdint>
#include <vector>
#include <string>
#include <mutex>
#include <unordered_map>
#include <atomic>
#include <functional>

// Forward declarations for WinDivert
struct WINDIVERT_ADDRESS;
typedef void* HANDLE;

namespace smartfox {

// Connection state for fake injection
struct FakeConnection {
    std::string srcIp;
    std::string dstIp;
    uint16_t srcPort;
    uint16_t dstPort;
    
    std::vector<uint8_t> fakeData;
    std::string bypassMethod;
    
    uint32_t synSeq{0xFFFFFFFF};
    uint32_t synAckSeq{0xFFFFFFFF};
    
    bool schFakeSent{false};
    bool fakeSent{false};
    bool monitor{true};
    
    std::atomic<bool> ackReceived{false};
    std::string t2aMsg;
    
    std::mutex lock;
};

// Connection identifier
struct ConnectionId {
    std::string srcIp;
    uint16_t srcPort;
    std::string dstIp;
    uint16_t dstPort;
    
    bool operator==(const ConnectionId& other) const {
        return srcIp == other.srcIp && srcPort == other.srcPort &&
               dstIp == other.dstIp && dstPort == other.dstPort;
    }
};

struct ConnectionIdHash {
    size_t operator()(const ConnectionId& id) const {
        return std::hash<std::string>()(id.srcIp) ^
               std::hash<uint16_t>()(id.srcPort) ^
               std::hash<std::string>()(id.dstIp) ^
               std::hash<uint16_t>()(id.dstPort);
    }
};

class PacketInjector {
public:
    PacketInjector();
    ~PacketInjector();

    bool initialize(const std::string& filter);
    void stop();
    void cleanup();

    // Run the packet interception loop
    void run();

    // Register a connection for monitoring
    void registerConnection(const ConnectionId& id, std::shared_ptr<FakeConnection> conn);
    void unregisterConnection(const ConnectionId& id);
    
    // Wait for fake data acknowledgment
    bool waitForAck(const ConnectionId& id, int timeoutMs);

    void setLogCallback(std::function<void(const std::string&)> callback) {
        logCallback_ = callback;
    }

private:
    void processPacket(uint8_t* packet, size_t packetLen, WINDIVERT_ADDRESS* addr);
    void onInboundPacket(uint8_t* packet, size_t packetLen, WINDIVERT_ADDRESS* addr, 
                         std::shared_ptr<FakeConnection> conn);
    void onOutboundPacket(uint8_t* packet, size_t packetLen, WINDIVERT_ADDRESS* addr,
                          std::shared_ptr<FakeConnection> conn);
    void sendFakeData(uint8_t* packet, size_t packetLen, WINDIVERT_ADDRESS* addr,
                      std::shared_ptr<FakeConnection> conn);
    void onUnexpectedPacket(uint8_t* packet, WINDIVERT_ADDRESS* addr,
                            std::shared_ptr<FakeConnection> conn, const std::string& reason);

    void log(const std::string& message);

    // WinDivert handle
    HANDLE handle_{nullptr};
    
    // Running state
    std::atomic<bool> running_{false};
    
    // Connections being monitored
    std::mutex connectionsMutex_;
    std::unordered_map<ConnectionId, std::shared_ptr<FakeConnection>, ConnectionIdHash> connections_;
    
    // Logging
    std::function<void(const std::string&)> logCallback_;
};

// Helper functions for packet parsing
namespace packet {
    // IP header offsets and functions
    uint8_t getIpVersion(const uint8_t* packet);
    size_t getIpHeaderLen(const uint8_t* packet);
    std::string getSrcIp(const uint8_t* packet);
    std::string getDstIp(const uint8_t* packet);
    uint16_t getIpTotalLen(const uint8_t* packet);
    void setIpTotalLen(uint8_t* packet, uint16_t len);
    uint16_t getIpIdent(const uint8_t* packet);
    void setIpIdent(uint8_t* packet, uint16_t ident);
    
    // TCP header offsets and functions (assuming IPv4)
    size_t getTcpHeaderOffset(const uint8_t* packet);
    uint16_t getTcpSrcPort(const uint8_t* packet);
    uint16_t getTcpDstPort(const uint8_t* packet);
    uint32_t getTcpSeqNum(const uint8_t* packet);
    void setTcpSeqNum(uint8_t* packet, uint32_t seq);
    uint32_t getTcpAckNum(const uint8_t* packet);
    uint8_t getTcpFlags(const uint8_t* packet);
    void setTcpFlags(uint8_t* packet, uint8_t flags);
    size_t getTcpHeaderLen(const uint8_t* packet);
    size_t getTcpPayloadOffset(const uint8_t* packet);
    size_t getTcpPayloadLen(const uint8_t* packet);
    void setTcpPayload(uint8_t* packet, const uint8_t* payload, size_t payloadLen);
    
    // TCP flags
    constexpr uint8_t TCP_FIN = 0x01;
    constexpr uint8_t TCP_SYN = 0x02;
    constexpr uint8_t TCP_RST = 0x04;
    constexpr uint8_t TCP_PSH = 0x08;
    constexpr uint8_t TCP_ACK = 0x10;
}

} // namespace smartfox

#endif // PACKET_INJECTOR_H
