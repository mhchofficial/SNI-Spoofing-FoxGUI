#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <map>
#include <mutex>

namespace smartfox {

struct ServiceConfig;

/**
 * Connection state tracking
 */
struct ConnectionState {
    std::string srcIp;
    uint16_t srcPort;
    std::string dstIp;
    uint16_t dstPort;
    
    enum class State {
        New,
        SynSent,
        Established,
        ClientHelloSent,
        Active,
        Closing,
        Closed
    };
    State state = State::New;
    
    uint32_t seqNum = 0;
    uint32_t ackNum = 0;
    
    std::string makeKey() const {
        return srcIp + ":" + std::to_string(srcPort) + 
               "->" + dstIp + ":" + std::to_string(dstPort);
    }
};

/**
 * Packet processor for SNI modification
 */
class PacketProcessor {
public:
    explicit PacketProcessor(const ServiceConfig& config);
    ~PacketProcessor();
    
    /**
     * Process outgoing packet (to server)
     * Returns list of modified packets (may be fragmented)
     */
    std::vector<std::vector<uint8_t>> processOutgoing(const std::vector<uint8_t>& packet);
    
    /**
     * Process incoming packet (from server)
     * Returns modified packet
     */
    std::vector<uint8_t> processIncoming(const std::vector<uint8_t>& packet);
    
    // Connection tracking
    int getActiveConnections() const;
    void cleanupConnections();

private:
    // IP packet parsing
    bool parseIpHeader(const std::vector<uint8_t>& packet, 
                      int& version, int& ihl, int& protocol,
                      std::string& srcIp, std::string& dstIp);
    
    // TCP handling
    bool parseTcpHeader(const std::vector<uint8_t>& packet, int offset,
                       uint16_t& srcPort, uint16_t& dstPort,
                       uint32_t& seqNum, uint32_t& ackNum, int& flags, int& headerLen);
    
    bool isTlsClientHello(const uint8_t* payload, size_t len);
    std::vector<uint8_t> modifyClientHello(const uint8_t* payload, size_t len);
    
    // Checksum calculation
    void recalculateIpChecksum(std::vector<uint8_t>& packet, int ihl);
    void recalculateTcpChecksum(std::vector<uint8_t>& packet, int ipOffset, int tcpOffset, int tcpLen);
    uint16_t calculateChecksum(const uint8_t* data, size_t len);
    
    // Fragmentation
    std::vector<std::vector<uint8_t>> fragmentPacket(const std::vector<uint8_t>& packet, int payloadOffset);
    
    const ServiceConfig& m_config;
    
    // Connection tracking
    std::map<std::string, ConnectionState> m_connections;
    mutable std::mutex m_connectionsMutex;
};

} // namespace smartfox

#endif // PACKET_PROCESSOR_H
