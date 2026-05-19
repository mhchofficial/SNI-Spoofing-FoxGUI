#include "packet_processor.h"
#include "sni_service.h"
#include "client_hello_maker.h"

#include <cstring>
#include <arpa/inet.h>
#include <random>

namespace smartfox {

PacketProcessor::PacketProcessor(const ServiceConfig& config)
    : m_config(config) {
}

PacketProcessor::~PacketProcessor() = default;

std::vector<std::vector<uint8_t>> PacketProcessor::processOutgoing(const std::vector<uint8_t>& packet) {
    if (packet.size() < 20) {
        return {packet}; // Too small
    }
    
    int version, ihl, protocol;
    std::string srcIp, dstIp;
    
    if (!parseIpHeader(packet, version, ihl, protocol, srcIp, dstIp)) {
        return {packet};
    }
    
    // Only process IPv4 TCP
    if (version != 4 || protocol != 6) { // 6 = TCP
        return {packet};
    }
    
    if (packet.size() < static_cast<size_t>(ihl + 20)) {
        return {packet}; // Too small for TCP header
    }
    
    uint16_t srcPort, dstPort;
    uint32_t seqNum, ackNum;
    int flags, tcpHeaderLen;
    
    if (!parseTcpHeader(packet, ihl, srcPort, dstPort, seqNum, ackNum, flags, tcpHeaderLen)) {
        return {packet};
    }
    
    // Only process HTTPS (port 443)
    if (dstPort != 443) {
        return {packet};
    }
    
    int payloadOffset = ihl + tcpHeaderLen;
    if (packet.size() <= static_cast<size_t>(payloadOffset)) {
        return {packet}; // No payload
    }
    
    // Check for TLS ClientHello
    const uint8_t* payload = packet.data() + payloadOffset;
    size_t payloadLen = packet.size() - payloadOffset;
    
    if (!isTlsClientHello(payload, payloadLen)) {
        return {packet};
    }
    
    // Modify ClientHello
    auto modifiedPayload = modifyClientHello(payload, payloadLen);
    
    // Build new packet
    std::vector<uint8_t> modifiedPacket(payloadOffset + modifiedPayload.size());
    std::memcpy(modifiedPacket.data(), packet.data(), payloadOffset);
    std::memcpy(modifiedPacket.data() + payloadOffset, modifiedPayload.data(), modifiedPayload.size());
    
    // Update IP total length
    uint16_t totalLen = modifiedPacket.size();
    modifiedPacket[2] = (totalLen >> 8) & 0xFF;
    modifiedPacket[3] = totalLen & 0xFF;
    
    // Recalculate checksums
    recalculateIpChecksum(modifiedPacket, ihl);
    recalculateTcpChecksum(modifiedPacket, 0, ihl, modifiedPacket.size() - ihl);
    
    // Apply fragmentation if enabled
    if (m_config.enableFragmentation) {
        return fragmentPacket(modifiedPacket, payloadOffset);
    }
    
    return {modifiedPacket};
}

std::vector<uint8_t> PacketProcessor::processIncoming(const std::vector<uint8_t>& packet) {
    // For incoming packets, just track statistics
    return packet;
}

int PacketProcessor::getActiveConnections() const {
    std::lock_guard<std::mutex> lock(m_connectionsMutex);
    return m_connections.size();
}

void PacketProcessor::cleanupConnections() {
    std::lock_guard<std::mutex> lock(m_connectionsMutex);
    // Remove closed connections
    auto it = m_connections.begin();
    while (it != m_connections.end()) {
        if (it->second.state == ConnectionState::State::Closed) {
            it = m_connections.erase(it);
        } else {
            ++it;
        }
    }
}

bool PacketProcessor::parseIpHeader(const std::vector<uint8_t>& packet,
                                   int& version, int& ihl, int& protocol,
                                   std::string& srcIp, std::string& dstIp) {
    if (packet.size() < 20) return false;
    
    version = (packet[0] >> 4) & 0x0F;
    ihl = (packet[0] & 0x0F) * 4;
    
    if (packet.size() < static_cast<size_t>(ihl)) return false;
    
    protocol = packet[9];
    
    // Source IP
    char ipStr[INET_ADDRSTRLEN];
    struct in_addr addr;
    std::memcpy(&addr.s_addr, &packet[12], 4);
    inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
    srcIp = ipStr;
    
    // Destination IP
    std::memcpy(&addr.s_addr, &packet[16], 4);
    inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));
    dstIp = ipStr;
    
    return true;
}

bool PacketProcessor::parseTcpHeader(const std::vector<uint8_t>& packet, int offset,
                                    uint16_t& srcPort, uint16_t& dstPort,
                                    uint32_t& seqNum, uint32_t& ackNum,
                                    int& flags, int& headerLen) {
    if (packet.size() < static_cast<size_t>(offset + 20)) return false;
    
    srcPort = (packet[offset] << 8) | packet[offset + 1];
    dstPort = (packet[offset + 2] << 8) | packet[offset + 3];
    
    seqNum = (packet[offset + 4] << 24) | (packet[offset + 5] << 16) |
             (packet[offset + 6] << 8) | packet[offset + 7];
    ackNum = (packet[offset + 8] << 24) | (packet[offset + 9] << 16) |
             (packet[offset + 10] << 8) | packet[offset + 11];
    
    headerLen = ((packet[offset + 12] >> 4) & 0x0F) * 4;
    flags = packet[offset + 13];
    
    return true;
}

bool PacketProcessor::isTlsClientHello(const uint8_t* payload, size_t len) {
    if (len < 6) return false;
    
    // TLS record header
    if (payload[0] != 0x16) return false; // Handshake
    
    // Handshake type
    if (payload[5] != 0x01) return false; // ClientHello
    
    return true;
}

std::vector<uint8_t> PacketProcessor::modifyClientHello(const uint8_t* payload, size_t len) {
    ClientHelloMaker maker;
    maker.setFakeSni(m_config.fakeSni);
    maker.setRealSni(m_config.realSni);
    
    // Determine TLS version
    if (m_config.tlsVersion == "tls13") {
        maker.setTlsVersion(ClientHelloMaker::TlsVersion::TLS_1_3);
    } else if (m_config.tlsVersion == "tls11") {
        maker.setTlsVersion(ClientHelloMaker::TlsVersion::TLS_1_1);
    } else if (m_config.tlsVersion == "tls10") {
        maker.setTlsVersion(ClientHelloMaker::TlsVersion::TLS_1_0);
    } else {
        maker.setTlsVersion(ClientHelloMaker::TlsVersion::TLS_1_2);
    }
    
    return maker.modifyClientHello(payload, len);
}

void PacketProcessor::recalculateIpChecksum(std::vector<uint8_t>& packet, int ihl) {
    // Clear old checksum
    packet[10] = 0;
    packet[11] = 0;
    
    uint32_t sum = 0;
    for (int i = 0; i < ihl; i += 2) {
        uint16_t word = (packet[i] << 8) | packet[i + 1];
        sum += word;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    uint16_t checksum = ~sum & 0xFFFF;
    packet[10] = (checksum >> 8) & 0xFF;
    packet[11] = checksum & 0xFF;
}

void PacketProcessor::recalculateTcpChecksum(std::vector<uint8_t>& packet,
                                            int ipOffset, int tcpOffset, int tcpLen) {
    // Clear old checksum
    packet[tcpOffset + 16] = 0;
    packet[tcpOffset + 17] = 0;
    
    uint32_t sum = 0;
    
    // Pseudo header
    // Source IP
    sum += (packet[ipOffset + 12] << 8) | packet[ipOffset + 13];
    sum += (packet[ipOffset + 14] << 8) | packet[ipOffset + 15];
    // Dest IP
    sum += (packet[ipOffset + 16] << 8) | packet[ipOffset + 17];
    sum += (packet[ipOffset + 18] << 8) | packet[ipOffset + 19];
    // Protocol (TCP = 6)
    sum += 6;
    // TCP length
    sum += tcpLen;
    
    // TCP segment
    for (int i = 0; i < tcpLen; i += 2) {
        uint16_t word;
        if (i + 1 < tcpLen) {
            word = (packet[tcpOffset + i] << 8) | packet[tcpOffset + i + 1];
        } else {
            word = packet[tcpOffset + i] << 8;
        }
        sum += word;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    uint16_t checksum = ~sum & 0xFFFF;
    packet[tcpOffset + 16] = (checksum >> 8) & 0xFF;
    packet[tcpOffset + 17] = checksum & 0xFF;
}

uint16_t PacketProcessor::calculateChecksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    
    for (size_t i = 0; i < len; i += 2) {
        uint16_t word;
        if (i + 1 < len) {
            word = (data[i] << 8) | data[i + 1];
        } else {
            word = data[i] << 8;
        }
        sum += word;
    }
    
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum & 0xFFFF;
}

std::vector<std::vector<uint8_t>> PacketProcessor::fragmentPacket(
    const std::vector<uint8_t>& packet, int payloadOffset) {
    
    int fragmentSize = m_config.fragmentSize;
    
    if (m_config.randomizeFragments) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(50, m_config.fragmentSize);
        fragmentSize = dis(gen);
    }
    
    // Check if fragmentation needed
    if (packet.size() - payloadOffset <= static_cast<size_t>(fragmentSize)) {
        return {packet};
    }
    
    std::vector<std::vector<uint8_t>> fragments;
    const uint8_t* payload = packet.data() + payloadOffset;
    size_t payloadLen = packet.size() - payloadOffset;
    size_t offset = 0;
    
    while (offset < payloadLen) {
        size_t chunkSize = std::min(static_cast<size_t>(fragmentSize), payloadLen - offset);
        
        std::vector<uint8_t> fragment(payloadOffset + chunkSize);
        std::memcpy(fragment.data(), packet.data(), payloadOffset);
        std::memcpy(fragment.data() + payloadOffset, payload + offset, chunkSize);
        
        // Update IP length
        uint16_t totalLen = fragment.size();
        fragment[2] = (totalLen >> 8) & 0xFF;
        fragment[3] = totalLen & 0xFF;
        
        // Recalculate IP checksum
        int ihl = (fragment[0] & 0x0F) * 4;
        recalculateIpChecksum(fragment, ihl);
        
        fragments.push_back(fragment);
        offset += chunkSize;
    }
    
    return fragments;
}

} // namespace smartfox
