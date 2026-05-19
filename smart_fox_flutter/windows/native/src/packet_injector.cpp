#include "packet_injector.h"
#include <windivert.h>
#include <sstream>
#include <thread>
#include <chrono>

namespace smartfox {

PacketInjector::PacketInjector() {
}

PacketInjector::~PacketInjector() {
    cleanup();
}

bool PacketInjector::initialize(const std::string& filter) {
    handle_ = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle_ == INVALID_HANDLE_VALUE) {
        return false;
    }
    running_ = true;
    return true;
}

void PacketInjector::stop() {
    running_ = false;
}

void PacketInjector::cleanup() {
    running_ = false;
    if (handle_) {
        WinDivertClose(handle_);
        handle_ = nullptr;
    }
}

void PacketInjector::run() {
    uint8_t packet[65535];
    UINT packetLen;
    WINDIVERT_ADDRESS addr;
    
    while (running_ && handle_) {
        if (WinDivertRecv(handle_, packet, sizeof(packet), &packetLen, &addr)) {
            processPacket(packet, packetLen, &addr);
        }
    }
}

void PacketInjector::registerConnection(const ConnectionId& id, std::shared_ptr<FakeConnection> conn) {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    connections_[id] = conn;
}

void PacketInjector::unregisterConnection(const ConnectionId& id) {
    std::lock_guard<std::mutex> lock(connectionsMutex_);
    connections_.erase(id);
}

bool PacketInjector::waitForAck(const ConnectionId& id, int timeoutMs) {
    auto start = std::chrono::steady_clock::now();
    
    while (std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count() < timeoutMs) {
        
        std::shared_ptr<FakeConnection> conn;
        {
            std::lock_guard<std::mutex> lock(connectionsMutex_);
            auto it = connections_.find(id);
            if (it == connections_.end()) {
                return false;
            }
            conn = it->second;
        }
        
        if (conn->ackReceived.load()) {
            return true;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    
    return false;
}

void PacketInjector::processPacket(uint8_t* packetData, size_t packetLen, WINDIVERT_ADDRESS* addr) {
    // Parse IP header
    if (packetLen < 20) {
        WinDivertSend(handle_, packetData, (UINT)packetLen, nullptr, addr);
        return;
    }
    
    uint8_t ipVersion = packet::getIpVersion(packetData);
    if (ipVersion != 4) {
        // Only handle IPv4 for now
        WinDivertSend(handle_, packetData, (UINT)packetLen, nullptr, addr);
        return;
    }
    
    // Check if TCP
    if (packetData[9] != 6) { // Protocol field
        WinDivertSend(handle_, packetData, (UINT)packetLen, nullptr, addr);
        return;
    }
    
    // Build connection ID
    ConnectionId id;
    if (addr->Outbound) {
        id.srcIp = packet::getSrcIp(packetData);
        id.srcPort = packet::getTcpSrcPort(packetData);
        id.dstIp = packet::getDstIp(packetData);
        id.dstPort = packet::getTcpDstPort(packetData);
    } else {
        id.srcIp = packet::getDstIp(packetData);
        id.srcPort = packet::getTcpDstPort(packetData);
        id.dstIp = packet::getSrcIp(packetData);
        id.dstPort = packet::getTcpSrcPort(packetData);
    }
    
    // Look up connection
    std::shared_ptr<FakeConnection> conn;
    {
        std::lock_guard<std::mutex> lock(connectionsMutex_);
        auto it = connections_.find(id);
        if (it == connections_.end()) {
            WinDivertSend(handle_, packetData, (UINT)packetLen, nullptr, addr);
            return;
        }
        conn = it->second;
    }
    
    // Process based on direction
    std::lock_guard<std::mutex> connLock(conn->lock);
    
    if (!conn->monitor) {
        WinDivertSend(handle_, packetData, (UINT)packetLen, nullptr, addr);
        return;
    }
    
    if (addr->Outbound) {
        onOutboundPacket(packetData, packetLen, addr, conn);
    } else {
        onInboundPacket(packetData, packetLen, addr, conn);
    }
}

void PacketInjector::onInboundPacket(uint8_t* packetData, size_t packetLen, WINDIVERT_ADDRESS* addr,
                                     std::shared_ptr<FakeConnection> conn) {
    uint8_t flags = packet::getTcpFlags(packetData);
    uint32_t seqNum = packet::getTcpSeqNum(packetData);
    uint32_t ackNum = packet::getTcpAckNum(packetData);
    size_t payloadLen = packet::getTcpPayloadLen(packetData);
    
    // Check for SYN-ACK
    if ((flags & (packet::TCP_SYN | packet::TCP_ACK)) == (packet::TCP_SYN | packet::TCP_ACK) &&
        !(flags & packet::TCP_RST) && !(flags & packet::TCP_FIN) && payloadLen == 0) {
        
        // Validate
        if (conn->synSeq == 0xFFFFFFFF) {
            onUnexpectedPacket(packetData, addr, conn, "unexpected inbound SYN-ACK, no SYN sent");
            return;
        }
        
        if (conn->synAckSeq != 0xFFFFFFFF && conn->synAckSeq != seqNum) {
            onUnexpectedPacket(packetData, addr, conn, "unexpected SYN-ACK seq change");
            return;
        }
        
        if (ackNum != ((conn->synSeq + 1) & 0xFFFFFFFF)) {
            onUnexpectedPacket(packetData, addr, conn, "SYN-ACK ack mismatch");
            return;
        }
        
        conn->synAckSeq = seqNum;
        WinDivertSend(handle_, packetData, (UINT)packetLen, nullptr, addr);
        return;
    }
    
    // Check for ACK (response to fake data)
    if ((flags & packet::TCP_ACK) && !(flags & packet::TCP_SYN) && 
        !(flags & packet::TCP_RST) && !(flags & packet::TCP_FIN) &&
        payloadLen == 0 && conn->fakeSent) {
        
        if (conn->synAckSeq == 0xFFFFFFFF || 
            seqNum != ((conn->synAckSeq + 1) & 0xFFFFFFFF)) {
            onUnexpectedPacket(packetData, addr, conn, "ACK seq mismatch");
            return;
        }
        
        if (ackNum != ((conn->synSeq + 1) & 0xFFFFFFFF)) {
            onUnexpectedPacket(packetData, addr, conn, "ACK ack mismatch");
            return;
        }
        
        conn->monitor = false;
        conn->t2aMsg = "fake_data_ack_recv";
        conn->ackReceived = true;
        return;
    }
    
    onUnexpectedPacket(packetData, addr, conn, "unexpected inbound packet");
}

void PacketInjector::onOutboundPacket(uint8_t* packetData, size_t packetLen, WINDIVERT_ADDRESS* addr,
                                      std::shared_ptr<FakeConnection> conn) {
    uint8_t flags = packet::getTcpFlags(packetData);
    uint32_t seqNum = packet::getTcpSeqNum(packetData);
    uint32_t ackNum = packet::getTcpAckNum(packetData);
    size_t payloadLen = packet::getTcpPayloadLen(packetData);
    
    if (conn->schFakeSent) {
        onUnexpectedPacket(packetData, addr, conn, "outbound packet after fake sent");
        return;
    }
    
    // Check for SYN
    if ((flags & packet::TCP_SYN) && !(flags & packet::TCP_ACK) &&
        !(flags & packet::TCP_RST) && !(flags & packet::TCP_FIN) && payloadLen == 0) {
        
        if (ackNum != 0) {
            onUnexpectedPacket(packetData, addr, conn, "SYN ack_num not zero");
            return;
        }
        
        if (conn->synSeq != 0xFFFFFFFF && conn->synSeq != seqNum) {
            onUnexpectedPacket(packetData, addr, conn, "SYN seq mismatch");
            return;
        }
        
        conn->synSeq = seqNum;
        WinDivertSend(handle_, packetData, (UINT)packetLen, nullptr, addr);
        return;
    }
    
    // Check for ACK (after SYN-ACK received)
    if ((flags & packet::TCP_ACK) && !(flags & packet::TCP_SYN) &&
        !(flags & packet::TCP_RST) && !(flags & packet::TCP_FIN) && payloadLen == 0) {
        
        if (conn->synSeq == 0xFFFFFFFF || 
            seqNum != ((conn->synSeq + 1) & 0xFFFFFFFF)) {
            onUnexpectedPacket(packetData, addr, conn, "ACK seq mismatch");
            return;
        }
        
        if (conn->synAckSeq == 0xFFFFFFFF ||
            ackNum != ((conn->synAckSeq + 1) & 0xFFFFFFFF)) {
            onUnexpectedPacket(packetData, addr, conn, "ACK ack mismatch");
            return;
        }
        
        // Send the original ACK
        WinDivertSend(handle_, packetData, (UINT)packetLen, nullptr, addr);
        
        // Schedule fake data injection
        conn->schFakeSent = true;
        
        // Delay and send fake packet
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        sendFakeData(packetData, packetLen, addr, conn);
        return;
    }
    
    onUnexpectedPacket(packetData, addr, conn, "unexpected outbound packet");
}

void PacketInjector::sendFakeData(uint8_t* packetData, size_t packetLen, WINDIVERT_ADDRESS* addr,
                                  std::shared_ptr<FakeConnection> conn) {
    if (!conn->monitor) {
        return;
    }
    
    // Create packet with fake data
    // We need to modify the sequence number to be "wrong" for DPI bypass
    
    std::vector<uint8_t> fakePacket(packetLen + conn->fakeData.size());
    std::memcpy(fakePacket.data(), packetData, packetLen);
    
    // Get TCP header offset
    size_t tcpOffset = packet::getTcpHeaderOffset(fakePacket.data());
    size_t payloadOffset = packet::getTcpPayloadOffset(fakePacket.data());
    
    // Set PSH flag
    uint8_t flags = packet::getTcpFlags(fakePacket.data());
    packet::setTcpFlags(fakePacket.data(), flags | packet::TCP_PSH);
    
    // Update IP total length
    uint16_t newLen = packet::getIpTotalLen(fakePacket.data()) + (uint16_t)conn->fakeData.size();
    packet::setIpTotalLen(fakePacket.data(), newLen);
    
    // Update IP ident
    uint16_t ident = packet::getIpIdent(fakePacket.data());
    packet::setIpIdent(fakePacket.data(), ident + 1);
    
    // Set wrong sequence number (for DPI bypass)
    uint32_t wrongSeq = (conn->synSeq + 1 - (uint32_t)conn->fakeData.size()) & 0xFFFFFFFF;
    packet::setTcpSeqNum(fakePacket.data(), wrongSeq);
    
    // Add payload
    std::memcpy(fakePacket.data() + payloadOffset, conn->fakeData.data(), conn->fakeData.size());
    
    conn->fakeSent = true;
    
    // Send with recalculated checksum
    WinDivertSend(handle_, fakePacket.data(), (UINT)fakePacket.size(), nullptr, addr);
}

void PacketInjector::onUnexpectedPacket(uint8_t* packetData, WINDIVERT_ADDRESS* addr,
                                        std::shared_ptr<FakeConnection> conn, const std::string& reason) {
    log("Unexpected packet: " + reason);
    
    conn->monitor = false;
    conn->t2aMsg = "unexpected_close";
    conn->ackReceived = true;
    
    // Send the packet anyway
    WinDivertSend(handle_, packetData, packet::getIpTotalLen(packetData), nullptr, addr);
}

void PacketInjector::log(const std::string& message) {
    if (logCallback_) {
        logCallback_(message);
    }
}

// Packet parsing helper functions
namespace packet {

uint8_t getIpVersion(const uint8_t* packet) {
    return (packet[0] >> 4) & 0x0F;
}

size_t getIpHeaderLen(const uint8_t* packet) {
    return (packet[0] & 0x0F) * 4;
}

std::string getSrcIp(const uint8_t* packet) {
    char buf[INET_ADDRSTRLEN];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
             packet[12], packet[13], packet[14], packet[15]);
    return buf;
}

std::string getDstIp(const uint8_t* packet) {
    char buf[INET_ADDRSTRLEN];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
             packet[16], packet[17], packet[18], packet[19]);
    return buf;
}

uint16_t getIpTotalLen(const uint8_t* packet) {
    return (packet[2] << 8) | packet[3];
}

void setIpTotalLen(uint8_t* packet, uint16_t len) {
    packet[2] = (len >> 8) & 0xFF;
    packet[3] = len & 0xFF;
}

uint16_t getIpIdent(const uint8_t* packet) {
    return (packet[4] << 8) | packet[5];
}

void setIpIdent(uint8_t* packet, uint16_t ident) {
    packet[4] = (ident >> 8) & 0xFF;
    packet[5] = ident & 0xFF;
}

size_t getTcpHeaderOffset(const uint8_t* packet) {
    return getIpHeaderLen(packet);
}

uint16_t getTcpSrcPort(const uint8_t* packet) {
    size_t off = getTcpHeaderOffset(packet);
    return (packet[off] << 8) | packet[off + 1];
}

uint16_t getTcpDstPort(const uint8_t* packet) {
    size_t off = getTcpHeaderOffset(packet);
    return (packet[off + 2] << 8) | packet[off + 3];
}

uint32_t getTcpSeqNum(const uint8_t* packet) {
    size_t off = getTcpHeaderOffset(packet);
    return ((uint32_t)packet[off + 4] << 24) |
           ((uint32_t)packet[off + 5] << 16) |
           ((uint32_t)packet[off + 6] << 8) |
           (uint32_t)packet[off + 7];
}

void setTcpSeqNum(uint8_t* packet, uint32_t seq) {
    size_t off = getTcpHeaderOffset(packet);
    packet[off + 4] = (seq >> 24) & 0xFF;
    packet[off + 5] = (seq >> 16) & 0xFF;
    packet[off + 6] = (seq >> 8) & 0xFF;
    packet[off + 7] = seq & 0xFF;
}

uint32_t getTcpAckNum(const uint8_t* packet) {
    size_t off = getTcpHeaderOffset(packet);
    return ((uint32_t)packet[off + 8] << 24) |
           ((uint32_t)packet[off + 9] << 16) |
           ((uint32_t)packet[off + 10] << 8) |
           (uint32_t)packet[off + 11];
}

uint8_t getTcpFlags(const uint8_t* packet) {
    size_t off = getTcpHeaderOffset(packet);
    return packet[off + 13];
}

void setTcpFlags(uint8_t* packet, uint8_t flags) {
    size_t off = getTcpHeaderOffset(packet);
    packet[off + 13] = flags;
}

size_t getTcpHeaderLen(const uint8_t* packet) {
    size_t off = getTcpHeaderOffset(packet);
    return ((packet[off + 12] >> 4) & 0x0F) * 4;
}

size_t getTcpPayloadOffset(const uint8_t* packet) {
    return getTcpHeaderOffset(packet) + getTcpHeaderLen(packet);
}

size_t getTcpPayloadLen(const uint8_t* packet) {
    size_t ipTotalLen = getIpTotalLen(packet);
    size_t ipHeaderLen = getIpHeaderLen(packet);
    size_t tcpHeaderLen = getTcpHeaderLen(packet);
    
    if (ipTotalLen < ipHeaderLen + tcpHeaderLen) {
        return 0;
    }
    return ipTotalLen - ipHeaderLen - tcpHeaderLen;
}

} // namespace packet

} // namespace smartfox
