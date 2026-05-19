#include "client_hello_maker.h"

#include <cstring>
#include <random>
#include <algorithm>

namespace smartfox {

ClientHelloMaker::ClientHelloMaker() = default;

void ClientHelloMaker::generateRandom(uint8_t* buffer, size_t len) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < len; ++i) {
        buffer[i] = static_cast<uint8_t>(dis(gen));
    }
}

std::vector<uint8_t> ClientHelloMaker::buildClientHello() {
    std::vector<uint8_t> result;
    
    // TLS Record Header
    result.push_back(TLS_HANDSHAKE); // Content type
    result.push_back(0x03); // Version major (TLS 1.0 in record layer for compatibility)
    result.push_back(0x01); // Version minor
    
    // Placeholder for record length (2 bytes)
    size_t recordLengthPos = result.size();
    result.push_back(0x00);
    result.push_back(0x00);
    
    // Handshake Header
    result.push_back(TLS_CLIENT_HELLO); // Handshake type
    
    // Placeholder for handshake length (3 bytes)
    size_t handshakeLengthPos = result.size();
    result.push_back(0x00);
    result.push_back(0x00);
    result.push_back(0x00);
    
    // Client Version
    switch (m_version) {
        case TlsVersion::TLS_1_0:
            result.push_back(0x03); result.push_back(0x01);
            break;
        case TlsVersion::TLS_1_1:
            result.push_back(0x03); result.push_back(0x02);
            break;
        case TlsVersion::TLS_1_3:
            // TLS 1.3 uses 1.2 version in ClientHello for compatibility
        case TlsVersion::TLS_1_2:
        default:
            result.push_back(0x03); result.push_back(0x03);
            break;
    }
    
    // Random (32 bytes)
    size_t randomPos = result.size();
    result.resize(result.size() + 32);
    generateRandom(result.data() + randomPos, 32);
    
    // Session ID (empty)
    result.push_back(0x00);
    
    // Cipher Suites
    std::vector<uint16_t> cipherSuites = {
        0x1301, // TLS_AES_128_GCM_SHA256
        0x1302, // TLS_AES_256_GCM_SHA384
        0x1303, // TLS_CHACHA20_POLY1305_SHA256
        0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0x009f, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
        0x009e, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    };
    
    uint16_t cipherSuitesLen = cipherSuites.size() * 2;
    result.push_back((cipherSuitesLen >> 8) & 0xFF);
    result.push_back(cipherSuitesLen & 0xFF);
    
    for (uint16_t cs : cipherSuites) {
        result.push_back((cs >> 8) & 0xFF);
        result.push_back(cs & 0xFF);
    }
    
    // Compression Methods (null only)
    result.push_back(0x01); // Length
    result.push_back(0x00); // Null compression
    
    // Extensions
    auto extensions = buildExtensions();
    uint16_t extensionsLen = extensions.size();
    result.push_back((extensionsLen >> 8) & 0xFF);
    result.push_back(extensionsLen & 0xFF);
    result.insert(result.end(), extensions.begin(), extensions.end());
    
    // Update lengths
    uint16_t recordLength = result.size() - 5;
    result[recordLengthPos] = (recordLength >> 8) & 0xFF;
    result[recordLengthPos + 1] = recordLength & 0xFF;
    
    uint32_t handshakeLength = result.size() - handshakeLengthPos - 3;
    result[handshakeLengthPos] = (handshakeLength >> 16) & 0xFF;
    result[handshakeLengthPos + 1] = (handshakeLength >> 8) & 0xFF;
    result[handshakeLengthPos + 2] = handshakeLength & 0xFF;
    
    return result;
}

std::vector<uint8_t> ClientHelloMaker::modifyClientHello(const uint8_t* data, size_t len) {
    if (len < 43) { // Minimum ClientHello size
        return std::vector<uint8_t>(data, data + len);
    }
    
    std::vector<uint8_t> result;
    
    // Copy TLS record header (5 bytes)
    result.insert(result.end(), data, data + 5);
    
    size_t offset = 5;
    
    // Handshake type (1 byte)
    result.push_back(data[offset++]);
    
    // Handshake length (3 bytes) - will update later
    size_t handshakeLengthPos = result.size();
    result.insert(result.end(), data + offset, data + offset + 3);
    offset += 3;
    
    // Client version (2 bytes)
    result.insert(result.end(), data + offset, data + offset + 2);
    offset += 2;
    
    // Random (32 bytes)
    result.insert(result.end(), data + offset, data + offset + 32);
    offset += 32;
    
    // Session ID
    uint8_t sessionIdLen = data[offset];
    result.push_back(sessionIdLen);
    offset++;
    if (sessionIdLen > 0) {
        result.insert(result.end(), data + offset, data + offset + sessionIdLen);
        offset += sessionIdLen;
    }
    
    // Cipher suites
    uint16_t cipherSuitesLen = (data[offset] << 8) | data[offset + 1];
    result.push_back(data[offset]);
    result.push_back(data[offset + 1]);
    offset += 2;
    result.insert(result.end(), data + offset, data + offset + cipherSuitesLen);
    offset += cipherSuitesLen;
    
    // Compression methods
    uint8_t compressionLen = data[offset];
    result.push_back(compressionLen);
    offset++;
    result.insert(result.end(), data + offset, data + offset + compressionLen);
    offset += compressionLen;
    
    // Extensions
    if (offset + 2 <= len) {
        uint16_t extensionsLen = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        
        std::vector<uint8_t> newExtensions;
        size_t extEnd = offset + extensionsLen;
        
        while (offset + 4 <= extEnd && offset + 4 <= len) {
            uint16_t extType = (data[offset] << 8) | data[offset + 1];
            uint16_t extLen = (data[offset + 2] << 8) | data[offset + 3];
            
            if (offset + 4 + extLen > len) break;
            
            if (extType == EXT_SNI) {
                // Replace with fake SNI
                auto sniExt = buildSniExtension(m_fakeSni);
                newExtensions.insert(newExtensions.end(), sniExt.begin(), sniExt.end());
            } else {
                // Copy extension as-is
                newExtensions.insert(newExtensions.end(), data + offset, data + offset + 4 + extLen);
            }
            
            offset += 4 + extLen;
        }
        
        // Write extensions length and data
        uint16_t newExtLen = newExtensions.size();
        result.push_back((newExtLen >> 8) & 0xFF);
        result.push_back(newExtLen & 0xFF);
        result.insert(result.end(), newExtensions.begin(), newExtensions.end());
    }
    
    // Update TLS record length
    uint16_t recordLength = result.size() - 5;
    result[3] = (recordLength >> 8) & 0xFF;
    result[4] = recordLength & 0xFF;
    
    // Update handshake length
    uint32_t handshakeLength = result.size() - handshakeLengthPos - 3;
    result[handshakeLengthPos] = (handshakeLength >> 16) & 0xFF;
    result[handshakeLengthPos + 1] = (handshakeLength >> 8) & 0xFF;
    result[handshakeLengthPos + 2] = handshakeLength & 0xFF;
    
    return result;
}

std::vector<uint8_t> ClientHelloMaker::buildSniExtension(const std::string& hostname) {
    std::vector<uint8_t> result;
    
    // Extension type
    result.push_back(0x00);
    result.push_back(0x00);
    
    // Calculate lengths
    uint16_t hostnameLen = hostname.size();
    uint16_t sniListLen = hostnameLen + 3; // type (1) + length (2) + hostname
    uint16_t extLen = sniListLen + 2; // list length (2) + list
    
    // Extension length
    result.push_back((extLen >> 8) & 0xFF);
    result.push_back(extLen & 0xFF);
    
    // SNI list length
    result.push_back((sniListLen >> 8) & 0xFF);
    result.push_back(sniListLen & 0xFF);
    
    // Host name type (0 = DNS hostname)
    result.push_back(0x00);
    
    // Host name length
    result.push_back((hostnameLen >> 8) & 0xFF);
    result.push_back(hostnameLen & 0xFF);
    
    // Host name
    result.insert(result.end(), hostname.begin(), hostname.end());
    
    return result;
}

std::string ClientHelloMaker::extractSni(const uint8_t* data, size_t len) {
    if (len < 43) return "";
    
    size_t offset = 5 + 1 + 3 + 2 + 32; // Record + handshake header + version + random
    
    // Skip session ID
    if (offset >= len) return "";
    uint8_t sessionIdLen = data[offset++];
    offset += sessionIdLen;
    
    // Skip cipher suites
    if (offset + 2 > len) return "";
    uint16_t cipherSuitesLen = (data[offset] << 8) | data[offset + 1];
    offset += 2 + cipherSuitesLen;
    
    // Skip compression
    if (offset >= len) return "";
    uint8_t compressionLen = data[offset++];
    offset += compressionLen;
    
    // Parse extensions
    if (offset + 2 > len) return "";
    uint16_t extensionsLen = (data[offset] << 8) | data[offset + 1];
    offset += 2;
    
    size_t extEnd = offset + extensionsLen;
    
    while (offset + 4 <= extEnd && offset + 4 <= len) {
        uint16_t extType = (data[offset] << 8) | data[offset + 1];
        uint16_t extLen = (data[offset + 2] << 8) | data[offset + 3];
        offset += 4;
        
        if (extType == EXT_SNI && offset + extLen <= len) {
            // Parse SNI extension
            if (extLen >= 5) {
                uint16_t sniListLen = (data[offset] << 8) | data[offset + 1];
                uint8_t nameType = data[offset + 2];
                uint16_t nameLen = (data[offset + 3] << 8) | data[offset + 4];
                
                if (nameType == 0 && offset + 5 + nameLen <= len) {
                    return std::string(reinterpret_cast<const char*>(data + offset + 5), nameLen);
                }
            }
        }
        
        offset += extLen;
    }
    
    return "";
}

std::vector<uint8_t> ClientHelloMaker::buildExtensions() {
    std::vector<uint8_t> result;
    
    // SNI extension
    auto sni = buildSniExtension(m_fakeSni);
    result.insert(result.end(), sni.begin(), sni.end());
    
    // Supported versions (for TLS 1.3)
    if (m_version == TlsVersion::TLS_1_3) {
        auto sv = buildSupportedVersionsExtension();
        result.insert(result.end(), sv.begin(), sv.end());
    }
    
    // Supported groups
    auto sg = buildSupportedGroupsExtension();
    result.insert(result.end(), sg.begin(), sg.end());
    
    // Signature algorithms
    auto sa = buildSignatureAlgorithmsExtension();
    result.insert(result.end(), sa.begin(), sa.end());
    
    // ALPN
    auto alpn = buildAlpnExtension();
    result.insert(result.end(), alpn.begin(), alpn.end());
    
    // PSK key exchange modes (for TLS 1.3)
    if (m_version == TlsVersion::TLS_1_3) {
        auto psk = buildPskKeyExchangeModesExtension();
        result.insert(result.end(), psk.begin(), psk.end());
        
        auto ks = buildKeyShareExtension();
        result.insert(result.end(), ks.begin(), ks.end());
    }
    
    // Extended master secret
    result.push_back(0x00);
    result.push_back(0x17);
    result.push_back(0x00);
    result.push_back(0x00);
    
    // Renegotiation info
    result.push_back(0xFF);
    result.push_back(0x01);
    result.push_back(0x00);
    result.push_back(0x01);
    result.push_back(0x00);
    
    return result;
}

std::vector<uint8_t> ClientHelloMaker::buildSupportedVersionsExtension() {
    std::vector<uint8_t> result;
    
    result.push_back(0x00);
    result.push_back(0x2B); // supported_versions
    result.push_back(0x00);
    result.push_back(0x05); // Extension length
    result.push_back(0x04); // Versions length
    result.push_back(0x03);
    result.push_back(0x04); // TLS 1.3
    result.push_back(0x03);
    result.push_back(0x03); // TLS 1.2
    
    return result;
}

std::vector<uint8_t> ClientHelloMaker::buildSupportedGroupsExtension() {
    std::vector<uint8_t> result;
    
    result.push_back(0x00);
    result.push_back(0x0A); // supported_groups
    result.push_back(0x00);
    result.push_back(0x08); // Extension length
    result.push_back(0x00);
    result.push_back(0x06); // Groups length
    result.push_back(0x00);
    result.push_back(0x1D); // x25519
    result.push_back(0x00);
    result.push_back(0x17); // secp256r1
    result.push_back(0x00);
    result.push_back(0x18); // secp384r1
    
    return result;
}

std::vector<uint8_t> ClientHelloMaker::buildSignatureAlgorithmsExtension() {
    std::vector<uint8_t> result;
    
    result.push_back(0x00);
    result.push_back(0x0D); // signature_algorithms
    result.push_back(0x00);
    result.push_back(0x0E); // Extension length
    result.push_back(0x00);
    result.push_back(0x0C); // Algorithms length
    
    // ecdsa_secp256r1_sha256
    result.push_back(0x04);
    result.push_back(0x03);
    // ecdsa_secp384r1_sha384
    result.push_back(0x05);
    result.push_back(0x03);
    // rsa_pss_rsae_sha256
    result.push_back(0x08);
    result.push_back(0x04);
    // rsa_pss_rsae_sha384
    result.push_back(0x08);
    result.push_back(0x05);
    // rsa_pkcs1_sha256
    result.push_back(0x04);
    result.push_back(0x01);
    // rsa_pkcs1_sha384
    result.push_back(0x05);
    result.push_back(0x01);
    
    return result;
}

std::vector<uint8_t> ClientHelloMaker::buildKeyShareExtension() {
    std::vector<uint8_t> result;
    
    result.push_back(0x00);
    result.push_back(0x33); // key_share
    result.push_back(0x00);
    result.push_back(0x26); // Extension length
    result.push_back(0x00);
    result.push_back(0x24); // Key share entries length
    
    // x25519 key share
    result.push_back(0x00);
    result.push_back(0x1D); // x25519
    result.push_back(0x00);
    result.push_back(0x20); // Key length (32 bytes)
    
    // Generate random key share
    size_t pos = result.size();
    result.resize(result.size() + 32);
    generateRandom(result.data() + pos, 32);
    
    return result;
}

std::vector<uint8_t> ClientHelloMaker::buildPskKeyExchangeModesExtension() {
    std::vector<uint8_t> result;
    
    result.push_back(0x00);
    result.push_back(0x2D); // psk_key_exchange_modes
    result.push_back(0x00);
    result.push_back(0x02); // Extension length
    result.push_back(0x01); // Modes length
    result.push_back(0x01); // psk_dhe_ke
    
    return result;
}

std::vector<uint8_t> ClientHelloMaker::buildAlpnExtension() {
    std::vector<uint8_t> result;
    
    result.push_back(0x00);
    result.push_back(0x10); // application_layer_protocol_negotiation
    result.push_back(0x00);
    result.push_back(0x0E); // Extension length
    result.push_back(0x00);
    result.push_back(0x0C); // ALPN list length
    
    // h2
    result.push_back(0x02);
    result.push_back('h');
    result.push_back('2');
    
    // http/1.1
    result.push_back(0x08);
    result.push_back('h');
    result.push_back('t');
    result.push_back('t');
    result.push_back('p');
    result.push_back('/');
    result.push_back('1');
    result.push_back('.');
    result.push_back('1');
    
    return result;
}

std::vector<uint8_t> ClientHelloMaker::buildPaddingExtension(size_t targetLen) {
    std::vector<uint8_t> result;
    
    if (targetLen < 4) return result;
    
    result.push_back(0x00);
    result.push_back(0x15); // padding
    
    uint16_t paddingLen = targetLen - 4;
    result.push_back((paddingLen >> 8) & 0xFF);
    result.push_back(paddingLen & 0xFF);
    
    result.resize(result.size() + paddingLen, 0x00);
    
    return result;
}

} // namespace smartfox
