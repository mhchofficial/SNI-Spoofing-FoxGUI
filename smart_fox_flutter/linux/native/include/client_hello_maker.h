#ifndef CLIENT_HELLO_MAKER_H
#define CLIENT_HELLO_MAKER_H

#include <vector>
#include <cstdint>
#include <string>

namespace smartfox {

/**
 * TLS ClientHello builder for SNI spoofing
 * Creates properly formatted ClientHello packets with fake SNI
 */
class ClientHelloMaker {
public:
    enum class TlsVersion {
        TLS_1_0,
        TLS_1_1,
        TLS_1_2,
        TLS_1_3
    };
    
    ClientHelloMaker();
    ~ClientHelloMaker() = default;
    
    // Configuration
    void setTlsVersion(TlsVersion version) { m_version = version; }
    void setFakeSni(const std::string& sni) { m_fakeSni = sni; }
    void setRealSni(const std::string& sni) { m_realSni = sni; }
    
    /**
     * Build a complete TLS ClientHello message
     */
    std::vector<uint8_t> buildClientHello();
    
    /**
     * Modify existing ClientHello to replace SNI
     */
    std::vector<uint8_t> modifyClientHello(const uint8_t* data, size_t len);
    
    /**
     * Build SNI extension only
     */
    std::vector<uint8_t> buildSniExtension(const std::string& hostname);
    
    /**
     * Find and extract SNI from ClientHello
     */
    std::string extractSni(const uint8_t* data, size_t len);

private:
    // Helper methods
    std::vector<uint8_t> buildExtensions();
    std::vector<uint8_t> buildSupportedVersionsExtension();
    std::vector<uint8_t> buildSupportedGroupsExtension();
    std::vector<uint8_t> buildSignatureAlgorithmsExtension();
    std::vector<uint8_t> buildKeyShareExtension();
    std::vector<uint8_t> buildPskKeyExchangeModesExtension();
    std::vector<uint8_t> buildAlpnExtension();
    std::vector<uint8_t> buildPaddingExtension(size_t targetLen);
    
    void generateRandom(uint8_t* buffer, size_t len);
    
    TlsVersion m_version = TlsVersion::TLS_1_2;
    std::string m_fakeSni;
    std::string m_realSni;
    
    // TLS constants
    static constexpr uint8_t TLS_HANDSHAKE = 0x16;
    static constexpr uint8_t TLS_CLIENT_HELLO = 0x01;
    
    // Extension types
    static constexpr uint16_t EXT_SNI = 0x0000;
    static constexpr uint16_t EXT_STATUS_REQUEST = 0x0005;
    static constexpr uint16_t EXT_SUPPORTED_GROUPS = 0x000A;
    static constexpr uint16_t EXT_EC_POINT_FORMATS = 0x000B;
    static constexpr uint16_t EXT_SIGNATURE_ALGORITHMS = 0x000D;
    static constexpr uint16_t EXT_ALPN = 0x0010;
    static constexpr uint16_t EXT_SIGNED_CERT_TIMESTAMP = 0x0012;
    static constexpr uint16_t EXT_PADDING = 0x0015;
    static constexpr uint16_t EXT_EXTENDED_MASTER_SECRET = 0x0017;
    static constexpr uint16_t EXT_SESSION_TICKET = 0x0023;
    static constexpr uint16_t EXT_SUPPORTED_VERSIONS = 0x002B;
    static constexpr uint16_t EXT_PSK_KEY_EXCHANGE_MODES = 0x002D;
    static constexpr uint16_t EXT_KEY_SHARE = 0x0033;
    static constexpr uint16_t EXT_RENEGOTIATION_INFO = 0xFF01;
};

} // namespace smartfox

#endif // CLIENT_HELLO_MAKER_H
