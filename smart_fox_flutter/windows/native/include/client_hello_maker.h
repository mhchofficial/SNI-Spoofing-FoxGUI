#ifndef CLIENT_HELLO_MAKER_H
#define CLIENT_HELLO_MAKER_H

#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>

namespace smartfox {

class ClientHelloMaker {
public:
    // Create a TLS ClientHello packet with the specified parameters
    // rnd, sessId, keyShare must be 32 bytes each
    // targetSni must be ASCII and max 219 bytes
    static std::vector<uint8_t> getClientHelloWith(
        const uint8_t* rnd,
        const uint8_t* sessId,
        const std::string& targetSni,
        const uint8_t* keyShare
    );

    // Parse a ClientHello packet
    // Returns tuple of (rnd, sessId, sni, keyShare)
    static void parseClientHello(
        const uint8_t* data, size_t len,
        uint8_t* outRnd,
        uint8_t* outSessId,
        std::string& outSni,
        uint8_t* outKeyShare
    );

    // Create a client response with change cipher spec and app data
    static std::vector<uint8_t> getClientResponseWith(const uint8_t* appData, size_t appDataLen);

    // TLS record headers
    static const uint8_t TLS_CHANGE_CIPHER[6];
    static const uint8_t TLS_APP_DATA_HEADER[3];

private:
    // Template components
    static const uint8_t STATIC1[11];
    static const uint8_t STATIC2[1];
    static const uint8_t STATIC3[44];
    static const uint8_t STATIC4[135];
    static const uint8_t STATIC5[2];
};

class ServerHelloMaker {
public:
    // Create a TLS ServerHello packet
    static std::vector<uint8_t> getServerHelloWith(
        const uint8_t* rnd,
        const uint8_t* sessId,
        const uint8_t* keyShare,
        const uint8_t* appData,
        size_t appDataLen
    );

    // Parse a ServerHello packet
    static void parseServerHello(
        const uint8_t* data, size_t len,
        uint8_t* outRnd,
        uint8_t* outSessId,
        uint8_t* outKeyShare,
        std::vector<uint8_t>& outAppData
    );

private:
    static const uint8_t STATIC1[11];
    static const uint8_t STATIC2[1];
    static const uint8_t STATIC3[19];
};

} // namespace smartfox

#endif // CLIENT_HELLO_MAKER_H
