#include "client_hello_maker.h"
#include <cstring>
#include <algorithm>

namespace smartfox {

// TLS ClientHello template (from Python code)
static const char* TLS_CH_TEMPLATE_HEX = 
    "1603010200010001fc030341d5b549d9cd1adfa7296c8418d157dc7b624c842824ff493b9375bb48d34f2b20bf018bcc90a7c89a230094815ad0c15b736e38c01209d72d282cb5e2105328150024130213031301c02cc030c02bc02fcca9cca8c024c028c023c027009f009e006b006700ff0100018f0000000b00090000066d63692e6972000b000403000102000a00160014001d0017001e0019001801000101010201030104002300000010000e000c02683208687474702f312e310016000000170000000d002a0028040305030603080708080809080a080b080408050806040105010601030303010302040205020602002b00050403040303002d00020101003300260024001d0020435bacc4d05f9d41fef44ab3ad55616c36e0613473e2338770efdaa98693d217001500d5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

static std::vector<uint8_t> hexToBytes(const char* hex) {
    size_t len = strlen(hex) / 2;
    std::vector<uint8_t> result(len);
    for (size_t i = 0; i < len; i++) {
        char byte[3] = {hex[i*2], hex[i*2+1], 0};
        result[i] = (uint8_t)strtoul(byte, nullptr, 16);
    }
    return result;
}

static std::vector<uint8_t> g_tlsChTemplate;
static const char* TEMPLATE_SNI = "mci.ir";

static void ensureTemplateInit() {
    if (g_tlsChTemplate.empty()) {
        g_tlsChTemplate = hexToBytes(TLS_CH_TEMPLATE_HEX);
    }
}

// Template components (lazy initialized)
const uint8_t ClientHelloMaker::TLS_CHANGE_CIPHER[6] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
const uint8_t ClientHelloMaker::TLS_APP_DATA_HEADER[3] = {0x17, 0x03, 0x03};

std::vector<uint8_t> ClientHelloMaker::getClientHelloWith(
    const uint8_t* rnd,
    const uint8_t* sessId,
    const std::string& targetSni,
    const uint8_t* keyShare
) {
    ensureTemplateInit();
    
    // Validation
    if (targetSni.empty()) {
        throw std::invalid_argument("targetSni must not be empty");
    }
    if (targetSni.length() > 219) {
        throw std::invalid_argument("targetSni is too long for the template");
    }
    for (char c : targetSni) {
        if ((uint8_t)c > 0x7F) {
            throw std::invalid_argument("targetSni must be ASCII");
        }
    }
    
    size_t templateSniLen = strlen(TEMPLATE_SNI);
    
    // Extract static parts from template
    // static1 = template[:11]
    // static2 = 0x20
    // static3 = template[76:120]
    // static4 = template[127+templateSniLen : 262+templateSniLen]
    // static5 = 0x00, 0x15
    
    std::vector<uint8_t> result;
    result.reserve(517);
    
    // static1 (11 bytes)
    result.insert(result.end(), g_tlsChTemplate.begin(), g_tlsChTemplate.begin() + 11);
    
    // rnd (32 bytes)
    result.insert(result.end(), rnd, rnd + 32);
    
    // static2 (1 byte)
    result.push_back(0x20);
    
    // sessId (32 bytes)
    result.insert(result.end(), sessId, sessId + 32);
    
    // static3 (44 bytes: 76 to 120)
    result.insert(result.end(), g_tlsChTemplate.begin() + 76, g_tlsChTemplate.begin() + 120);
    
    // Server name extension
    size_t sniLen = targetSni.length();
    
    // Length field 1: sniLen + 5
    result.push_back((sniLen + 5) >> 8);
    result.push_back((sniLen + 5) & 0xFF);
    
    // Length field 2: sniLen + 3
    result.push_back((sniLen + 3) >> 8);
    result.push_back((sniLen + 3) & 0xFF);
    
    // Name type: 0x00
    result.push_back(0x00);
    
    // Name length
    result.push_back(sniLen >> 8);
    result.push_back(sniLen & 0xFF);
    
    // SNI value
    result.insert(result.end(), targetSni.begin(), targetSni.end());
    
    // static4 (135 bytes: from 127+templateSniLen to 262+templateSniLen)
    size_t static4Start = 127 + templateSniLen;
    size_t static4End = 262 + templateSniLen;
    result.insert(result.end(), g_tlsChTemplate.begin() + static4Start, g_tlsChTemplate.begin() + static4End);
    
    // keyShare (32 bytes)
    result.insert(result.end(), keyShare, keyShare + 32);
    
    // static5 (2 bytes: padding extension type)
    result.push_back(0x00);
    result.push_back(0x15);
    
    // Padding extension
    size_t paddingLen = 219 - sniLen;
    result.push_back(paddingLen >> 8);
    result.push_back(paddingLen & 0xFF);
    result.insert(result.end(), paddingLen, 0x00);
    
    return result;
}

void ClientHelloMaker::parseClientHello(
    const uint8_t* data, size_t len,
    uint8_t* outRnd,
    uint8_t* outSessId,
    std::string& outSni,
    uint8_t* outKeyShare
) {
    if (len != 517) {
        throw std::invalid_argument("clientHelloBytes must be exactly 517 bytes");
    }
    
    // rnd: [11:43)
    std::memcpy(outRnd, data + 11, 32);
    
    // sessId: [44:76)
    std::memcpy(outSessId, data + 44, 32);
    
    // sniLen: bytes 125-127
    uint16_t sniLen = (data[125] << 8) | data[126];
    if (sniLen == 0) {
        throw std::invalid_argument("SNI length must be non-zero");
    }
    if (127 + sniLen > len) {
        throw std::invalid_argument("invalid SNI length in client hello");
    }
    
    // SNI: [127:127+sniLen)
    for (size_t i = 0; i < sniLen; i++) {
        if (data[127 + i] > 0x7F) {
            throw std::invalid_argument("client hello SNI must be ASCII");
        }
    }
    outSni = std::string((char*)(data + 127), sniLen);
    
    // keyShare: [262+sniLen : 294+sniLen)
    size_t ksInd = 262 + sniLen;
    if (ksInd + 32 > len) {
        throw std::invalid_argument("invalid key_share position in client hello");
    }
    std::memcpy(outKeyShare, data + ksInd, 32);
}

std::vector<uint8_t> ClientHelloMaker::getClientResponseWith(const uint8_t* appData, size_t appDataLen) {
    std::vector<uint8_t> result;
    result.reserve(6 + 3 + 2 + appDataLen);
    
    // TLS change cipher spec
    result.insert(result.end(), TLS_CHANGE_CIPHER, TLS_CHANGE_CIPHER + 6);
    
    // TLS app data header
    result.insert(result.end(), TLS_APP_DATA_HEADER, TLS_APP_DATA_HEADER + 3);
    
    // Length
    result.push_back(appDataLen >> 8);
    result.push_back(appDataLen & 0xFF);
    
    // App data
    result.insert(result.end(), appData, appData + appDataLen);
    
    return result;
}

// ServerHelloMaker implementation

static const char* TLS_SH_TEMPLATE_HEX = 
    "160303007a0200007603035e39ed63ad58140fbd12af1c6a37c879299a39461b308d63cb1dae291c5b69702057d2a640c5ca53fed0f24491baaf96347f12db603fd1babe6bc3ad0b6fbde406130200002e002b0002030400330024001d0020d934ed49a1619be820856c4986e865c5b0e4eb188ebd30193271e8171152eb4e";

static std::vector<uint8_t> g_tlsShTemplate;

static void ensureShTemplateInit() {
    if (g_tlsShTemplate.empty()) {
        g_tlsShTemplate = hexToBytes(TLS_SH_TEMPLATE_HEX);
    }
}

std::vector<uint8_t> ServerHelloMaker::getServerHelloWith(
    const uint8_t* rnd,
    const uint8_t* sessId,
    const uint8_t* keyShare,
    const uint8_t* appData,
    size_t appDataLen
) {
    ensureShTemplateInit();
    
    std::vector<uint8_t> result;
    result.reserve(138 + appDataLen);
    
    // static1 (11 bytes)
    result.insert(result.end(), g_tlsShTemplate.begin(), g_tlsShTemplate.begin() + 11);
    
    // rnd (32 bytes)
    result.insert(result.end(), rnd, rnd + 32);
    
    // static2 (1 byte)
    result.push_back(0x20);
    
    // sessId (32 bytes)
    result.insert(result.end(), sessId, sessId + 32);
    
    // static3 (19 bytes: 76 to 95)
    result.insert(result.end(), g_tlsShTemplate.begin() + 76, g_tlsShTemplate.begin() + 95);
    
    // keyShare (32 bytes)
    result.insert(result.end(), keyShare, keyShare + 32);
    
    // TLS change cipher spec
    result.insert(result.end(), ClientHelloMaker::TLS_CHANGE_CIPHER, 
                  ClientHelloMaker::TLS_CHANGE_CIPHER + 6);
    
    // TLS app data header
    result.insert(result.end(), ClientHelloMaker::TLS_APP_DATA_HEADER,
                  ClientHelloMaker::TLS_APP_DATA_HEADER + 3);
    
    // App data length
    result.push_back(appDataLen >> 8);
    result.push_back(appDataLen & 0xFF);
    
    // App data
    result.insert(result.end(), appData, appData + appDataLen);
    
    return result;
}

void ServerHelloMaker::parseServerHello(
    const uint8_t* data, size_t len,
    uint8_t* outRnd,
    uint8_t* outSessId,
    uint8_t* outKeyShare,
    std::vector<uint8_t>& outAppData
) {
    if (len < 159) {
        throw std::invalid_argument("serverHelloBytes is too short");
    }
    
    // rnd: [11:43)
    std::memcpy(outRnd, data + 11, 32);
    
    // sessId: [44:76)
    std::memcpy(outSessId, data + 44, 32);
    
    // keyShare: [95:127)
    std::memcpy(outKeyShare, data + 95, 32);
    
    // appData: [138:end)
    outAppData.assign(data + 138, data + len);
}

} // namespace smartfox
