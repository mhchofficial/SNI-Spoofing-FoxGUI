#include "sni_service.h"
#include "packet_injector.h"
#include "client_hello_maker.h"

#include <windivert.h>
#include <iphlpapi.h>
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace smartfox {

SniService::SniService() {
}

SniService::~SniService() {
    cleanup();
}

bool SniService::initialize() {
    if (initialized_) {
        return true;
    }

    // Initialize Winsock
    WSADATA wsaData;
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
        reportError("WSAStartup failed: " + std::to_string(result));
        return false;
    }

    initialized_ = true;
    log("[init] Service initialized");
    return true;
}

bool SniService::start(const SniConfig& config) {
    if (running_) {
        return false;
    }

    config_ = config;
    
    updateStatus("starting");
    log("[start] Starting service...");

    // Get default interface IP
    interfaceIpv4_ = "0.0.0.0";
    
    // Try to get the actual interface IP for the target
    ULONG size = 0;
    GetAdaptersAddresses(AF_INET, 0, nullptr, nullptr, &size);
    if (size > 0) {
        auto addresses = (PIP_ADAPTER_ADDRESSES)malloc(size);
        if (GetAdaptersAddresses(AF_INET, 0, nullptr, addresses, &size) == NO_ERROR) {
            for (auto addr = addresses; addr; addr = addr->Next) {
                if (addr->OperStatus == IfOperStatusUp && addr->FirstUnicastAddress) {
                    auto sockaddr = (sockaddr_in*)addr->FirstUnicastAddress->Address.lpSockaddr;
                    char ip[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &sockaddr->sin_addr, ip, INET_ADDRSTRLEN);
                    if (strcmp(ip, "127.0.0.1") != 0) {
                        interfaceIpv4_ = ip;
                        break;
                    }
                }
            }
        }
        free(addresses);
    }
    
    log("[start] Using interface: " + interfaceIpv4_);

    // Create WinDivert filter for TCP traffic to our target
    std::stringstream filterSs;
    filterSs << "tcp and ip.DstAddr == " << config_.connect_ip 
             << " and tcp.DstPort == " << config_.connect_port;
    std::string filter = filterSs.str();
    
    // Open WinDivert handle
    windivertHandle_ = WinDivertOpen(filter.c_str(), WINDIVERT_LAYER_NETWORK, 0, 0);
    if (windivertHandle_ == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        reportError("WinDivert open failed: " + std::to_string(err));
        return false;
    }
    
    log("[start] WinDivert filter: " + filter);

    // Create listen socket
    listenSocket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket_ == INVALID_SOCKET) {
        reportError("Failed to create listen socket");
        WinDivertClose(windivertHandle_);
        windivertHandle_ = nullptr;
        return false;
    }

    // Set socket options
    int opt = 1;
    setsockopt(listenSocket_, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
    
    if (config_.enable_tcp_nodelay) {
        setsockopt(listenSocket_, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
    }
    
    setsockopt(listenSocket_, SOL_SOCKET, SO_SNDBUF, (char*)&config_.socket_sndbuf, sizeof(config_.socket_sndbuf));
    setsockopt(listenSocket_, SOL_SOCKET, SO_RCVBUF, (char*)&config_.socket_rcvbuf, sizeof(config_.socket_rcvbuf));

    // Bind
    sockaddr_in bindAddr = {};
    bindAddr.sin_family = AF_INET;
    bindAddr.sin_port = htons(config_.listen_port);
    inet_pton(AF_INET, config_.listen_host, &bindAddr.sin_addr);

    if (bind(listenSocket_, (sockaddr*)&bindAddr, sizeof(bindAddr)) == SOCKET_ERROR) {
        reportError("Bind failed: " + std::to_string(WSAGetLastError()));
        closesocket(listenSocket_);
        WinDivertClose(windivertHandle_);
        return false;
    }

    if (listen(listenSocket_, SOMAXCONN) == SOCKET_ERROR) {
        reportError("Listen failed");
        closesocket(listenSocket_);
        WinDivertClose(windivertHandle_);
        return false;
    }

    running_ = true;

    // Start threads
    serverThread_ = std::thread(&SniService::serverThread, this);
    injectorThread_ = std::thread(&SniService::injectorThread, this);
    statsThread_ = std::thread(&SniService::statsReporterThread, this);

    updateStatus("running");
    log("[start] Service started on " + std::string(config_.listen_host) + ":" + std::to_string(config_.listen_port));
    
    return true;
}

void SniService::stop() {
    if (!running_) {
        return;
    }

    updateStatus("stopping");
    log("[stop] Stopping service...");
    
    running_ = false;

    // Close listen socket to unblock accept()
    if (listenSocket_ != INVALID_SOCKET) {
        closesocket(listenSocket_);
        listenSocket_ = INVALID_SOCKET;
    }

    // Close WinDivert
    if (windivertHandle_) {
        WinDivertClose(windivertHandle_);
        windivertHandle_ = nullptr;
    }

    // Wait for threads
    if (serverThread_.joinable()) {
        serverThread_.join();
    }
    if (injectorThread_.joinable()) {
        injectorThread_.join();
    }
    if (statsThread_.joinable()) {
        statsThread_.join();
    }

    updateStatus("stopped");
    log("[stop] Service stopped");
}

void SniService::cleanup() {
    stop();
    
    if (initialized_) {
        WSACleanup();
        initialized_ = false;
    }
}

void SniService::getStats(TrafficStats& stats) const {
    stats.upload_bps = windowUpload_.load();
    stats.download_bps = windowDownload_.load();
    stats.total_upload = totalUpload_.load();
    stats.total_download = totalDownload_.load();
    stats.active_connections = activeConnections_.load();
}

void SniService::serverThread() {
    log("[server] Server thread started");
    
    while (running_) {
        sockaddr_in clientAddr;
        int addrLen = sizeof(clientAddr);
        
        SOCKET clientSocket = accept(listenSocket_, (sockaddr*)&clientAddr, &addrLen);
        if (clientSocket == INVALID_SOCKET) {
            if (running_) {
                int err = WSAGetLastError();
                if (err != WSAEINTR && err != WSAENOTSOCK) {
                    log("[server] Accept error: " + std::to_string(err));
                }
            }
            continue;
        }

        char clientIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, clientIp, INET_ADDRSTRLEN);
        
        // Check connection limits
        {
            std::lock_guard<std::mutex> lock(connectionMutex_);
            
            if (activeConnections_ >= config_.max_connections) {
                log("[server] Connection rejected: max connections reached");
                closesocket(clientSocket);
                continue;
            }
            
            int& perIpCount = connectionsPerIp_[clientIp];
            if (perIpCount >= config_.max_connections_per_ip) {
                log("[server] Connection rejected: max per IP reached for " + std::string(clientIp));
                closesocket(clientSocket);
                continue;
            }
            
            perIpCount++;
            activeConnections_++;
        }

        // Handle connection in a new thread
        std::thread([this, clientSocket, clientIp = std::string(clientIp)]() {
            handleConnection(clientSocket, clientIp);
        }).detach();
    }
    
    log("[server] Server thread stopped");
}

void SniService::handleConnection(SOCKET clientSocket, const std::string& clientIp) {
    // Set socket options
    int opt = 1;
    if (config_.enable_tcp_nodelay) {
        setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
    }
    setsockopt(clientSocket, SOL_SOCKET, SO_SNDBUF, (char*)&config_.socket_sndbuf, sizeof(config_.socket_sndbuf));
    setsockopt(clientSocket, SOL_SOCKET, SO_RCVBUF, (char*)&config_.socket_rcvbuf, sizeof(config_.socket_rcvbuf));

    // Generate fake TLS ClientHello
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist(0, 255);
    
    uint8_t rnd[32], sessId[32], keyShare[32];
    for (int i = 0; i < 32; i++) {
        rnd[i] = dist(gen);
        sessId[i] = dist(gen);
        keyShare[i] = dist(gen);
    }
    
    std::vector<uint8_t> fakeData;
    try {
        fakeData = ClientHelloMaker::getClientHelloWith(rnd, sessId, config_.fake_sni, keyShare);
    } catch (const std::exception& e) {
        log("[conn] Failed to create ClientHello: " + std::string(e.what()));
        closesocket(clientSocket);
        
        std::lock_guard<std::mutex> lock(connectionMutex_);
        connectionsPerIp_[clientIp]--;
        activeConnections_--;
        return;
    }

    // Connect to target
    SOCKET targetSocket = INVALID_SOCKET;
    bool connected = false;
    
    for (int attempt = 0; attempt < config_.connect_retry_count && !connected; attempt++) {
        targetSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (targetSocket == INVALID_SOCKET) {
            continue;
        }

        // Bind to interface
        sockaddr_in localAddr = {};
        localAddr.sin_family = AF_INET;
        inet_pton(AF_INET, interfaceIpv4_.c_str(), &localAddr.sin_addr);
        bind(targetSocket, (sockaddr*)&localAddr, sizeof(localAddr));

        // Set options
        if (config_.enable_tcp_nodelay) {
            setsockopt(targetSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&opt, sizeof(opt));
        }

        // Connect with timeout
        u_long nonBlocking = 1;
        ioctlsocket(targetSocket, FIONBIO, &nonBlocking);

        sockaddr_in targetAddr = {};
        targetAddr.sin_family = AF_INET;
        targetAddr.sin_port = htons(config_.connect_port);
        inet_pton(AF_INET, config_.connect_ip, &targetAddr.sin_addr);

        connect(targetSocket, (sockaddr*)&targetAddr, sizeof(targetAddr));

        // Wait for connection
        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(targetSocket, &writeSet);

        timeval timeout;
        timeout.tv_sec = (long)config_.connect_timeout_sec;
        timeout.tv_usec = (long)((config_.connect_timeout_sec - timeout.tv_sec) * 1000000);

        int selectResult = select(0, nullptr, &writeSet, nullptr, &timeout);
        if (selectResult > 0) {
            int error = 0;
            int errLen = sizeof(error);
            getsockopt(targetSocket, SOL_SOCKET, SO_ERROR, (char*)&error, &errLen);
            if (error == 0) {
                connected = true;
            }
        }

        if (!connected) {
            closesocket(targetSocket);
            targetSocket = INVALID_SOCKET;
            
            if (attempt < config_.connect_retry_count - 1) {
                Sleep((DWORD)(config_.connect_retry_delay_sec * 1000));
            }
        }
    }

    if (!connected) {
        log("[conn] Failed to connect to target after " + std::to_string(config_.connect_retry_count) + " attempts");
        closesocket(clientSocket);
        
        std::lock_guard<std::mutex> lock(connectionMutex_);
        connectionsPerIp_[clientIp]--;
        activeConnections_--;
        return;
    }

    // Set back to blocking
    u_long blocking = 0;
    ioctlsocket(targetSocket, FIONBIO, &blocking);

    // Note: In a full implementation, we would:
    // 1. Register this connection with the PacketInjector
    // 2. Wait for the fake data to be injected and acknowledged
    // 3. Then relay traffic bidirectionally
    
    // For now, we do a simple relay
    log("[conn] Connected to target, starting relay");

    // Bidirectional relay using select()
    char buffer[65536];
    bool clientClosed = false, targetClosed = false;

    while (running_ && !clientClosed && !targetClosed) {
        fd_set readSet;
        FD_ZERO(&readSet);
        if (!clientClosed) FD_SET(clientSocket, &readSet);
        if (!targetClosed) FD_SET(targetSocket, &readSet);

        timeval timeout;
        timeout.tv_sec = (long)config_.relay_idle_timeout_sec;
        timeout.tv_usec = 0;

        int selectResult = select(0, &readSet, nullptr, nullptr, &timeout);
        if (selectResult <= 0) {
            break; // Timeout or error
        }

        // Client -> Target
        if (FD_ISSET(clientSocket, &readSet)) {
            int recvLen = recv(clientSocket, buffer, sizeof(buffer), 0);
            if (recvLen <= 0) {
                clientClosed = true;
            } else {
                send(targetSocket, buffer, recvLen, 0);
                totalUpload_ += recvLen;
                windowUpload_ += recvLen;
            }
        }

        // Target -> Client
        if (FD_ISSET(targetSocket, &readSet)) {
            int recvLen = recv(targetSocket, buffer, sizeof(buffer), 0);
            if (recvLen <= 0) {
                targetClosed = true;
            } else {
                send(clientSocket, buffer, recvLen, 0);
                totalDownload_ += recvLen;
                windowDownload_ += recvLen;
            }
        }
    }

    closesocket(clientSocket);
    closesocket(targetSocket);

    // Update connection count
    {
        std::lock_guard<std::mutex> lock(connectionMutex_);
        connectionsPerIp_[clientIp]--;
        if (connectionsPerIp_[clientIp] <= 0) {
            connectionsPerIp_.erase(clientIp);
        }
        activeConnections_--;
    }
}

void SniService::injectorThread() {
    log("[injector] Injector thread started");
    
    uint8_t packet[65535];
    UINT packetLen;
    WINDIVERT_ADDRESS addr;
    
    while (running_ && windivertHandle_) {
        if (WinDivertRecv(windivertHandle_, packet, sizeof(packet), &packetLen, &addr)) {
            // Process packet for injection logic
            // For now, just pass through
            WinDivertSend(windivertHandle_, packet, packetLen, nullptr, &addr);
        } else {
            DWORD err = GetLastError();
            if (err != ERROR_NO_DATA && running_) {
                log("[injector] WinDivert recv error: " + std::to_string(err));
                break;
            }
        }
    }
    
    log("[injector] Injector thread stopped");
}

void SniService::statsReporterThread() {
    log("[stats] Stats reporter thread started");
    
    while (running_) {
        Sleep(1000);
        
        int64_t upWindow = windowUpload_.exchange(0);
        int64_t downWindow = windowDownload_.exchange(0);
        
        if (statsCallback_) {
            TrafficStats stats;
            stats.upload_bps = upWindow;
            stats.download_bps = downWindow;
            stats.total_upload = totalUpload_.load();
            stats.total_download = totalDownload_.load();
            stats.active_connections = activeConnections_.load();
            statsCallback_(&stats);
        }
    }
    
    log("[stats] Stats reporter thread stopped");
}

void SniService::log(const std::string& message) {
    if (logCallback_) {
        logCallback_(message.c_str());
    }
}

void SniService::reportError(const std::string& error) {
    log("[ERROR] " + error);
    if (errorCallback_) {
        errorCallback_(error.c_str());
    }
}

void SniService::updateStatus(const std::string& status) {
    if (statusCallback_) {
        statusCallback_(status.c_str());
    }
}

} // namespace smartfox
