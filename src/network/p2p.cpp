#include "p2p.h"
#include "../crypto/random.h"
#include "../crypto/sha256.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

namespace powercoin {

    // ============== PeerInfo Implementation ==============

    PeerInfo::PeerInfo()
        : port(0), version(0), services(0), height(0), lastSeen(0),
          lastPing(0), pingTime(0), state(PeerState::DISCONNECTED),
          bytesSent(0), bytesReceived(0), messagesSent(0), messagesReceived(0),
          failedConnections(0), connectionTime(0), isOutbound(false),
          isWhitelisted(false) {}

    std::string PeerInfo::toString() const {
        std::stringstream ss;
        ss << "Peer: " << id << "\n";
        ss << "  IP: " << ip << ":" << port << "\n";
        ss << "  State: " << static_cast<int>(state) << "\n";
        ss << "  Version: " << version << "\n";
        ss << "  Height: " << height << "\n";
        ss << "  User Agent: " << userAgent << "\n";
        ss << "  Ping: " << pingTime << " ms\n";
        ss << "  Sent: " << bytesSent << " bytes\n";
        ss << "  Received: " << bytesReceived << " bytes\n";
        return ss.str();
    }

    // ============== NetworkAddress Implementation ==============

    NetworkAddress::NetworkAddress() : time(0), services(0), port(0) {
        memset(ip, 0, sizeof(ip));
    }

    std::string NetworkAddress::getIP() const {
        char str[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, ip, str, sizeof(str))) {
            return std::string(str);
        }
        return "";
    }

    void NetworkAddress::setIP(const std::string& ipStr) {
        if (inet_pton(AF_INET6, ipStr.c_str(), ip) != 1) {
            // Try IPv4 mapped to IPv6
            struct in_addr addr4;
            if (inet_pton(AF_INET, ipStr.c_str(), &addr4) == 1) {
                memset(ip, 0, 10);
                memset(ip + 10, 0xff, 2);
                memcpy(ip + 12, &addr4, 4);
            }
        }
    }

    bool NetworkAddress::isIPv4() const {
        static const uint8_t prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        return memcmp(ip, prefix, 12) == 0;
    }

    std::string NetworkAddress::toString() const {
        if (isIPv4()) {
            struct in_addr addr4;
            memcpy(&addr4, ip + 12, 4);
            char str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &addr4, str, sizeof(str))) {
                return std::string(str) + ":" + std::to_string(port);
            }
        } else {
            char str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, ip, str, sizeof(str))) {
                return "[" + std::string(str) + "]:" + std::to_string(port);
            }
        }
        return "";
    }

    std::vector<uint8_t> NetworkAddress::serialize() const {
        std::vector<uint8_t> data;
        data.reserve(26);
        
        // Write time (4 bytes)
        uint32_t timeBe = htobe32(time);
        data.insert(data.end(), (uint8_t*)&timeBe, (uint8_t*)&timeBe + 4);
        
        // Write services (8 bytes)
        uint64_t servicesBe = htobe64(services);
        data.insert(data.end(), (uint8_t*)&servicesBe, (uint8_t*)&servicesBe + 8);
        
        // Write IP (16 bytes)
        data.insert(data.end(), ip, ip + 16);
        
        // Write port (2 bytes)
        uint16_t portBe = htobe16(port);
        data.insert(data.end(), (uint8_t*)&portBe, (uint8_t*)&portBe + 2);
        
        return data;
    }

    bool NetworkAddress::deserialize(const std::vector<uint8_t>& data, size_t& pos) {
        if (pos + 26 > data.size()) return false;
        
        // Read time
        uint32_t timeBe;
        memcpy(&timeBe, data.data() + pos, 4);
        time = be32toh(timeBe);
        pos += 4;
        
        // Read services
        uint64_t servicesBe;
        memcpy(&servicesBe, data.data() + pos, 8);
        services = be64toh(servicesBe);
        pos += 8;
        
        // Read IP
        memcpy(ip, data.data() + pos, 16);
        pos += 16;
        
        // Read port
        uint16_t portBe;
        memcpy(&portBe, data.data() + pos, 2);
        port = be16toh(portBe);
        pos += 2;
        
        return true;
    }

    // ============== Inventory Implementation ==============

    Inventory::Inventory() : type(InventoryType::ERROR) {}

    Inventory::Inventory(InventoryType t, const std::string& h) : type(t), hash(h) {}

    std::vector<uint8_t> Inventory::serialize() const {
        std::vector<uint8_t> data;
        data.reserve(36);
        
        // Write type (4 bytes)
        uint32_t typeBe = htobe32(static_cast<uint32_t>(type));
        data.insert(data.end(), (uint8_t*)&typeBe, (uint8_t*)&typeBe + 4);
        
        // Write hash (32 bytes)
        auto hashBytes = SHA256::hashToBytes(hash);
        data.insert(data.end(), hashBytes.begin(), hashBytes.end());
        
        return data;
    }

    bool Inventory::deserialize(const std::vector<uint8_t>& data, size_t& pos) {
        if (pos + 36 > data.size()) return false;
        
        // Read type
        uint32_t typeBe;
        memcpy(&typeBe, data.data() + pos, 4);
        type = static_cast<InventoryType>(be32toh(typeBe));
        pos += 4;
        
        // Read hash
        std::array<uint8_t, 32> hashBytes;
        memcpy(hashBytes.data(), data.data() + pos, 32);
        hash = SHA256::bytesToHash(hashBytes);
        pos += 32;
        
        return true;
    }

    bool Inventory::operator<(const Inventory& other) const {
        return hash < other.hash;
    }

    // ============== MessageHeader Implementation ==============

    MessageHeader::MessageHeader() : magic(0), length(0), checksum(0) {}

    std::vector<uint8_t> MessageHeader::serialize() const {
        std::vector<uint8_t> data;
        data.reserve(24);
        
        // Write magic (4 bytes)
        uint32_t magicBe = htobe32(magic);
        data.insert(data.end(), (uint8_t*)&magicBe, (uint8_t*)&magicBe + 4);
        
        // Write command (12 bytes, null-padded)
        std::array<char, 12> cmd = {0};
        strncpy(cmd.data(), command.c_str(), 11);
        data.insert(data.end(), cmd.begin(), cmd.end());
        
        // Write length (4 bytes)
        uint32_t lengthBe = htobe32(length);
        data.insert(data.end(), (uint8_t*)&lengthBe, (uint8_t*)&lengthBe + 4);
        
        // Write checksum (4 bytes)
        uint32_t checksumBe = htobe32(checksum);
        data.insert(data.end(), (uint8_t*)&checksumBe, (uint8_t*)&checksumBe + 4);
        
        return data;
    }

    bool MessageHeader::deserialize(const std::vector<uint8_t>& data, size_t& pos) {
        if (pos + 24 > data.size()) return false;
        
        // Read magic
        uint32_t magicBe;
        memcpy(&magicBe, data.data() + pos, 4);
        magic = be32toh(magicBe);
        pos += 4;
        
        // Read command
        command = std::string((char*)data.data() + pos, 12);
        command = command.c_str(); // Remove null padding
        pos += 12;
        
        // Read length
        uint32_t lengthBe;
        memcpy(&lengthBe, data.data() + pos, 4);
        length = be32toh(lengthBe);
        pos += 4;
        
        // Read checksum
        uint32_t checksumBe;
        memcpy(&checksumBe, data.data() + pos, 4);
        checksum = be32toh(checksumBe);
        pos += 4;
        
        return true;
    }

    bool MessageHeader::validateChecksum(const std::vector<uint8_t>& payload) const {
        uint32_t expected = calculateChecksum(payload);
        return checksum == expected;
    }

    uint32_t MessageHeader::calculateChecksum(const std::vector<uint8_t>& payload) {
        auto hash = SHA256::doubleHash(payload.data(), payload.size());
        uint32_t result;
        memcpy(&result, hash.data(), 4);
        return result;
    }

    // ============== Message Implementation ==============

    Message::Message() {}

    std::vector<uint8_t> Message::serialize() const {
        auto headerData = header.serialize();
        auto result = headerData;
        result.insert(result.end(), payload.begin(), payload.end());
        return result;
    }

    bool Message::deserialize(const std::vector<uint8_t>& data) {
        size_t pos = 0;
        if (!header.deserialize(data, pos)) return false;
        
        if (pos + header.length > data.size()) return false;
        payload.assign(data.begin() + pos, data.begin() + pos + header.length);
        
        return header.validateChecksum(payload);
    }

    // ============== VersionMessage Implementation ==============

    VersionMessage::VersionMessage()
        : version(P2P_PROTOCOL_VERSION), services(0), timestamp(0),
          nonce(0), startHeight(0), relay(false) {}

    std::vector<uint8_t> VersionMessage::serialize() const {
        std::vector<uint8_t> data;
        
        // Write version (4 bytes)
        uint32_t versionBe = htobe32(version);
        data.insert(data.end(), (uint8_t*)&versionBe, (uint8_t*)&versionBe + 4);
        
        // Write services (8 bytes)
        uint64_t servicesBe = htobe64(services);
        data.insert(data.end(), (uint8_t*)&servicesBe, (uint8_t*)&servicesBe + 8);
        
        // Write timestamp (8 bytes)
        int64_t timestampBe = htobe64(timestamp);
        data.insert(data.end(), (uint8_t*)&timestampBe, (uint8_t*)&timestampBe + 8);
        
        // Write receiver address
        auto addrRecvData = addrRecv.serialize();
        data.insert(data.end(), addrRecvData.begin(), addrRecvData.end());
        
        // Write sender address
        auto addrFromData = addrFrom.serialize();
        data.insert(data.end(), addrFromData.begin(), addrFromData.end());
        
        // Write nonce (8 bytes)
        uint64_t nonceBe = htobe64(nonce);
        data.insert(data.end(), (uint8_t*)&nonceBe, (uint8_t*)&nonceBe + 8);
        
        // Write user agent (variable length)
        data.push_back(userAgent.size());
        data.insert(data.end(), userAgent.begin(), userAgent.end());
        
        // Write start height (4 bytes)
        uint32_t heightBe = htobe32(startHeight);
        data.insert(data.end(), (uint8_t*)&heightBe, (uint8_t*)&heightBe + 4);
        
        // Write relay (1 byte)
        data.push_back(relay ? 1 : 0);
        
        return data;
    }

    bool VersionMessage::deserialize(const std::vector<uint8_t>& data, size_t& pos) {
        if (pos + 4 > data.size()) return false;
        
        // Read version
        uint32_t versionBe;
        memcpy(&versionBe, data.data() + pos, 4);
        version = be32toh(versionBe);
        pos += 4;
        
        if (pos + 8 > data.size()) return false;
        // Read services
        uint64_t servicesBe;
        memcpy(&servicesBe, data.data() + pos, 8);
        services = be64toh(servicesBe);
        pos += 8;
        
        if (pos + 8 > data.size()) return false;
        // Read timestamp
        int64_t timestampBe;
        memcpy(&timestampBe, data.data() + pos, 8);
        timestamp = be64toh(timestampBe);
        pos += 8;
        
        // Read addresses
        if (!addrRecv.deserialize(data, pos)) return false;
        if (!addrFrom.deserialize(data, pos)) return false;
        
        if (pos + 8 > data.size()) return false;
        // Read nonce
        uint64_t nonceBe;
        memcpy(&nonceBe, data.data() + pos, 8);
        nonce = be64toh(nonceBe);
        pos += 8;
        
        // Read user agent
        if (pos >= data.size()) return false;
        uint8_t uaLen = data[pos++];
        if (pos + uaLen > data.size()) return false;
        userAgent.assign((char*)data.data() + pos, uaLen);
        pos += uaLen;
        
        if (pos + 4 > data.size()) return false;
        // Read start height
        uint32_t heightBe;
        memcpy(&heightBe, data.data() + pos, 4);
        startHeight = be32toh(heightBe);
        pos += 4;
        
        if (pos < data.size()) {
            relay = data[pos++] != 0;
        }
        
        return true;
    }

    // ============== AddrMessage Implementation ==============

    AddrMessage::AddrMessage() {}

    std::vector<uint8_t> AddrMessage::serialize() const {
        std::vector<uint8_t> data;
        
        // Write count (variable)
        if (addresses.size() < 0xFD) {
            data.push_back(addresses.size());
        } else if (addresses.size() <= 0xFFFF) {
            data.push_back(0xFD);
            uint16_t countBe = htobe16(addresses.size());
            data.insert(data.end(), (uint8_t*)&countBe, (uint8_t*)&countBe + 2);
        } else {
            data.push_back(0xFE);
            uint32_t countBe = htobe32(addresses.size());
            data.insert(data.end(), (uint8_t*)&countBe, (uint8_t*)&countBe + 4);
        }
        
        // Write addresses
        for (const auto& addr : addresses) {
            auto addrData = addr.serialize();
            data.insert(data.end(), addrData.begin(), addrData.end());
        }
        
        return data;
    }

    bool AddrMessage::deserialize(const std::vector<uint8_t>& data, size_t& pos) {
        if (pos >= data.size()) return false;
        
        uint64_t count = 0;
        uint8_t first = data[pos++];
        
        if (first < 0xFD) {
            count = first;
        } else if (first == 0xFD) {
            if (pos + 2 > data.size()) return false;
            uint16_t countBe;
            memcpy(&countBe, data.data() + pos, 2);
            count = be16toh(countBe);
            pos += 2;
        } else if (first == 0xFE) {
            if (pos + 4 > data.size()) return false;
            uint32_t countBe;
            memcpy(&countBe, data.data() + pos, 4);
            count = be32toh(countBe);
            pos += 4;
        } else {
            return false;
        }
        
        addresses.clear();
        for (uint64_t i = 0; i < count; i++) {
            NetworkAddress addr;
            if (!addr.deserialize(data, pos)) return false;
            addresses.push_back(addr);
        }
        
        return true;
    }

    // ============== InvMessage Implementation ==============

    InvMessage::InvMessage() {}

    std::vector<uint8_t> InvMessage::serialize() const {
        std::vector<uint8_t> data;
        
        // Write count (variable)
        if (inventories.size() < 0xFD) {
            data.push_back(inventories.size());
        } else if (inventories.size() <= 0xFFFF) {
            data.push_back(0xFD);
            uint16_t countBe = htobe16(inventories.size());
            data.insert(data.end(), (uint8_t*)&countBe, (uint8_t*)&countBe + 2);
        } else {
            data.push_back(0xFE);
            uint32_t countBe = htobe32(inventories.size());
            data.insert(data.end(), (uint8_t*)&countBe, (uint8_t*)&countBe + 4);
        }
        
        // Write inventories
        for (const auto& inv : inventories) {
            auto invData = inv.serialize();
            data.insert(data.end(), invData.begin(), invData.end());
        }
        
        return data;
    }

    bool InvMessage::deserialize(const std::vector<uint8_t>& data, size_t& pos) {
        if (pos >= data.size()) return false;
        
        uint64_t count = 0;
        uint8_t first = data[pos++];
        
        if (first < 0xFD) {
            count = first;
        } else if (first == 0xFD) {
            if (pos + 2 > data.size()) return false;
            uint16_t countBe;
            memcpy(&countBe, data.data() + pos, 2);
            count = be16toh(countBe);
            pos += 2;
        } else if (first == 0xFE) {
            if (pos + 4 > data.size()) return false;
            uint32_t countBe;
            memcpy(&countBe, data.data() + pos, 4);
            count = be32toh(countBe);
            pos += 4;
        } else {
            return false;
        }
        
        inventories.clear();
        for (uint64_t i = 0; i < count; i++) {
            Inventory inv;
            if (!inv.deserialize(data, pos)) return false;
            inventories.push_back(inv);
        }
        
        return true;
    }

    // ============== GetDataMessage Implementation ==============

    GetDataMessage::GetDataMessage() {}

    std::vector<uint8_t> GetDataMessage::serialize() const {
        InvMessage invMsg;
        invMsg.inventories = inventories;
        return invMsg.serialize();
    }

    bool GetDataMessage::deserialize(const std::vector<uint8_t>& data, size_t& pos) {
        InvMessage invMsg;
        if (!invMsg.deserialize(data, pos)) return false;
        inventories = invMsg.inventories;
        return true;
    }

    // ============== P2PConfig Implementation ==============

    P2PConfig::P2PConfig()
        : port(8333), maxPeers(125), minPeers(8), connectTimeout(30),
          handshakeTimeout(10), pingInterval(120), banTime(86400),
          maxFailures(3), allowLocalhost(false), allowLan(true),
          userAgent("/PowerCoin:1.0.0/"), protocolVersion(P2P_PROTOCOL_VERSION),
          services(1) {
        bootstrapNodes = {
            "seed.powercoin.net:8333",
            "seed1.powercoin.net:8333",
            "seed2.powercoin.net:8333"
        };
    }

    // ============== P2PStats Implementation ==============

    P2PStats::P2PStats()
        : bytesSent(0), bytesReceived(0), messagesSent(0), messagesReceived(0),
          peersConnected(0), peersDisconnected(0), peersBanned(0),
          failedConnections(0), uptime(0), bandwidthIn(0), bandwidthOut(0) {}

    // ============== P2PNetwork Implementation ==============

    struct P2PNetwork::Impl {
        int listenSocket;
        std::thread listenThread;
        std::atomic<bool> running;
        std::map<std::string, std::shared_ptr<Peer>> peers;
        std::map<std::string, PeerInfo> peerInfo;
        std::set<std::string> banned;
        std::set<std::string> whitelisted;
        P2PStats stats;
        std::chrono::steady_clock::time_point startTime;
        uint32_t bestHeight;
        std::string bestPeer;
        
        // Callbacks
        std::function<void(const PeerInfo&)> onPeerConnected;
        std::function<void(const PeerInfo&, const std::string&)> onPeerDisconnected;
        std::function<void(const std::vector<uint8_t>&, const std::string&)> onBlockReceived;
        std::function<void(const std::vector<uint8_t>&, const std::string&)> onTransactionReceived;
        std::function<void(const std::vector<Inventory>&, const std::string&)> onInventoryReceived;
        std::function<void(const std::vector<std::string>&, const std::string&)> onHeadersReceived;
        std::function<void(uint64_t, const std::string&)> onPingReceived;
        std::function<void(uint64_t, const std::string&)> onPongReceived;
        std::function<void(const std::string&, const std::string&)> onError;

        Impl() : listenSocket(-1), running(false), bestHeight(0) {
            startTime = std::chrono::steady_clock::now();
        }
    };

    P2PNetwork::P2PNetwork(const P2PConfig& cfg) : config(cfg) {
        impl = std::make_unique<Impl>();
    }

    P2PNetwork::~P2PNetwork() {
        stop();
    }

    bool P2PNetwork::start() {
        std::lock_guard<std::mutex> lock(mutex);
        
        if (impl->running) return true;
        
        // Create listen socket
        impl->listenSocket = socket(AF_INET6, SOCK_STREAM, 0);
        if (impl->listenSocket < 0) {
            return false;
        }
        
        // Allow both IPv4 and IPv6
        int no = 0;
        setsockopt(impl->listenSocket, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no));
        
        // Set non-blocking
        int flags = fcntl(impl->listenSocket, F_GETFL, 0);
        fcntl(impl->listenSocket, F_SETFL, flags | O_NONBLOCK);
        
        // Bind socket
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_addr = in6addr_any;
        addr.sin6_port = htons(config.port);
        
        if (bind(impl->listenSocket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(impl->listenSocket);
            return false;
        }
        
        // Listen
        if (listen(impl->listenSocket, 10) < 0) {
            close(impl->listenSocket);
            return false;
        }
        
        impl->running = true;
        
        // Start listen thread
        impl->listenThread = std::thread([this]() {
            while (impl->running) {
                struct sockaddr_in6 clientAddr;
                socklen_t clientLen = sizeof(clientAddr);
                
                int clientSocket = accept(impl->listenSocket, 
                                         (struct sockaddr*)&clientAddr, 
                                         &clientLen);
                
                if (clientSocket >= 0) {
                    char ipStr[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &clientAddr.sin6_addr, ipStr, sizeof(ipStr));
                    
                    auto peer = std::make_shared<Peer>(ipStr, ntohs(clientAddr.sin6_port), false);
                    if (peer->connect()) {
                        addPeer(peer);
                    }
                }
                
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        });
        
        // Connect to bootstrap nodes
        for (const auto& node : config.bootstrapNodes) {
            size_t colon = node.find(':');
            if (colon != std::string::npos) {
                std::string ip = node.substr(0, colon);
                uint16_t port = std::stoi(node.substr(colon + 1));
                connectToPeer(ip, port);
            }
        }
        
        return true;
    }

    void P2PNetwork::stop() {
        std::lock_guard<std::mutex> lock(mutex);
        
        impl->running = false;
        
        if (impl->listenThread.joinable()) {
            impl->listenThread.join();
        }
        
        if (impl->listenSocket >= 0) {
            close(impl->listenSocket);
            impl->listenSocket = -1;
        }
        
        // Disconnect all peers
        for (auto& [id, peer] : impl->peers) {
            peer->disconnect();
        }
        impl->peers.clear();
    }

    bool P2PNetwork::isRunning() const {
        return impl->running;
    }

    bool P2PNetwork::connectToPeer(const std::string& ip, uint16_t port) {
        if (isBanned(ip)) return false;
        
        auto peer = std::make_shared<Peer>(ip, port, true);
        if (peer->connect()) {
            addPeer(peer);
            return true;
        }
        return false;
    }

    void P2PNetwork::addPeer(const std::shared_ptr<Peer>& peer) {
        std::lock_guard<std::mutex> lock(mutex);
        
        impl->peers[peer->getId()] = peer;
        
        // Start message processing
        peer->processMessages([this](const Message& msg) {
            // Handle message
        });
    }

    size_t P2PNetwork::getConnectedCount() const {
        std::lock_guard<std::mutex> lock(mutex);
        
        size_t count = 0;
        for (const auto& [id, peer] : impl->peers) {
            if (peer->isConnected()) count++;
        }
        return count;
    }

    P2PStats P2PNetwork::getStats() const {
        std::lock_guard<std::mutex> lock(mutex);
        
        P2PStats stats = impl->stats;
        stats.uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - impl->startTime).count();
        return stats;
    }

    std::string P2PNetwork::getLocalAddress() const {
        char hostname[256];
        gethostname(hostname, sizeof(hostname));
        
        struct addrinfo hints, *info;
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_INET6;
        hints.ai_socktype = SOCK_STREAM;
        
        if (getaddrinfo(hostname, nullptr, &hints, &info) == 0) {
            struct sockaddr_in6* addr = (struct sockaddr_in6*)info->ai_addr;
            char ipStr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &addr->sin6_addr, ipStr, sizeof(ipStr));
            freeaddrinfo(info);
            return ipStr;
        }
        
        return "::1";
    }

    std::string P2PNetwork::getNodeId() const {
        auto addr = getLocalAddress();
        auto port = config.port;
        std::string data = addr + ":" + std::to_string(port);
        return SHA256::hash(data).substr(0, 16);
    }

    uint32_t P2PNetwork::getBestHeight() const {
        std::lock_guard<std::mutex> lock(mutex);
        return impl->bestHeight;
    }

    std::string P2PNetwork::getBestPeer() const {
        std::lock_guard<std::mutex> lock(mutex);
        return impl->bestPeer;
    }

    bool P2PNetwork::isBanned(const std::string& ip) const {
        std::lock_guard<std::mutex> lock(mutex);
        return impl->banned.find(ip) != impl->banned.end();
    }

    bool P2PNetwork::isWhitelisted(const std::string& ip) const {
        std::lock_guard<std::mutex> lock(mutex);
        return impl->whitelisted.find(ip) != impl->whitelisted.end();
    }

    // ============== Peer Implementation ==============

    Peer::Peer(const std::string& peerIp, uint16_t peerPort, bool outbound)
        : ip(peerIp), port(peerPort), socket(-1), state(PeerState::DISCONNECTED),
          running(false), pingNonce(0) {
        
        // Generate peer ID
        std::string data = ip + ":" + std::to_string(port) + 
                          std::to_string(Random::getUint64());
        id = SHA256::hash(data).substr(0, 16);
        
        info.id = id;
        info.ip = ip;
        info.port = port;
        info.isOutbound = outbound;
    }

    Peer::~Peer() {
        disconnect();
    }

    bool Peer::connect() {
        if (state != PeerState::DISCONNECTED) return false;
        
        socket = ::socket(AF_INET6, SOCK_STREAM, 0);
        if (socket < 0) return false;
        
        // Set non-blocking
        int flags = fcntl(socket, F_GETFL, 0);
        fcntl(socket, F_SETFL, flags | O_NONBLOCK);
        
        struct sockaddr_in6 addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        
        if (inet_pton(AF_INET6, ip.c_str(), &addr.sin6_addr) != 1) {
            // Try IPv4
            struct sockaddr_in addr4;
            memset(&addr4, 0, sizeof(addr4));
            addr4.sin_family = AF_INET;
            addr4.sin_port = htons(port);
            if (inet_pton(AF_INET, ip.c_str(), &addr4.sin_addr) == 1) {
                // Convert to IPv4-mapped IPv6
                memset(&addr, 0, sizeof(addr));
                addr.sin6_family = AF_INET6;
                addr.sin6_port = htons(port);
                memset(addr.sin6_addr.s6_addr, 0, 10);
                memset(addr.sin6_addr.s6_addr + 10, 0xff, 2);
                memcpy(addr.sin6_addr.s6_addr + 12, &addr4.sin_addr, 4);
            } else {
                close(socket);
                return false;
            }
        }
        
        int result = ::connect(socket, (struct sockaddr*)&addr, sizeof(addr));
        if (result < 0 && errno != EINPROGRESS) {
            close(socket);
            return false;
        }
        
        state = PeerState::CONNECTING;
        running = true;
        
        // Start receive thread
        recvThread = std::thread([this]() {
            std::vector<uint8_t> buffer(4096);
            
            while (running) {
                fd_set fds;
                FD_ZERO(&fds);
                FD_SET(socket, &fds);
                
                struct timeval tv;
                tv.tv_sec = 1;
                tv.tv_usec = 0;
                
                if (select(socket + 1, &fds, nullptr, nullptr, &tv) > 0) {
                    ssize_t len = recv(socket, buffer.data(), buffer.size(), 0);
                    if (len > 0) {
                        recvBuffer.insert(recvBuffer.end(), buffer.begin(), buffer.begin() + len);
                        
                        // Process messages
                        while (recvBuffer.size() >= 24) {
                            Message msg;
                            if (msg.deserialize(recvBuffer)) {
                                // Handle message
                                recvBuffer.erase(recvBuffer.begin(), 
                                                recvBuffer.begin() + 24 + msg.header.length);
                            } else {
                                break;
                            }
                        }
                    } else if (len == 0) {
                        break; // Connection closed
                    }
                }
            }
        });
        
        return true;
    }

    void Peer::disconnect() {
        running = false;
        
        if (recvThread.joinable()) {
            recvThread.join();
        }
        
        if (sendThread.joinable()) {
            sendThread.join();
        }
        
        if (socket >= 0) {
            close(socket);
            socket = -1;
        }
        
        state = PeerState::DISCONNECTED;
    }

    bool Peer::isConnected() const {
        return state == PeerState::CONNECTED || state == PeerState::SYNCING;
    }

    bool Peer::sendMessage(const Message& message) {
        std::lock_guard<std::mutex> lock(sendMutex);
        
        auto data = message.serialize();
        ssize_t sent = send(socket, data.data(), data.size(), 0);
        return sent == static_cast<ssize_t>(data.size());
    }

    void Peer::updateState(PeerState newState) {
        state = newState;
        info.state = newState;
        if (newState == PeerState::CONNECTED) {
            info.connectionTime = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }
    }

    uint64_t Peer::getPingTime() const {
        return info.pingTime;
    }

    void Peer::startPing() {
        pingNonce = Random::getUint64();
        lastPing = std::chrono::steady_clock::now();
        
        // Send ping message
        Message msg;
        msg.header.command = "ping";
        msg.payload.resize(8);
        uint64_t nonceBe = htobe64(pingNonce);
        memcpy(msg.payload.data(), &nonceBe, 8);
        msg.header.length = 8;
        msg.header.checksum = MessageHeader::calculateChecksum(msg.payload);
        
        sendMessage(msg);
    }

    void Peer::handlePong(uint64_t nonce) {
        if (nonce == pingNonce) {
            lastPong = std::chrono::steady_clock::now();
            auto pingTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                lastPong - lastPing).count();
            info.pingTime = pingTime;
            info.lastPing = std::chrono::duration_cast<std::chrono::seconds>(
                lastPong.time_since_epoch()).count();
        }
    }

} // namespace powercoin