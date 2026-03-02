#include "messages.h"
#include "../crypto/sha256.h"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace powercoin {

    // ============== NetworkMessage Implementation ==============

    NetworkMessage::NetworkMessage() : magic(MAGIC_POWERCOIN), checksum(0) {}

    uint32_t NetworkMessage::calculateChecksum(const std::vector<uint8_t>& payload) const {
        auto hash = SHA256::doubleHash(payload.data(), payload.size());
        uint32_t result;
        memcpy(&result, hash.data(), 4);
        return result;
    }

    size_t NetworkMessage::getSize() const {
        return 24; // header size
    }

    std::string NetworkMessage::toString() const {
        return "NetworkMessage: " + command;
    }

    // ============== VersionMessage Implementation ==============

    VersionMessage::VersionMessage() {
        command = MSG_VERSION;
        version = 70015;
        services = SERVICE_NODE_NETWORK | SERVICE_NODE_WITNESS;
        timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        addrRecvServices = 0;
        addrRecvIp = "::";
        addrRecvPort = 0;
        addrFromServices = services;
        addrFromIp = "::";
        addrFromPort = 8333;
        nonce = 0;
        userAgent = "/PowerCoin:1.0.0/";
        startHeight = 0;
        relay = true;
    }

    std::vector<uint8_t> VersionMessage::serialize() const {
        std::vector<uint8_t> data;

        // Version (4 bytes)
        uint32_t version_le = htole32(version);
        data.insert(data.end(), (uint8_t*)&version_le, (uint8_t*)&version_le + 4);

        // Services (8 bytes)
        uint64_t services_le = htole64(services);
        data.insert(data.end(), (uint8_t*)&services_le, (uint8_t*)&services_le + 8);

        // Timestamp (8 bytes)
        int64_t timestamp_le = htole64(timestamp);
        data.insert(data.end(), (uint8_t*)&timestamp_le, (uint8_t*)&timestamp_le + 8);

        // Receiver address services (8 bytes)
        uint64_t addrRecvServices_le = htole64(addrRecvServices);
        data.insert(data.end(), (uint8_t*)&addrRecvServices_le, (uint8_t*)&addrRecvServices_le + 8);

        // Receiver IP (16 bytes)
        std::vector<uint8_t> ipBytes(16, 0);
        if (addrRecvIp.find(':') != std::string::npos) {
            // IPv6
            inet_pton(AF_INET6, addrRecvIp.c_str(), ipBytes.data());
        } else {
            // IPv4 mapped
            struct in_addr addr4;
            if (inet_pton(AF_INET, addrRecvIp.c_str(), &addr4) == 1) {
                memset(ipBytes.data(), 0, 10);
                memset(ipBytes.data() + 10, 0xff, 2);
                memcpy(ipBytes.data() + 12, &addr4, 4);
            }
        }
        data.insert(data.end(), ipBytes.begin(), ipBytes.end());

        // Receiver port (2 bytes)
        uint16_t port_be = htobe16(addrRecvPort);
        data.insert(data.end(), (uint8_t*)&port_be, (uint8_t*)&port_be + 2);

        // Sender address services (8 bytes)
        uint64_t addrFromServices_le = htole64(addrFromServices);
        data.insert(data.end(), (uint8_t*)&addrFromServices_le, (uint8_t*)&addrFromServices_le + 8);

        // Sender IP (16 bytes)
        if (addrFromIp.find(':') != std::string::npos) {
            inet_pton(AF_INET6, addrFromIp.c_str(), ipBytes.data());
        } else {
            struct in_addr addr4;
            if (inet_pton(AF_INET, addrFromIp.c_str(), &addr4) == 1) {
                memset(ipBytes.data(), 0, 10);
                memset(ipBytes.data() + 10, 0xff, 2);
                memcpy(ipBytes.data() + 12, &addr4, 4);
            }
        }
        data.insert(data.end(), ipBytes.begin(), ipBytes.end());

        // Sender port (2 bytes)
        port_be = htobe16(addrFromPort);
        data.insert(data.end(), (uint8_t*)&port_be, (uint8_t*)&port_be + 2);

        // Nonce (8 bytes)
        uint64_t nonce_le = htole64(nonce);
        data.insert(data.end(), (uint8_t*)&nonce_le, (uint8_t*)&nonce_le + 8);

        // User agent (variable)
        data.push_back(userAgent.size());
        data.insert(data.end(), userAgent.begin(), userAgent.end());

        // Start height (4 bytes)
        uint32_t height_le = htole32(startHeight);
        data.insert(data.end(), (uint8_t*)&height_le, (uint8_t*)&height_le + 4);

        // Relay (1 byte)
        data.push_back(relay ? 1 : 0);

        return data;
    }

    bool VersionMessage::deserialize(const std::vector<uint8_t>& data) {
        size_t pos = 0;

        if (pos + 4 > data.size()) return false;
        memcpy(&version, data.data() + pos, 4);
        version = le32toh(version);
        pos += 4;

        if (pos + 8 > data.size()) return false;
        memcpy(&services, data.data() + pos, 8);
        services = le64toh(services);
        pos += 8;

        if (pos + 8 > data.size()) return false;
        memcpy(&timestamp, data.data() + pos, 8);
        timestamp = le64toh(timestamp);
        pos += 8;

        if (pos + 8 > data.size()) return false;
        memcpy(&addrRecvServices, data.data() + pos, 8);
        addrRecvServices = le64toh(addrRecvServices);
        pos += 8;

        if (pos + 16 > data.size()) return false;
        char ipStr[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, data.data() + pos, ipStr, sizeof(ipStr))) {
            addrRecvIp = ipStr;
        }
        pos += 16;

        if (pos + 2 > data.size()) return false;
        uint16_t port_be;
        memcpy(&port_be, data.data() + pos, 2);
        addrRecvPort = be16toh(port_be);
        pos += 2;

        if (pos + 8 > data.size()) return false;
        memcpy(&addrFromServices, data.data() + pos, 8);
        addrFromServices = le64toh(addrFromServices);
        pos += 8;

        if (pos + 16 > data.size()) return false;
        if (inet_ntop(AF_INET6, data.data() + pos, ipStr, sizeof(ipStr))) {
            addrFromIp = ipStr;
        }
        pos += 16;

        if (pos + 2 > data.size()) return false;
        memcpy(&port_be, data.data() + pos, 2);
        addrFromPort = be16toh(port_be);
        pos += 2;

        if (pos + 8 > data.size()) return false;
        memcpy(&nonce, data.data() + pos, 8);
        nonce = le64toh(nonce);
        pos += 8;

        if (pos >= data.size()) return false;
        uint8_t uaLen = data[pos++];
        if (pos + uaLen > data.size()) return false;
        userAgent.assign((char*)data.data() + pos, uaLen);
        pos += uaLen;

        if (pos + 4 > data.size()) return false;
        memcpy(&startHeight, data.data() + pos, 4);
        startHeight = le32toh(startHeight);
        pos += 4;

        if (pos < data.size()) {
            relay = data[pos] != 0;
        }

        return true;
    }

    size_t VersionMessage::getSize() const {
        return NetworkMessage::getSize() + 4 + 8 + 8 + 8 + 16 + 2 + 8 + 16 + 2 + 8 + 1 + userAgent.size() + 4 + 1;
    }

    std::string VersionMessage::toString() const {
        std::stringstream ss;
        ss << "VersionMessage:\n";
        ss << "  version: " << version << "\n";
        ss << "  services: " << services << "\n";
        ss << "  timestamp: " << timestamp << "\n";
        ss << "  userAgent: " << userAgent << "\n";
        ss << "  startHeight: " << startHeight << "\n";
        ss << "  relay: " << relay;
        return ss.str();
    }

    // ============== VerackMessage Implementation ==============

    VerackMessage::VerackMessage() {
        command = MSG_VERACK;
    }

    std::vector<uint8_t> VerackMessage::serialize() const {
        return {};
    }

    bool VerackMessage::deserialize(const std::vector<uint8_t>& data) {
        return data.empty();
    }

    size_t VerackMessage::getSize() const {
        return NetworkMessage::getSize();
    }

    std::string VerackMessage::toString() const {
        return "VerackMessage";
    }

    // ============== NetworkAddress Implementation ==============

    NetworkAddress::NetworkAddress() : time(0), services(0), port(0) {}

    bool NetworkAddress::operator==(const NetworkAddress& other) const {
        return ip == other.ip && port == other.port;
    }

    std::vector<uint8_t> NetworkAddress::serialize() const {
        std::vector<uint8_t> data;

        // Time (4 bytes)
        uint32_t time_le = htole32(time);
        data.insert(data.end(), (uint8_t*)&time_le, (uint8_t*)&time_le + 4);

        // Services (8 bytes)
        uint64_t services_le = htole64(services);
        data.insert(data.end(), (uint8_t*)&services_le, (uint8_t*)&services_le + 8);

        // IP (16 bytes)
        std::vector<uint8_t> ipBytes(16, 0);
        if (ip.find(':') != std::string::npos) {
            inet_pton(AF_INET6, ip.c_str(), ipBytes.data());
        } else {
            struct in_addr addr4;
            if (inet_pton(AF_INET, ip.c_str(), &addr4) == 1) {
                memset(ipBytes.data(), 0, 10);
                memset(ipBytes.data() + 10, 0xff, 2);
                memcpy(ipBytes.data() + 12, &addr4, 4);
            }
        }
        data.insert(data.end(), ipBytes.begin(), ipBytes.end());

        // Port (2 bytes)
        uint16_t port_be = htobe16(port);
        data.insert(data.end(), (uint8_t*)&port_be, (uint8_t*)&port_be + 2);

        return data;
    }

    bool NetworkAddress::deserialize(const std::vector<uint8_t>& data, size_t& pos) {
        if (pos + 4 > data.size()) return false;
        memcpy(&time, data.data() + pos, 4);
        time = le32toh(time);
        pos += 4;

        if (pos + 8 > data.size()) return false;
        memcpy(&services, data.data() + pos, 8);
        services = le64toh(services);
        pos += 8;

        if (pos + 16 > data.size()) return false;
        char ipStr[INET6_ADDRSTRLEN];
        if (inet_ntop(AF_INET6, data.data() + pos, ipStr, sizeof(ipStr))) {
            ip = ipStr;
        }
        pos += 16;

        if (pos + 2 > data.size()) return false;
        uint16_t port_be;
        memcpy(&port_be, data.data() + pos, 2);
        port = be16toh(port_be);
        pos += 2;

        return true;
    }

    std::string NetworkAddress::toString() const {
        std::stringstream ss;
        ss << ip << ":" << port << " (services: " << services << ")";
        return ss.str();
    }

    bool NetworkAddress::isIPv4() const {
        static const uint8_t prefix[12] = {0,0,0,0,0,0,0,0,0,0,0xff,0xff};
        std::vector<uint8_t> ipBytes(16);
        if (inet_pton(AF_INET6, ip.c_str(), ipBytes.data()) == 1) {
            return memcmp(ipBytes.data(), prefix, 12) == 0;
        }
        return ip.find('.') != std::string::npos;
    }

    bool NetworkAddress::isValid() const {
        return !ip.empty() && port > 0 && port < 65536;
    }

    // ============== AddrMessage Implementation ==============

    AddrMessage::AddrMessage() {
        command = MSG_ADDR;
    }

    std::vector<uint8_t> AddrMessage::serialize() const {
        std::vector<uint8_t> data;

        // Count (variable length)
        if (addresses.size() < 0xFD) {
            data.push_back(addresses.size());
        } else if (addresses.size() <= 0xFFFF) {
            data.push_back(0xFD);
            uint16_t count_le = htole16(addresses.size());
            data.insert(data.end(), (uint8_t*)&count_le, (uint8_t*)&count_le + 2);
        } else {
            data.push_back(0xFE);
            uint32_t count_le = htole32(addresses.size());
            data.insert(data.end(), (uint8_t*)&count_le, (uint8_t*)&count_le + 4);
        }

        // Addresses
        for (const auto& addr : addresses) {
            auto addrData = addr.serialize();
            data.insert(data.end(), addrData.begin(), addrData.end());
        }

        return data;
    }

    bool AddrMessage::deserialize(const std::vector<uint8_t>& data) {
        size_t pos = 0;

        if (pos >= data.size()) return false;

        uint64_t count = 0;
        uint8_t first = data[pos++];

        if (first < 0xFD) {
            count = first;
        } else if (first == 0xFD) {
            if (pos + 2 > data.size()) return false;
            uint16_t count_le;
            memcpy(&count_le, data.data() + pos, 2);
            count = le16toh(count_le);
            pos += 2;
        } else if (first == 0xFE) {
            if (pos + 4 > data.size()) return false;
            uint32_t count_le;
            memcpy(&count_le, data.data() + pos, 4);
            count = le32toh(count_le);
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

    size_t AddrMessage::getSize() const {
        size_t size = NetworkMessage::getSize() + 1; // count byte
        for (const auto& addr : addresses) {
            size += 30; // 4+8+16+2
        }
        return size;
    }

    std::string AddrMessage::toString() const {
        std::stringstream ss;
        ss << "AddrMessage: " << addresses.size() << " addresses";
        return ss.str();
    }

    void AddrMessage::addAddress(const NetworkAddress& addr) {
        addresses.push_back(addr);
    }

    void AddrMessage::clear() {
        addresses.clear();
    }

    // ============== InventoryVector Implementation ==============

    InventoryVector::InventoryVector() : type(InventoryType::ERROR) {}

    InventoryVector::InventoryVector(InventoryType t, const std::string& h) 
        : type(t), hash(h) {}

    std::vector<uint8_t> InventoryVector::serialize() const {
        std::vector<uint8_t> data;

        // Type (4 bytes)
        uint32_t type_le = htole32(static_cast<uint32_t>(type));
        data.insert(data.end(), (uint8_t*)&type_le, (uint8_t*)&type_le + 4);

        // Hash (32 bytes)
        auto hashBytes = SHA256::hashToBytes(hash);
        data.insert(data.end(), hashBytes.begin(), hashBytes.end());

        return data;
    }

    bool InventoryVector::deserialize(const std::vector<uint8_t>& data, size_t& pos) {
        if (pos + 4 > data.size()) return false;

        uint32_t type_le;
        memcpy(&type_le, data.data() + pos, 4);
        type = static_cast<InventoryType>(le32toh(type_le));
        pos += 4;

        if (pos + 32 > data.size()) return false;
        std::array<uint8_t, 32> hashBytes;
        memcpy(hashBytes.data(), data.data() + pos, 32);
        hash = SHA256::bytesToHash(hashBytes);
        pos += 32;

        return true;
    }

    std::string InventoryVector::toString() const {
        std::stringstream ss;
        ss << "Inv: type=" << static_cast<int>(type) << " hash=" << hash.substr(0, 16) << "...";
        return ss.str();
    }

    bool InventoryVector::operator<(const InventoryVector& other) const {
        return hash < other.hash;
    }

    bool InventoryVector::operator==(const InventoryVector& other) const {
        return type == other.type && hash == other.hash;
    }

    std::string InventoryVector::generateHash() {
        std::vector<uint8_t> random(32);
        for (size_t i = 0; i < 32; i++) {
            random[i] = rand() % 256;
        }
        return SHA256::bytesToHash(*reinterpret_cast<std::array<uint8_t, 32>*>(random.data()));
    }

    // ============== InvMessage Implementation ==============

    InvMessage::InvMessage() {
        command = MSG_INV;
    }

    std::vector<uint8_t> InvMessage::serialize() const {
        std::vector<uint8_t> data;

        // Count (variable length)
        if (inventories.size() < 0xFD) {
            data.push_back(inventories.size());
        } else if (inventories.size() <= 0xFFFF) {
            data.push_back(0xFD);
            uint16_t count_le = htole16(inventories.size());
            data.insert(data.end(), (uint8_t*)&count_le, (uint8_t*)&count_le + 2);
        } else {
            data.push_back(0xFE);
            uint32_t count_le = htole32(inventories.size());
            data.insert(data.end(), (uint8_t*)&count_le, (uint8_t*)&count_le + 4);
        }

        // Inventories
        for (const auto& inv : inventories) {
            auto invData = inv.serialize();
            data.insert(data.end(), invData.begin(), invData.end());
        }

        return data;
    }

    bool InvMessage::deserialize(const std::vector<uint8_t>& data) {
        size_t pos = 0;

        if (pos >= data.size()) return false;

        uint64_t count = 0;
        uint8_t first = data[pos++];

        if (first < 0xFD) {
            count = first;
        } else if (first == 0xFD) {
            if (pos + 2 > data.size()) return false;
            uint16_t count_le;
            memcpy(&count_le, data.data() + pos, 2);
            count = le16toh(count_le);
            pos += 2;
        } else if (first == 0xFE) {
            if (pos + 4 > data.size()) return false;
            uint32_t count_le;
            memcpy(&count_le, data.data() + pos, 4);
            count = le32toh(count_le);
            pos += 4;
        } else {
            return false;
        }

        inventories.clear();
        for (uint64_t i = 0; i < count; i++) {
            InventoryVector inv;
            if (!inv.deserialize(data, pos)) return false;
            inventories.push_back(inv);
        }

        return true;
    }

    size_t InvMessage::getSize() const {
        size_t size = NetworkMessage::getSize() + 1; // count byte
        size += inventories.size() * 36; // 4 + 32
        return size;
    }

    std::string InvMessage::toString() const {
        std::stringstream ss;
        ss << "InvMessage: " << inventories.size() << " items";
        return ss.str();
    }

    void InvMessage::addInventory(const InventoryVector& inv) {
        inventories.push_back(inv);
    }

    void InvMessage::addTransaction(const std::string& txHash) {
        inventories.emplace_back(InventoryType::MSG_TX, txHash);
    }

    void InvMessage::addBlock(const std::string& blockHash) {
        inventories.emplace_back(InventoryType::MSG_BLOCK, blockHash);
    }

    bool InvMessage::contains(const InventoryVector& inv) const {
        for (const auto& i : inventories) {
            if (i == inv) return true;
        }
        return false;
    }

    // ============== GetDataMessage Implementation ==============

    GetDataMessage::GetDataMessage() {
        command = MSG_GETDATA;
    }

    std::vector<uint8_t> GetDataMessage::serialize() const {
        InvMessage invMsg;
        invMsg.inventories = inventories;
        return invMsg.serialize();
    }

    bool GetDataMessage::deserialize(const std::vector<uint8_t>& data) {
        InvMessage invMsg;
        if (!invMsg.deserialize(data)) return false;
        inventories = invMsg.inventories;
        return true;
    }

    size_t GetDataMessage::getSize() const {
        InvMessage invMsg;
        invMsg.inventories = inventories;
        return invMsg.getSize();
    }

    std::string GetDataMessage::toString() const {
        std::stringstream ss;
        ss << "GetDataMessage: " << inventories.size() << " items";
        return ss.str();
    }

    void GetDataMessage::addInventory(const InventoryVector& inv) {
        inventories.push_back(inv);
    }

    void GetDataMessage::addTransaction(const std::string& txHash) {
        inventories.emplace_back(InventoryType::MSG_TX, txHash);
    }

    void GetDataMessage::addBlock(const std::string& blockHash) {
        inventories.emplace_back(InventoryType::MSG_BLOCK, blockHash);
    }

    // ============== NotFoundMessage Implementation ==============

    NotFoundMessage::NotFoundMessage() {
        command = MSG_NOTFOUND;
    }

    std::vector<uint8_t> NotFoundMessage::serialize() const {
        InvMessage invMsg;
        invMsg.inventories = inventories;
        return invMsg.serialize();
    }

    bool NotFoundMessage::deserialize(const std::vector<uint8_t>& data) {
        InvMessage invMsg;
        if (!invMsg.deserialize(data)) return false;
        inventories = invMsg.inventories;
        return true;
    }

    size_t NotFoundMessage::getSize() const {
        InvMessage invMsg;
        invMsg.inventories = inventories;
        return invMsg.getSize();
    }

    std::string NotFoundMessage::toString() const {
        std::stringstream ss;
        ss << "NotFoundMessage: " << inventories.size() << " items";
        return ss.str();
    }

    // ============== GetBlocksMessage Implementation ==============

    GetBlocksMessage::GetBlocksMessage() {
        command = MSG_GETBLOCKS;
        version = 70015;
        hashStop = "0";
    }

    std::vector<uint8_t> GetBlocksMessage::serialize() const {
        std::vector<uint8_t> data;

        // Version (4 bytes)
        uint32_t version_le = htole32(version);
        data.insert(data.end(), (uint8_t*)&version_le, (uint8_t*)&version_le + 4);

        // Hash count (variable)
        if (blockLocatorHashes.size() < 0xFD) {
            data.push_back(blockLocatorHashes.size());
        } else if (blockLocatorHashes.size() <= 0xFFFF) {
            data.push_back(0xFD);
            uint16_t count_le = htole16(blockLocatorHashes.size());
            data.insert(data.end(), (uint8_t*)&count_le, (uint8_t*)&count_le + 2);
        } else {
            data.push_back(0xFE);
            uint32_t count_le = htole32(blockLocatorHashes.size());
            data.insert(data.end(), (uint8_t*)&count_le, (uint8_t*)&count_le + 4);
        }

        // Block locator hashes
        for (const auto& hash : blockLocatorHashes) {
            auto hashBytes = SHA256::hashToBytes(hash);
            data.insert(data.end(), hashBytes.begin(), hashBytes.end());
        }

        // Hash stop
        auto hashStopBytes = SHA256::hashToBytes(hashStop);
        data.insert(data.end(), hashStopBytes.begin(), hashStopBytes.end());

        return data;
    }

    bool GetBlocksMessage::deserialize(const std::vector<uint8_t>& data) {
        size_t pos = 0;

        if (pos + 4 > data.size()) return false;
        memcpy(&version, data.data() + pos, 4);
        version = le32toh(version);
        pos += 4;

        if (pos >= data.size()) return false;

        uint64_t count = 0;
        uint8_t first = data[pos++];

        if (first < 0xFD) {
            count = first;
        } else if (first == 0xFD) {
            if (pos + 2 > data.size()) return false;
            uint16_t count_le;
            memcpy(&count_le, data.data() + pos, 2);
            count = le16toh(count_le);
            pos += 2;
        } else if (first == 0xFE) {
            if (pos + 4 > data.size()) return false;
            uint32_t count_le;
            memcpy(&count_le, data.data() + pos, 4);
            count = le32toh(count_le);
            pos += 4;
        } else {
            return false;
        }

        blockLocatorHashes.clear();
        for (uint64_t i = 0; i < count; i++) {
            if (pos + 32 > data.size()) return false;
            std::array<uint8_t, 32> hashBytes;
            memcpy(hashBytes.data(), data.data() + pos, 32);
            blockLocatorHashes.push_back(SHA256::bytesToHash(hashBytes));
            pos += 32;
        }

        if (pos + 32 > data.size()) return false;
        std::array<uint8_t, 32> hashStopBytes;
        memcpy(hashStopBytes.data(), data.data() + pos, 32);
        hashStop = SHA256::bytesToHash(hashStopBytes);

        return true;
    }

    size_t GetBlocksMessage::getSize() const {
        return NetworkMessage::getSize() + 4 + 1 + blockLocatorHashes.size() * 32 + 32;
    }

    std::string GetBlocksMessage::toString() const {
        std::stringstream ss;
        ss << "GetBlocksMessage: " << blockLocatorHashes.size() << " locators";
        return ss.str();
    }

    // ============== PingMessage Implementation ==============

    PingMessage::PingMessage() {
        command = MSG_PING;
        nonce = 0;
    }

    PingMessage::PingMessage(uint64_t n) {
        command = MSG_PING;
        nonce = n;
    }

    std::vector<uint8_t> PingMessage::serialize() const {
        std::vector<uint8_t> data(8);
        uint64_t nonce_le = htole64(nonce);
        memcpy(data.data(), &nonce_le, 8);
        return data;
    }

    bool PingMessage::deserialize(const std::vector<uint8_t>& data) {
        if (data.size() != 8) return false;
        memcpy(&nonce, data.data(), 8);
        nonce = le64toh(nonce);
        return true;
    }

    size_t PingMessage::getSize() const {
        return NetworkMessage::getSize() + 8;
    }

    std::string PingMessage::toString() const {
        std::stringstream ss;
        ss << "PingMessage: nonce=" << nonce;
        return ss.str();
    }

    // ============== PongMessage Implementation ==============

    PongMessage::PongMessage() {
        command = MSG_PONG;
        nonce = 0;
    }

    PongMessage::PongMessage(uint64_t n) {
        command = MSG_PONG;
        nonce = n;
    }

    std::vector<uint8_t> PongMessage::serialize() const {
        std::vector<uint8_t> data(8);
        uint64_t nonce_le = htole64(nonce);
        memcpy(data.data(), &nonce_le, 8);
        return data;
    }

    bool PongMessage::deserialize(const std::vector<uint8_t>& data) {
        if (data.size() != 8) return false;
        memcpy(&nonce, data.data(), 8);
        nonce = le64toh(nonce);
        return true;
    }

    size_t PongMessage::getSize() const {
        return NetworkMessage::getSize() + 8;
    }

    std::string PongMessage::toString() const {
        std::stringstream ss;
        ss << "PongMessage: nonce=" << nonce;
        return ss.str();
    }

    // ============== RejectMessage Implementation ==============

    RejectMessage::RejectMessage() {
        command = MSG_REJECT;
        code = RejectCode::REJECT_MALFORMED;
    }

    std::vector<uint8_t> RejectMessage::serialize() const {
        std::vector<uint8_t> data;

        // Message (variable)
        data.push_back(message.size());
        data.insert(data.end(), message.begin(), message.end());

        // Code (1 byte)
        data.push_back(static_cast<uint8_t>(code));

        // Reason (variable)
        data.push_back(reason.size());
        data.insert(data.end(), reason.begin(), reason.end());

        // Data (variable)
        if (!data.empty()) {
            data.push_back(data.size());
            data.insert(data.end(), data.begin(), data.end());
        }

        return data;
    }

    bool RejectMessage::deserialize(const std::vector<uint8_t>& data) {
        size_t pos = 0;

        if (pos >= data.size()) return false;

        uint8_t msgLen = data[pos++];
        if (pos + msgLen > data.size()) return false;
        message.assign((char*)data.data() + pos, msgLen);
        pos += msgLen;

        if (pos >= data.size()) return false;
        code = static_cast<RejectCode>(data[pos++]);

        if (pos >= data.size()) return false;
        uint8_t reasonLen = data[pos++];
        if (pos + reasonLen > data.size()) return false;
        reason.assign((char*)data.data() + pos, reasonLen);
        pos += reasonLen;

        if (pos < data.size()) {
            uint8_t dataLen = data[pos++];
            if (pos + dataLen <= data.size()) {
                this->data.assign((char*)data.data() + pos, dataLen);
            }
        }

        return true;
    }

    size_t RejectMessage::getSize() const {
        return NetworkMessage::getSize() + 1 + message.size() + 1 + 1 + reason.size() + 1 + data.size();
    }

    std::string RejectMessage::toString() const {
        std::stringstream ss;
        ss << "RejectMessage: " << message << " " << codeToString(code) << " " << reason;
        return ss.str();
    }

    std::string RejectMessage::codeToString(RejectCode code) {
        switch (code) {
            case RejectCode::REJECT_MALFORMED: return "MALFORMED";
            case RejectCode::REJECT_INVALID: return "INVALID";
            case RejectCode::REJECT_OBSOLETE: return "OBSOLETE";
            case RejectCode::REJECT_DUPLICATE: return "DUPLICATE";
            case RejectCode::REJECT_NONSTANDARD: return "NONSTANDARD";
            case RejectCode::REJECT_DUST: return "DUST";
            case RejectCode::REJECT_INSUFFICIENTFEE: return "INSUFFICIENTFEE";
            case RejectCode::REJECT_CHECKPOINT: return "CHECKPOINT";
            default: return "UNKNOWN";
        }
    }

    // ============== MessageFactory Implementation ==============

    std::unique_ptr<NetworkMessage> MessageFactory::createMessage(const std::vector<uint8_t>& data) {
        if (data.size() < 24) return nullptr;

        std::string cmd = getCommand(data);
        std::unique_ptr<NetworkMessage> msg;

        if (cmd == MSG_VERSION) {
            msg = std::make_unique<VersionMessage>();
        } else if (cmd == MSG_VERACK) {
            msg = std::make_unique<VerackMessage>();
        } else if (cmd == MSG_ADDR) {
            msg = std::make_unique<AddrMessage>();
        } else if (cmd == MSG_INV) {
            msg = std::make_unique<InvMessage>();
        } else if (cmd == MSG_GETDATA) {
            msg = std::make_unique<GetDataMessage>();
        } else if (cmd == MSG_NOTFOUND) {
            msg = std::make_unique<NotFoundMessage>();
        } else if (cmd == MSG_GETBLOCKS) {
            msg = std::make_unique<GetBlocksMessage>();
        } else if (cmd == MSG_PING) {
            msg = std::make_unique<PingMessage>();
        } else if (cmd == MSG_PONG) {
            msg = std::make_unique<PongMessage>();
        } else if (cmd == MSG_REJECT) {
            msg = std::make_unique<RejectMessage>();
        } else {
            return nullptr;
        }

        if (!msg->deserialize(std::vector<uint8_t>(data.begin() + 24, data.end()))) {
            return nullptr;
        }

        return msg;
    }

    std::string MessageFactory::getCommand(const std::vector<uint8_t>& data) {
        if (data.size() < 24) return "";
        return std::string((char*)data.data() + 4, 12);
    }

    bool MessageFactory::validateChecksum(const std::vector<uint8_t>& data) {
        if (data.size() < 24) return false;

        uint32_t expectedChecksum;
        memcpy(&expectedChecksum, data.data() + 20, 4);

        std::vector<uint8_t> payload(data.begin() + 24, data.end());
        auto hash = SHA256::doubleHash(payload.data(), payload.size());
        uint32_t actualChecksum;
        memcpy(&actualChecksum, hash.data(), 4);

        return expectedChecksum == actualChecksum;
    }

    // ============== MessageBuilder Implementation ==============

    MessageBuilder::MessageBuilder(uint32_t networkMagic) : magic(networkMagic) {}

    std::vector<uint8_t> MessageBuilder::buildVersion(const VersionMessage& msg) {
        auto payload = msg.serialize();
        std::vector<uint8_t> header(24);

        // Magic (4 bytes)
        uint32_t magic_le = htole32(magic);
        memcpy(header.data(), &magic_le, 4);

        // Command (12 bytes)
        memset(header.data() + 4, 0, 12);
        strncpy((char*)header.data() + 4, MSG_VERSION, 11);

        // Length (4 bytes)
        uint32_t len_le = htole32(payload.size());
        memcpy(header.data() + 16, &len_le, 4);

        // Checksum (4 bytes)
        uint32_t checksum = msg.calculateChecksum(payload);
        uint32_t checksum_le = htole32(checksum);
        memcpy(header.data() + 20, &checksum_le, 4);

        header.insert(header.end(), payload.begin(), payload.end());
        return header;
    }

    std::vector<uint8_t> MessageBuilder::buildVerack() {
        VerackMessage msg;
        auto payload = msg.serialize();
        std::vector<uint8_t> header(24);

        uint32_t magic_le = htole32(magic);
        memcpy(header.data(), &magic_le, 4);
        memset(header.data() + 4, 0, 12);
        strncpy((char*)header.data() + 4, MSG_VERACK, 11);
        uint32_t len_le = htole32(payload.size());
        memcpy(header.data() + 16, &len_le, 4);
        uint32_t checksum = msg.calculateChecksum(payload);
        uint32_t checksum_le = htole32(checksum);
        memcpy(header.data() + 20, &checksum_le, 4);

        header.insert(header.end(), payload.begin(), payload.end());
        return header;
    }

    std::vector<uint8_t> MessageBuilder::buildAddr(const std::vector<NetworkAddress>& addrs) {
        AddrMessage msg;
        msg.addresses = addrs;
        auto payload = msg.serialize();
        std::vector<uint8_t> header(24);

        uint32_t magic_le = htole32(magic);
        memcpy(header.data(), &magic_le, 4);
        memset(header.data() + 4, 0, 12);
        strncpy((char*)header.data() + 4, MSG_ADDR, 11);
        uint32_t len_le = htole32(payload.size());
        memcpy(header.data() + 16, &len_le, 4);
        uint32_t checksum = msg.calculateChecksum(payload);
        uint32_t checksum_le = htole32(checksum);
        memcpy(header.data() + 20, &checksum_le, 4);

        header.insert(header.end(), payload.begin(), payload.end());
        return header;
    }

    std::vector<uint8_t> MessageBuilder::buildInv(const std::vector<InventoryVector>& invs) {
        InvMessage msg;
        msg.inventories = invs;
        auto payload = msg.serialize();
        std::vector<uint8_t> header(24);

        uint32_t magic_le = htole32(magic);
        memcpy(header.data(), &magic_le, 4);
        memset(header.data() + 4, 0, 12);
        strncpy((char*)header.data() + 4, MSG_INV, 11);
        uint32_t len_le = htole32(payload.size());
        memcpy(header.data() + 16, &len_le, 4);
        uint32_t checksum = msg.calculateChecksum(payload);
        uint32_t checksum_le = htole32(checksum);
        memcpy(header.data() + 20, &checksum_le, 4);

        header.insert(header.end(), payload.begin(), payload.end());
        return header;
    }

    std::vector<uint8_t> MessageBuilder::buildGetData(const std::vector<InventoryVector>& invs) {
        GetDataMessage msg;
        msg.inventories = invs;
        auto payload = msg.serialize();
        std::vector<uint8_t> header(24);

        uint32_t magic_le = htole32(magic);
        memcpy(header.data(), &magic_le, 4);
        memset(header.data() + 4, 0, 12);
        strncpy((char*)header.data() + 4, MSG_GETDATA, 11);
        uint32_t len_le = htole32(payload.size());
        memcpy(header.data() + 16, &len_le, 4);
        uint32_t checksum = msg.calculateChecksum(payload);
        uint32_t checksum_le = htole32(checksum);
        memcpy(header.data() + 20, &checksum_le, 4);

        header.insert(header.end(), payload.begin(), payload.end());
        return header;
    }

    std::vector<uint8_t> MessageBuilder::buildGetBlocks(const std::vector<std::string>& locator,
                                                        const std::string& hashStop) {
        GetBlocksMessage msg;
        msg.blockLocatorHashes = locator;
        msg.hashStop = hashStop;
        auto payload = msg.serialize();
        std::vector<uint8_t> header(24);

        uint32_t magic_le = htole32(magic);
        memcpy(header.data(), &magic_le, 4);
        memset(header.data() + 4, 0, 12);
        strncpy((char*)header.data() + 4, MSG_GETBLOCKS, 11);
        uint32_t len_le = htole32(payload.size());
        memcpy(header.data() + 16, &len_le, 4);
        uint32_t checksum = msg.calculateChecksum(payload);
        uint32_t checksum_le = htole32(checksum);
        memcpy(header.data() + 20, &checksum_le, 4);

        header.insert(header.end(), payload.begin(), payload.end());
        return header;
    }

    std::vector<uint8_t> MessageBuilder::buildPing(uint64_t nonce) {
        PingMessage msg(nonce);
        auto payload = msg.serialize();
        std::vector<uint8_t> header(24);

        uint32_t magic_le = htole32(magic);
        memcpy(header.data(), &magic_le, 4);
        memset(header.data() + 4, 0, 12);
        strncpy((char*)header.data() + 4, MSG_PING, 11);
        uint32_t len_le = htole32(payload.size());
        memcpy(header.data() + 16, &len_le, 4);
        uint32_t checksum = msg.calculateChecksum(payload);
        uint32_t checksum_le = htole32(checksum);
        memcpy(header.data() + 20, &checksum_le, 4);

        header.insert(header.end(), payload.begin(), payload.end());
        return header;
    }

    std::vector<uint8_t> MessageBuilder::buildPong(uint64_t nonce) {
        PongMessage msg(nonce);
        auto payload = msg.serialize();
        std::vector<uint8_t> header(24);

        uint32_t magic_le = htole32(magic);
        memcpy(header.data(), &magic_le, 4);
        memset(header.data() + 4, 0, 12);
        strncpy((char*)header.data() + 4, MSG_PONG, 11);
        uint32_t len_le = htole32(payload.size());
        memcpy(header.data() + 16, &len_le, 4);
        uint32_t checksum = msg.calculateChecksum(payload);
        uint32_t checksum_le = htole32(checksum);
        memcpy(header.data() + 20, &checksum_le, 4);

        header.insert(header.end(), payload.begin(), payload.end());
        return header;
    }

} // namespace powercoin