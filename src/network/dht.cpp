#include "dht.h"
#include "../crypto/sha256.h"
#include "../crypto/random.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>

namespace powercoin {

    // ============== DHTNodeID Implementation ==============

    DHTNodeID::DHTNodeID() {
        data.fill(0);
    }

    DHTNodeID::DHTNodeID(const std::vector<uint8_t>& bytes) {
        if (bytes.size() >= DHT_ID_SIZE) {
            std::copy(bytes.begin(), bytes.begin() + DHT_ID_SIZE, data.begin());
        } else {
            data.fill(0);
            std::copy(bytes.begin(), bytes.end(), data.begin());
        }
    }

    DHTNodeID::DHTNodeID(const std::string& hex) {
        data.fill(0);
        if (hex.length() >= DHT_ID_SIZE * 2) {
            for (size_t i = 0; i < DHT_ID_SIZE; i++) {
                std::string byteStr = hex.substr(i * 2, 2);
                data[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
            }
        }
    }

    DHTNodeID::DHTNodeID(uint64_t seed) {
        std::mt19937_64 gen(seed);
        for (size_t i = 0; i < DHT_ID_SIZE; i += 8) {
            uint64_t val = gen();
            size_t bytes = std::min(size_t(8), DHT_ID_SIZE - i);
            memcpy(data.data() + i, &val, bytes);
        }
    }

    bool DHTNodeID::operator==(const DHTNodeID& other) const {
        return data == other.data;
    }

    bool DHTNodeID::operator!=(const DHTNodeID& other) const {
        return data != other.data;
    }

    bool DHTNodeID::operator<(const DHTNodeID& other) const {
        return data < other.data;
    }

    DHTNodeID DHTNodeID::xor(const DHTNodeID& other) const {
        DHTNodeID result;
        for (size_t i = 0; i < DHT_ID_SIZE; i++) {
            result.data[i] = data[i] ^ other.data[i];
        }
        return result;
    }

    int DHTNodeID::getCommonPrefixBits(const DHTNodeID& other) const {
        auto x = xor(other);
        for (int i = 0; i < DHT_B; i++) {
            int bytePos = i / 8;
            int bitPos = 7 - (i % 8);
            if ((x.data[bytePos] >> bitPos) & 1) {
                return i;
            }
        }
        return DHT_B;
    }

    bool DHTNodeID::isZero() const {
        for (auto byte : data) {
            if (byte != 0) return false;
        }
        return true;
    }

    std::string DHTNodeID::toString() const {
        std::stringstream ss;
        for (auto byte : data) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(byte);
        }
        return ss.str();
    }

    std::string DHTNodeID::toHex() const {
        return toString();
    }

    std::vector<uint8_t> DHTNodeID::toBytes() const {
        return std::vector<uint8_t>(data.begin(), data.end());
    }

    size_t DHTNodeID::hash() const {
        size_t h = 0;
        for (size_t i = 0; i < DHT_ID_SIZE; i += sizeof(size_t)) {
            size_t val = 0;
            size_t bytes = std::min(sizeof(size_t), DHT_ID_SIZE - i);
            memcpy(&val, data.data() + i, bytes);
            h ^= val;
        }
        return h;
    }

    DHTNodeID DHTNodeID::generate() {
        std::vector<uint8_t> bytes(DHT_ID_SIZE);
        Random::getBytes(bytes.data(), bytes.size());
        return DHTNodeID(bytes);
    }

    DHTNodeID DHTNodeID::fromString(const std::string& str) {
        return DHTNodeID(str);
    }

    DHTNodeID DHTNodeID::fromHash(const std::vector<uint8_t>& data) {
        auto hash = SHA256::doubleHash(data.data(), data.size());
        hash.resize(DHT_ID_SIZE);
        return DHTNodeID(hash);
    }

    DHTNodeID DHTNodeID::randomInBucket(int bucketIndex) const {
        std::vector<uint8_t> bytes(DHT_ID_SIZE);
        Random::getBytes(bytes.data(), bytes.size());
        
        DHTNodeID random(bytes);
        
        // Keep first bucketIndex bits the same as this node
        for (int i = 0; i < bucketIndex; i++) {
            int bytePos = i / 8;
            int bitPos = 7 - (i % 8);
            uint8_t mask = 1 << bitPos;
            random.data[bytePos] = (random.data[bytePos] & ~mask) | (data[bytePos] & mask);
        }
        
        // Flip the bucketIndex-th bit
        if (bucketIndex < DHT_B) {
            int bytePos = bucketIndex / 8;
            int bitPos = 7 - (bucketIndex % 8);
            random.data[bytePos] ^= (1 << bitPos);
        }
        
        return random;
    }

    // ============== DHTNode Implementation ==============

    DHTNode::DHTNode() 
        : port(0), lastSeen(0), version(0), responseTime(0), 
          failures(0), isHealthy(true), isBootstrapped(false) {}

    std::string DHTNode::toString() const {
        std::stringstream ss;
        ss << "DHTNode: " << id.toString() << "\n";
        ss << "  Address: " << ip << ":" << port << "\n";
        ss << "  Version: " << version << "\n";
        ss << "  Last Seen: " << lastSeen << "\n";
        ss << "  Healthy: " << (isHealthy ? "yes" : "no") << "\n";
        return ss.str();
    }

    bool DHTNode::isExpired() const {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return (now - lastSeen) > DHT_EXPIRY_TIME;
    }

    void DHTNode::updateSeen() {
        lastSeen = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        failures = 0;
        isHealthy = true;
    }

    // ============== KBucket Implementation ==============

    KBucket::KBucket(size_t maxSize) : maxSize(maxSize), lastRefreshed(0) {}

    bool KBucket::addNode(const DHTNode& node) {
        std::lock_guard<std::mutex> lock(mutex);

        // Check if node already exists
        if (nodeIds.find(node.id) != nodeIds.end()) {
            // Move to front (most recent)
            for (auto it = nodes.begin(); it != nodes.end(); ++it) {
                if (it->id == node.id) {
                    nodes.erase(it);
                    break;
                }
            }
            nodes.push_front(node);
            return true;
        }

        // Add new node
        if (nodes.size() < maxSize) {
            nodes.push_front(node);
            nodeIds.insert(node.id);
            return true;
        }

        return false; // Bucket full
    }

    bool KBucket::removeNode(const DHTNodeID& id) {
        std::lock_guard<std::mutex> lock(mutex);

        for (auto it = nodes.begin(); it != nodes.end(); ++it) {
            if (it->id == id) {
                nodes.erase(it);
                nodeIds.erase(id);
                return true;
            }
        }
        return false;
    }

    bool KBucket::contains(const DHTNodeID& id) const {
        std::lock_guard<std::mutex> lock(mutex);
        return nodeIds.find(id) != nodeIds.end();
    }

    DHTNode* KBucket::getNode(const DHTNodeID& id) {
        std::lock_guard<std::mutex> lock(mutex);

        for (auto& node : nodes) {
            if (node.id == id) {
                return &node;
            }
        }
        return nullptr;
    }

    std::vector<DHTNode> KBucket::getNodes(size_t count) const {
        std::lock_guard<std::mutex> lock(mutex);

        std::vector<DHTNode> result;
        if (count == 0 || count >= nodes.size()) {
            result.assign(nodes.begin(), nodes.end());
        } else {
            result.assign(nodes.begin(), std::next(nodes.begin(), count));
        }
        return result;
    }

    std::vector<DHTNode> KBucket::getRandomNodes(size_t count) const {
        std::lock_guard<std::mutex> lock(mutex);

        if (nodes.empty() || count == 0) return {};

        std::vector<DHTNode> allNodes(nodes.begin(), nodes.end());
        std::vector<DHTNode> result;

        size_t n = std::min(count, allNodes.size());
        auto indices = Random::sample(allNodes.size(), n);

        for (auto idx : indices) {
            result.push_back(allNodes[idx]);
        }

        return result;
    }

    size_t KBucket::size() const {
        std::lock_guard<std::mutex> lock(mutex);
        return nodes.size();
    }

    bool KBucket::isFull() const {
        std::lock_guard<std::mutex> lock(mutex);
        return nodes.size() >= maxSize;
    }

    void KBucket::refresh() {
        lastRefreshed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    void KBucket::split(KBucket& left, KBucket& right, int bitIndex) const {
        std::lock_guard<std::mutex> lock(mutex);

        for (const auto& node : nodes) {
            int bytePos = bitIndex / 8;
            int bitPos = 7 - (bitIndex % 8);
            if ((node.id.toBytes()[bytePos] >> bitPos) & 1) {
                right.addNode(node);
            } else {
                left.addNode(node);
            }
        }
    }

    std::vector<DHTNode> KBucket::getClosestNodes(const DHTNodeID& target, size_t count) const {
        std::lock_guard<std::mutex> lock(mutex);

        std::vector<std::pair<DHTNodeID, DHTNode>> distances;
        for (const auto& node : nodes) {
            distances.emplace_back(target.xor(node.id), node);
        }

        std::sort(distances.begin(), distances.end(),
            [](const auto& a, const auto& b) {
                return a.first < b.first;
            });

        std::vector<DHTNode> result;
        size_t n = std::min(count, distances.size());
        for (size_t i = 0; i < n; i++) {
            result.push_back(distances[i].second);
        }

        return result;
    }

    // ============== RoutingTable Implementation ==============

    RoutingTable::RoutingTable(const DHTNodeID& nodeId) : localNodeId(nodeId) {
        // Initialize with one bucket covering entire ID space
        buckets.push_back(std::make_unique<KBucket>());
    }

    RoutingTable::~RoutingTable() = default;

    int RoutingTable::getBucketIndex(const DHTNodeID& id) const {
        if (id == localNodeId) return -1;

        int commonBits = localNodeId.getCommonPrefixBits(id);
        return std::min(commonBits, DHT_B - 1);
    }

    void RoutingTable::splitBucket(int index) {
        if (index < 0 || index >= static_cast<int>(buckets.size())) return;

        auto& bucket = buckets[index];
        if (!bucket->isFull()) return;

        auto left = std::make_unique<KBucket>();
        auto right = std::make_unique<KBucket>();

        bucket->split(*left, *right, index);

        buckets.erase(buckets.begin() + index);
        buckets.insert(buckets.begin() + index, std::move(right));
        buckets.insert(buckets.begin() + index, std::move(left));
    }

    bool RoutingTable::addNode(const DHTNode& node) {
        std::lock_guard<std::recursive_mutex> lock(mutex);

        if (node.id == localNodeId) return false;

        int index = getBucketIndex(node.id);
        if (index < 0 || index >= static_cast<int>(buckets.size())) return false;

        auto& bucket = buckets[index];

        if (bucket->addNode(node)) {
            // Check if bucket needs splitting
            if (bucket->isFull() && index < DHT_B - 1) {
                splitBucket(index);
            }
            return true;
        }

        return false;
    }

    bool RoutingTable::removeNode(const DHTNodeID& id) {
        std::lock_guard<std::recursive_mutex> lock(mutex);

        int index = getBucketIndex(id);
        if (index < 0 || index >= static_cast<int>(buckets.size())) return false;

        return buckets[index]->removeNode(id);
    }

    bool RoutingTable::contains(const DHTNodeID& id) const {
        std::lock_guard<std::recursive_mutex> lock(mutex);

        int index = getBucketIndex(id);
        if (index < 0 || index >= static_cast<int>(buckets.size())) return false;

        return buckets[index]->contains(id);
    }

    DHTNode* RoutingTable::getNode(const DHTNodeID& id) {
        std::lock_guard<std::recursive_mutex> lock(mutex);

        int index = getBucketIndex(id);
        if (index < 0 || index >= static_cast<int>(buckets.size())) return nullptr;

        return buckets[index]->getNode(id);
    }

    std::vector<DHTNode> RoutingTable::getClosestNodes(const DHTNodeID& target, size_t count) const {
        std::lock_guard<std::recursive_mutex> lock(mutex);

        std::vector<std::pair<DHTNodeID, DHTNode>> distances;

        for (const auto& bucket : buckets) {
            auto nodes = bucket->getNodes();
            for (const auto& node : nodes) {
                distances.emplace_back(target.xor(node.id), node);
            }
        }

        std::sort(distances.begin(), distances.end(),
            [](const auto& a, const auto& b) {
                return a.first < b.first;
            });

        std::vector<DHTNode> result;
        size_t n = std::min(count, distances.size());
        for (size_t i = 0; i < n; i++) {
            result.push_back(distances[i].second);
        }

        return result;
    }

    std::vector<DHTNode> RoutingTable::getAllNodes() const {
        std::lock_guard<std::recursive_mutex> lock(mutex);

        std::vector<DHTNode> result;
        for (const auto& bucket : buckets) {
            auto nodes = bucket->getNodes();
            result.insert(result.end(), nodes.begin(), nodes.end());
        }
        return result;
    }

    size_t RoutingTable::getTotalNodes() const {
        std::lock_guard<std::recursive_mutex> lock(mutex);

        size_t total = 0;
        for (const auto& bucket : buckets) {
            total += bucket->size();
        }
        return total;
    }

    void RoutingTable::refresh() {
        std::lock_guard<std::recursive_mutex> lock(mutex);

        for (auto& bucket : buckets) {
            bucket->refresh();
        }
    }

    // ============== DHTValue Implementation ==============

    DHTValue::DHTValue() : timestamp(0), expiryTime(0), version(0) {}

    bool DHTValue::isExpired() const {
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        return now > expiryTime;
    }

    // ============== DHTLookupResult Implementation ==============

    DHTLookupResult::DHTLookupResult() : found(false), responseTime(0) {}

    // ============== DHTConfig Implementation ==============

    DHTConfig::DHTConfig()
        : port(8334), k(DHT_K), alpha(DHT_ALPHA),
          refreshInterval(DHT_REFRESH_INTERVAL),
          replicateInterval(DHT_REPLICATE_INTERVAL),
          republishInterval(DHT_REPUBLISH_INTERVAL),
          expiryTime(DHT_EXPIRY_TIME),
          enableStore(true), enableLookup(true), maxStoreSize(10000) {
        bootstrapNodes = {
            "dht.powercoin.net:8334",
            "dht1.powercoin.net:8334",
            "dht2.powercoin.net:8334"
        };
    }

    // ============== DHTStats Implementation ==============

    DHTStats::DHTStats()
        : totalNodes(0), bucketsCount(0), totalLookups(0),
          successfulLookups(0), totalStores(0), successfulStores(0),
          bytesStored(0), storedValues(0), averageResponseTime(0),
          uptime(0) {}

    // ============== DHT Implementation ==============

    struct DHT::Impl {
        std::unique_ptr<RoutingTable> routingTable;
        std::map<DHTNodeID, DHTValue> storage;
        std::vector<DHTNode> bootstrapNodes;
        DHTStats stats;
        std::atomic<bool> running;
        std::thread maintenanceThread;
        std::chrono::steady_clock::time_point startTime;

        // Callbacks
        std::function<void(const DHTNode&)> onNodeFound;
        std::function<void(const DHTNodeID&, const DHTValue&)> onValueStored;
        std::function<void(const DHTNodeID&, const DHTValue&)> onValueRetrieved;
        std::function<void(const std::string&, const DHTNodeID&)> onError;

        Impl() : running(false) {
            startTime = std::chrono::steady_clock::now();
        }
    };

    DHT::DHT(const DHTConfig& cfg) : config(cfg) {
        impl = std::make_unique<Impl>();
    }

    DHT::~DHT() {
        stop();
    }

    bool DHT::start() {
        if (impl->running) return true;

        auto localId = DHTNodeID::generate();
        impl->routingTable = std::make_unique<RoutingTable>(localId);
        impl->running = true;

        // Start maintenance thread
        impl->maintenanceThread = std::thread([this]() {
            while (impl->running) {
                std::this_thread::sleep_for(std::chrono::seconds(60));

                if (impl->running) {
                    refresh();
                    expire();
                }
            }
        });

        // Bootstrap with known nodes
        bootstrap(config.bootstrapNodes);

        return true;
    }

    void DHT::stop() {
        impl->running = false;
        if (impl->maintenanceThread.joinable()) {
            impl->maintenanceThread.join();
        }
    }

    bool DHT::isRunning() const {
        return impl->running;
    }

    DHTNodeID DHT::getLocalNodeId() const {
        return impl->routingTable->getLocalNodeId();
    }

    void DHT::bootstrap(const std::vector<DHTNode>& nodes) {
        for (const auto& node : nodes) {
            addPeer(node);
            impl->bootstrapNodes.push_back(node);
        }

        // Find closest nodes to our own ID
        auto closest = findNodes(getLocalNodeId(), DHT_K);
        for (const auto& node : closest) {
            addPeer(node);
        }
    }

    void DHT::bootstrap(const std::vector<std::string>& addresses) {
        std::vector<DHTNode> nodes;
        for (const auto& addr : addresses) {
            size_t colon = addr.find(':');
            if (colon != std::string::npos) {
                DHTNode node;
                node.ip = addr.substr(0, colon);
                node.port = std::stoi(addr.substr(colon + 1));
                node.id = DHTNodeID::fromHash(
                    std::vector<uint8_t>(node.ip.begin(), node.ip.end()));
                nodes.push_back(node);
            }
        }
        bootstrap(nodes);
    }

    std::vector<DHTNode> DHT::findNodes(const DHTNodeID& target, size_t count) {
        std::vector<DHTNode> closest = impl->routingTable->getClosestNodes(target, count);
        std::set<DHTNodeID> queried;
        std::vector<DHTNode> result;

        // Parallel queries (simplified)
        for (size_t i = 0; i < std::min(config.alpha, closest.size()); i++) {
            const auto& node = closest[i];
            if (queried.find(node.id) == queried.end()) {
                queried.insert(node.id);
                // In real implementation, would send FIND_NODE RPC
                result.push_back(node);
                impl->stats.totalLookups++;
            }
        }

        impl->stats.successfulLookups += result.size();
        return result;
    }

    DHTLookupResult DHT::findValue(const DHTNodeID& key) {
        DHTLookupResult result;

        // Check local storage first
        if (hasLocalValue(key)) {
            result.found = true;
            result.value = *getLocalValue(key).empty() ? nullptr : &storage[key];
            return result;
        }

        // Find nodes closest to key
        auto nodes = findNodes(key, DHT_K);
        result.closestNodes = nodes;

        // In real implementation, would send FIND_VALUE RPC to nodes
        impl->stats.totalLookups++;

        return result;
    }

    DHTStoreResult DHT::storeValue(const DHTNodeID& key, 
                                     const std::vector<uint8_t>& value,
                                     uint32_t expiry) {
        if (!config.enableStore) {
            return DHTStoreResult::ERROR;
        }

        if (value.empty() || value.size() > 1024 * 1024) { // 1MB max
            return DHTStoreResult::INVALID_VALUE;
        }

        if (impl->storage.size() >= config.maxStoreSize) {
            return DHTStoreResult::NODE_FULL;
        }

        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        DHTValue dhtValue;
        dhtValue.data = value;
        dhtValue.timestamp = now;
        dhtValue.expiryTime = now + expiry;
        dhtValue.version++;
        dhtValue.publisher = getLocalNodeId();

        impl->storage[key] = dhtValue;
        impl->stats.totalStores++;
        impl->stats.successfulStores++;
        impl->stats.bytesStored += value.size();
        impl->stats.storedValues = impl->storage.size();

        if (impl->onValueStored) {
            impl->onValueStored(key, dhtValue);
        }

        return DHTStoreResult::SUCCESS;
    }

    std::vector<uint8_t> DHT::getLocalValue(const DHTNodeID& key) const {
        auto it = impl->storage.find(key);
        if (it != impl->storage.end() && !it->second.isExpired()) {
            return it->second.data;
        }
        return {};
    }

    bool DHT::hasLocalValue(const DHTNodeID& key) const {
        auto it = impl->storage.find(key);
        return it != impl->storage.end() && !it->second.isExpired();
    }

    bool DHT::removeLocalValue(const DHTNodeID& key) {
        auto it = impl->storage.find(key);
        if (it != impl->storage.end()) {
            impl->stats.bytesStored -= it->second.size();
            impl->storage.erase(it);
            impl->stats.storedValues = impl->storage.size();
            return true;
        }
        return false;
    }

    bool DHT::addPeer(const DHTNode& node) {
        if (node.id.isZero()) return false;
        if (node.id == getLocalNodeId()) return false;

        bool added = impl->routingTable->addNode(node);

        if (added && impl->onNodeFound) {
            impl->onNodeFound(node);
        }

        return added;
    }

    bool DHT::addPeer(const std::string& ip, uint16_t port) {
        DHTNode node;
        node.ip = ip;
        node.port = port;
        node.id = DHTNodeID::fromHash(
            std::vector<uint8_t>(ip.begin(), ip.end()));
        return addPeer(node);
    }

    bool DHT::removePeer(const DHTNodeID& nodeId) {
        return impl->routingTable->removeNode(nodeId);
    }

    const RoutingTable& DHT::getRoutingTable() const {
        return *impl->routingTable;
    }

    std::vector<DHTNode> DHT::getAllPeers() const {
        return impl->routingTable->getAllNodes();
    }

    std::vector<DHTNode> DHT::getRandomPeers(size_t count) const {
        auto allNodes = getAllPeers();
        if (allNodes.empty() || count == 0) return {};

        std::vector<DHTNode> result;
        size_t n = std::min(count, allNodes.size());
        auto indices = Random::sample(allNodes.size(), n);

        for (auto idx : indices) {
            result.push_back(allNodes[idx]);
        }

        return result;
    }

    size_t DHT::getPeerCount() const {
        return impl->routingTable->getTotalNodes();
    }

    DHTStats DHT::getStats() const {
        DHTStats stats = impl->stats;
        stats.totalNodes = getPeerCount();
        stats.bucketsCount = impl->routingTable->getBucketCount();
        stats.uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - impl->startTime).count();

        if (stats.totalLookups > 0) {
            stats.averageResponseTime = stats.successfulLookups / 
                                        static_cast<double>(stats.totalLookups);
        }

        return stats;
    }

    void DHT::refresh() {
        // Refresh random buckets
        auto allNodes = getAllPeers();
        if (allNodes.empty()) return;

        size_t refreshCount = std::min(size_t(10), allNodes.size());
        auto randomNodes = getRandomPeers(refreshCount);

        for (const auto& node : randomNodes) {
            findNodes(node.id, DHT_K);
        }

        impl->routingTable->refresh();
    }

    void DHT::replicate() {
        // Replicate values to closest nodes
        for (const auto& [key, value] : impl->storage) {
            auto closest = findNodes(key, DHT_K);
            // In real implementation, would send STORE RPC to closest nodes
        }
    }

    void DHT::republish() {
        // Refresh TTL of stored values
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        for (auto& [key, value] : impl->storage) {
            if (now > value.expiryTime - config.republishInterval) {
                value.expiryTime = now + config.expiryTime;
                value.version++;
            }
        }
    }

    void DHT::expire() {
        // Remove expired values
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        for (auto it = impl->storage.begin(); it != impl->storage.end();) {
            if (it->second.isExpired()) {
                impl->stats.bytesStored -= it->second.size();
                it = impl->storage.erase(it);
            } else {
                ++it;
            }
        }
        impl->stats.storedValues = impl->storage.size();
    }

    std::vector<uint8_t> DHT::handleQuery(const std::vector<uint8_t>& query,
                                           const DHTNode& from) {
        DHTQuery dhtQuery;
        if (!dhtQuery.deserialize(query)) {
            return {};
        }

        DHTResponse response;
        response.type = dhtQuery.type;

        switch (dhtQuery.type) {
            case DHTQueryType::PING:
                response.target = dhtQuery.target;
                break;

            case DHTQueryType::FIND_NODE:
                response.nodes = findNodes(dhtQuery.target, DHT_K);
                break;

            case DHTQueryType::FIND_VALUE:
                {
                    auto result = findValue(dhtQuery.key);
                    if (result.found) {
                        response.found = true;
                        response.value = result.value.data;
                    } else {
                        response.found = false;
                        response.nodes = result.closestNodes;
                    }
                }
                break;

            case DHTQueryType::STORE:
                {
                    auto result = storeValue(dhtQuery.key, dhtQuery.value);
                    if (result == DHTStoreResult::SUCCESS) {
                        response.found = true;
                    } else {
                        response.error = "Store failed";
                    }
                }
                break;

            default:
                response.error = "Unknown query type";
                break;
        }

        return response.serialize();
    }

    bool DHT::saveState(const std::string& filename) const {
        // TODO: Implement state serialization to file
        return false;
    }

    bool DHT::loadState(const std::string& filename) {
        // TODO: Implement state loading from file
        return false;
    }

    void DHT::setOnNodeFound(std::function<void(const DHTNode&)> callback) {
        impl->onNodeFound = callback;
    }

    void DHT::setOnValueStored(std::function<void(const DHTNodeID&, const DHTValue&)> callback) {
        impl->onValueStored = callback;
    }

    void DHT::setOnValueRetrieved(std::function<void(const DHTNodeID&, const DHTValue&)> callback) {
        impl->onValueRetrieved = callback;
    }

    void DHT::setOnError(std::function<void(const std::string&, const DHTNodeID&)> callback) {
        impl->onError = callback;
    }

    // ============== DHTQuery Implementation ==============

    DHTQuery::DHTQuery() : type(DHTQueryType::PING), ttl(0), timestamp(0) {}

    std::vector<uint8_t> DHTQuery::serialize() const {
        std::vector<uint8_t> data;
        data.push_back(static_cast<uint8_t>(type));

        auto targetBytes = target.toBytes();
        data.insert(data.end(), targetBytes.begin(), targetBytes.end());

        auto keyBytes = key.toBytes();
        data.insert(data.end(), keyBytes.begin(), keyBytes.end());

        // Value length
        uint32_t valueLen = value.size();
        for (int i = 0; i < 4; i++) {
            data.push_back((valueLen >> (24 - i * 8)) & 0xFF);
        }
        data.insert(data.end(), value.begin(), value.end());

        // Sender info
        auto senderIdBytes = sender.id.toBytes();
        data.insert(data.end(), senderIdBytes.begin(), senderIdBytes.end());

        uint16_t portBe = htobe16(sender.port);
        data.insert(data.end(), (uint8_t*)&portBe, (uint8_t*)&portBe + 2);
        data.insert(data.end(), sender.ip.begin(), sender.ip.end());
        data.push_back(0); // null terminator

        // TTL and timestamp
        uint32_t ttlBe = htobe32(ttl);
        data.insert(data.end(), (uint8_t*)&ttlBe, (uint8_t*)&ttlBe + 4);

        uint64_t tsBe = htobe64(timestamp);
        data.insert(data.end(), (uint8_t*)&tsBe, (uint8_t*)&tsBe + 8);

        return data;
    }

    bool DHTQuery::deserialize(const std::vector<uint8_t>& data) {
        size_t pos = 0;
        if (pos >= data.size()) return false;

        type = static_cast<DHTQueryType>(data[pos++]);

        // Target
        if (pos + DHT_ID_SIZE > data.size()) return false;
        std::vector<uint8_t> targetBytes(data.begin() + pos, 
                                          data.begin() + pos + DHT_ID_SIZE);
        target = DHTNodeID(targetBytes);
        pos += DHT_ID_SIZE;

        // Key
        if (pos + DHT_ID_SIZE > data.size()) return false;
        std::vector<uint8_t> keyBytes(data.begin() + pos,
                                       data.begin() + pos + DHT_ID_SIZE);
        key = DHTNodeID(keyBytes);
        pos += DHT_ID_SIZE;

        // Value length
        if (pos + 4 > data.size()) return false;
        uint32_t valueLen = (data[pos] << 24) | (data[pos+1] << 16) |
                           (data[pos+2] << 8) | data[pos+3];
        pos += 4;

        // Value
        if (pos + valueLen > data.size()) return false;
        value.assign(data.begin() + pos, data.begin() + pos + valueLen);
        pos += valueLen;

        // Sender ID
        if (pos + DHT_ID_SIZE > data.size()) return false;
        std::vector<uint8_t> senderIdBytes(data.begin() + pos,
                                           data.begin() + pos + DHT_ID_SIZE);
        sender.id = DHTNodeID(senderIdBytes);
        pos += DHT_ID_SIZE;

        // Sender port
        if (pos + 2 > data.size()) return false;
        uint16_t portBe;
        memcpy(&portBe, data.data() + pos, 2);
        sender.port = be16toh(portBe);
        pos += 2;

        // Sender IP (null-terminated string)
        sender.ip.clear();
        while (pos < data.size() && data[pos] != 0) {
            sender.ip += static_cast<char>(data[pos++]);
        }
        pos++; // skip null

        // TTL
        if (pos + 4 > data.size()) return false;
        uint32_t ttlBe;
        memcpy(&ttlBe, data.data() + pos, 4);
        ttl = be32toh(ttlBe);
        pos += 4;

        // Timestamp
        if (pos + 8 > data.size()) return false;
        uint64_t tsBe;
        memcpy(&tsBe, data.data() + pos, 8);
        timestamp = be64toh(tsBe);

        return true;
    }

    // ============== DHTResponse Implementation ==============

    DHTResponse::DHTResponse() : type(DHTQueryType::RESPONSE), found(false) {}

    std::vector<uint8_t> DHTResponse::serialize() const {
        std::vector<uint8_t> data;
        data.push_back(static_cast<uint8_t>(type));

        auto targetBytes = target.toBytes();
        data.insert(data.end(), targetBytes.begin(), targetBytes.end());

        data.push_back(found ? 1 : 0);

        // Nodes
        uint32_t nodeCount = nodes.size();
        for (int i = 0; i < 4; i++) {
            data.push_back((nodeCount >> (24 - i * 8)) & 0xFF);
        }

        for (const auto& node : nodes) {
            auto idBytes = node.id.toBytes();
            data.insert(data.end(), idBytes.begin(), idBytes.end());

            uint16_t portBe = htobe16(node.port);
            data.insert(data.end(), (uint8_t*)&portBe, (uint8_t*)&portBe + 2);
            data.insert(data.end(), node.ip.begin(), node.ip.end());
            data.push_back(0);
        }

        // Value
        uint32_t valueLen = value.size();
        for (int i = 0; i < 4; i++) {
            data.push_back((valueLen >> (24 - i * 8)) & 0xFF);
        }
        data.insert(data.end(), value.begin(), value.end());

        // Error
        data.insert(data.end(), error.begin(), error.end());
        data.push_back(0);

        return data;
    }

    bool DHTResponse::deserialize(const std::vector<uint8_t>& data) {
        size_t pos = 0;
        if (pos >= data.size()) return false;

        type = static_cast<DHTQueryType>(data[pos++]);

        // Target
        if (pos + DHT_ID_SIZE > data.size()) return false;
        std::vector<uint8_t> targetBytes(data.begin() + pos,
                                          data.begin() + pos + DHT_ID_SIZE);
        target = DHTNodeID(targetBytes);
        pos += DHT_ID_SIZE;

        // Found flag
        if (pos >= data.size()) return false;
        found = data[pos++] != 0;

        // Node count
        if (pos + 4 > data.size()) return false;
        uint32_t nodeCount = (data[pos] << 24) | (data[pos+1] << 16) |
                            (data[pos+2] << 8) | data[pos+3];
        pos += 4;

        // Nodes
        nodes.clear();
        for (uint32_t i = 0; i < nodeCount; i++) {
            if (pos + DHT_ID_SIZE > data.size()) return false;
            std::vector<uint8_t> idBytes(data.begin() + pos,
                                          data.begin() + pos + DHT_ID_SIZE);
            DHTNode node;
            node.id = DHTNodeID(idBytes);
            pos += DHT_ID_SIZE;

            if (pos + 2 > data.size()) return false;
            uint16_t portBe;
            memcpy(&portBe, data.data() + pos, 2);
            node.port = be16toh(portBe);
            pos += 2;

            node.ip.clear();
            while (pos < data.size() && data[pos] != 0) {
                node.ip += static_cast<char>(data[pos++]);
            }
            pos++; // skip null

            nodes.push_back(node);
        }

        // Value length
        if (pos + 4 > data.size()) return false;
        uint32_t valueLen = (data[pos] << 24) | (data[pos+1] << 16) |
                           (data[pos+2] << 8) | data[pos+3];
        pos += 4;

        // Value
        if (pos + valueLen > data.size()) return false;
        value.assign(data.begin() + pos, data.begin() + pos + valueLen);
        pos += valueLen;

        // Error
        error.clear();
        while (pos < data.size() && data[pos] != 0) {
            error += static_cast<char>(data[pos++]);
        }

        return true;
    }

} // namespace powercoin