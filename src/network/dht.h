#ifndef POWERCOIN_DHT_H
#define POWERCOIN_DHT_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <functional>
#include <mutex>
#include <random>
#include <chrono>

namespace powercoin {

    /**
     * Kademlia DHT constants
     */
    constexpr size_t DHT_K = 20;              // Bucket size (k)
    constexpr size_t DHT_ALPHA = 3;            // Parallel queries (α)
    constexpr size_t DHT_B = 160;              // Bits in node ID (b)
    constexpr size_t DHT_ID_SIZE = 20;         // Node ID size in bytes (160 bits)
    constexpr size_t DHT_REFRESH_INTERVAL = 3600; // Refresh interval in seconds
    constexpr size_t DHT_REPLICATE_INTERVAL = 3600;
    constexpr size_t DHT_REPUBLISH_INTERVAL = 86400;
    constexpr size_t DHT_EXPIRY_TIME = 86400;

    /**
     * DHT node ID (160-bit)
     */
    class DHTNodeID {
    private:
        std::array<uint8_t, DHT_ID_SIZE> data;

    public:
        DHTNodeID();
        explicit DHTNodeID(const std::vector<uint8_t>& bytes);
        explicit DHTNodeID(const std::string& hex);
        explicit DHTNodeID(uint64_t seed);

        // Comparison operators
        bool operator==(const DHTNodeID& other) const;
        bool operator!=(const DHTNodeID& other) const;
        bool operator<(const DHTNodeID& other) const;

        // Distance calculation (XOR metric)
        DHTNodeID xor(const DHTNodeID& other) const;
        int getCommonPrefixBits(const DHTNodeID& other) const;
        bool isZero() const;

        // Utility
        std::string toString() const;
        std::string toHex() const;
        std::vector<uint8_t> toBytes() const;
        size_t hash() const;

        // Static helpers
        static DHTNodeID generate();
        static DHTNodeID fromString(const std::string& str);
        static DHTNodeID fromHash(const std::vector<uint8_t>& data);

        // Random node ID in bucket range
        DHTNodeID randomInBucket(int bucketIndex) const;
    };

    /**
     * DHT node information
     */
    struct DHTNode {
        DHTNodeID id;
        std::string ip;
        uint16_t port;
        uint64_t lastSeen;
        uint32_t version;
        uint64_t responseTime;
        uint32_t failures;
        bool isHealthy;
        bool isBootstrapped;

        DHTNode();
        std::string toString() const;
        bool isExpired() const;
        void updateSeen();
    };

    /**
     * KBucket - holds k nodes in a specific ID range
     */
    class KBucket {
    private:
        std::list<DHTNode> nodes;
        std::set<DHTNodeID> nodeIds;
        size_t maxSize;
        uint64_t lastRefreshed;
        mutable std::mutex mutex;

    public:
        explicit KBucket(size_t maxSize = DHT_K);

        bool addNode(const DHTNode& node);
        bool removeNode(const DHTNodeID& id);
        bool contains(const DHTNodeID& id) const;
        DHTNode* getNode(const DHTNodeID& id);
        std::vector<DHTNode> getNodes(size_t count = 0) const;
        std::vector<DHTNode> getRandomNodes(size_t count) const;
        
        size_t size() const;
        bool isFull() const;
        void refresh();
        uint64_t getLastRefreshed() const { return lastRefreshed; }

        void split(KBucket& left, KBucket& right, int bitIndex) const;
        std::vector<DHTNode> getClosestNodes(const DHTNodeID& target, size_t count) const;
    };

    /**
     * DHT routing table
     */
    class RoutingTable {
    private:
        DHTNodeID localNodeId;
        std::vector<std::unique_ptr<KBucket>> buckets;
        mutable std::recursive_mutex mutex;

        int getBucketIndex(const DHTNodeID& id) const;
        void splitBucket(int index);

    public:
        explicit RoutingTable(const DHTNodeID& nodeId);
        ~RoutingTable();

        bool addNode(const DHTNode& node);
        bool removeNode(const DHTNodeID& id);
        bool contains(const DHTNodeID& id) const;
        DHTNode* getNode(const DHTNodeID& id);
        
        std::vector<DHTNode> getClosestNodes(const DHTNodeID& target, size_t count = DHT_K) const;
        std::vector<DHTNode> getAllNodes() const;
        size_t getTotalNodes() const;
        size_t getBucketCount() const { return buckets.size(); }

        void refresh();
        const DHTNodeID& getLocalNodeId() const { return localNodeId; }
    };

    /**
     * DHT value storage
     */
    struct DHTValue {
        std::vector<uint8_t> data;
        uint64_t timestamp;
        uint64_t expiryTime;
        uint32_t version;
        DHTNodeID publisher;

        DHTValue();
        bool isExpired() const;
        size_t size() const { return data.size(); }
    };

    /**
     * DHT store operation result
     */
    enum class DHTStoreResult {
        SUCCESS,
        ALREADY_EXISTS,
        INVALID_VALUE,
        NODE_FULL,
        EXPIRED,
        ERROR
    };

    /**
     * DHT lookup operation result
     */
    struct DHTLookupResult {
        bool found;
        DHTValue value;
        std::vector<DHTNode> closestNodes;
        uint64_t responseTime;

        DHTLookupResult();
    };

    /**
     * DHT configuration
     */
    struct DHTConfig {
        uint16_t port;
        size_t k;
        size_t alpha;
        uint32_t refreshInterval;
        uint32_t replicateInterval;
        uint32_t republishInterval;
        uint32_t expiryTime;
        std::vector<std::string> bootstrapNodes;
        bool enableStore;
        bool enableLookup;
        size_t maxStoreSize;

        DHTConfig();
    };

    /**
     * DHT statistics
     */
    struct DHTStats {
        size_t totalNodes;
        size_t bucketsCount;
        uint64_t totalLookups;
        uint64_t successfulLookups;
        uint64_t totalStores;
        uint64_t successfulStores;
        uint64_t bytesStored;
        size_t storedValues;
        double averageResponseTime;
        uint64_t uptime;

        DHTStats();
    };

    /**
     * Main DHT (Distributed Hash Table) class
     * Kademlia-based peer discovery and storage
     */
    class DHT {
    private:
        struct Impl;
        std::unique_ptr<Impl> impl;

    public:
        /**
         * Constructor
         * @param config DHT configuration
         */
        explicit DHT(const DHTConfig& config = DHTConfig());

        /**
         * Destructor
         */
        ~DHT();

        // Disable copy
        DHT(const DHT&) = delete;
        DHT& operator=(const DHT&) = delete;

        /**
         * Start the DHT node
         * @return true if successful
         */
        bool start();

        /**
         * Stop the DHT node
         */
        void stop();

        /**
         * Check if DHT is running
         * @return true if running
         */
        bool isRunning() const;

        /**
         * Get local node ID
         * @return Node ID
         */
        DHTNodeID getLocalNodeId() const;

        /**
         * Bootstrap the DHT with known nodes
         * @param nodes Bootstrap nodes
         */
        void bootstrap(const std::vector<DHTNode>& nodes);

        /**
         * Bootstrap with addresses (ip:port)
         * @param addresses Vector of addresses
         */
        void bootstrap(const std::vector<std::string>& addresses);

        /**
         * Find nodes closest to target ID
         * @param target Target node ID
         * @param count Number of nodes to find (k)
         * @return Vector of closest nodes
         */
        std::vector<DHTNode> findNodes(const DHTNodeID& target, size_t count = DHT_K);

        /**
         * Find value for key
         * @param key Key to look up
         * @return Lookup result
         */
        DHTLookupResult findValue(const DHTNodeID& key);

        /**
         * Store value at key
         * @param key Storage key
         * @param value Value to store
         * @param expiry Expiry time in seconds
         * @return Store result
         */
        DHTStoreResult storeValue(const DHTNodeID& key, 
                                   const std::vector<uint8_t>& value,
                                   uint32_t expiry = DHT_EXPIRY_TIME);

        /**
         * Get value for key from local storage
         * @param key Key to look up
         * @return Value if found, empty vector otherwise
         */
        std::vector<uint8_t> getLocalValue(const DHTNodeID& key) const;

        /**
         * Check if key exists in local storage
         * @param key Key to check
         * @return true if exists
         */
        bool hasLocalValue(const DHTNodeID& key) const;

        /**
         * Remove value from local storage
         * @param key Key to remove
         * @return true if removed
         */
        bool removeLocalValue(const DHTNodeID& key);

        /**
         * Add peer to routing table
         * @param node Peer node
         * @return true if added
         */
        bool addPeer(const DHTNode& node);

        /**
         * Add peer by address
         * @param ip IP address
         * @param port Port number
         * @return true if added
         */
        bool addPeer(const std::string& ip, uint16_t port);

        /**
         * Remove peer from routing table
         * @param nodeId Peer node ID
         * @return true if removed
         */
        bool removePeer(const DHTNodeID& nodeId);

        /**
         * Get routing table
         * @return Const reference to routing table
         */
        const RoutingTable& getRoutingTable() const;

        /**
         * Get all known peers
         * @return Vector of peer nodes
         */
        std::vector<DHTNode> getAllPeers() const;

        /**
         * Get random peers
         * @param count Number of peers
         * @return Vector of random peers
         */
        std::vector<DHTNode> getRandomPeers(size_t count) const;

        /**
         * Get peer count
         * @return Number of peers in routing table
         */
        size_t getPeerCount() const;

        /**
         * Get statistics
         * @return DHT statistics
         */
        DHTStats getStats() const;

        /**
         * Refresh routing table
         */
        void refresh();

        /**
         * Replicate values to closest nodes
         */
        void replicate();

        /**
         * Republish values (refresh TTL)
         */
        void republish();

        /**
         * Expire old values
         */
        void expire();

        /**
         * Handle incoming DHT query
         * @param query Query data
         * @param from Source node
         * @return Response data
         */
        std::vector<uint8_t> handleQuery(const std::vector<uint8_t>& query,
                                          const DHTNode& from);

        /**
         * Save DHT state to file
         * @param filename File name
         * @return true if successful
         */
        bool saveState(const std::string& filename) const;

        /**
         * Load DHT state from file
         * @param filename File name
         * @return true if successful
         */
        bool loadState(const std::string& filename);

        // Callbacks
        void setOnNodeFound(std::function<void(const DHTNode&)> callback);
        void setOnValueStored(std::function<void(const DHTNodeID&, const DHTValue&)> callback);
        void setOnValueRetrieved(std::function<void(const DHTNodeID&, const DHTValue&)> callback);
        void setOnError(std::function<void(const std::string&, const DHTNodeID&)> callback);

    private:
        DHTConfig config;
        mutable std::mutex mutex;
    };

    /**
     * DHT query types
     */
    enum class DHTQueryType : uint8_t {
        PING = 0,
        STORE = 1,
        FIND_NODE = 2,
        FIND_VALUE = 3,
        RESPONSE = 4,
        ERROR = 5
    };

    /**
     * DHT query message
     */
    struct DHTQuery {
        DHTQueryType type;
        DHTNodeID target;
        DHTNodeID key;
        std::vector<uint8_t> value;
        DHTNode sender;
        uint32_t ttl;
        uint64_t timestamp;

        DHTQuery();
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data);
    };

    /**
     * DHT response message
     */
    struct DHTResponse {
        DHTQueryType type;
        DHTNodeID target;
        std::vector<DHTNode> nodes;
        std::vector<uint8_t> value;
        bool found;
        std::string error;

        DHTResponse();
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data);
    };

} // namespace powercoin

#endif // POWERCOIN_DHT_H