#ifndef POWERCOIN_P2P_H
#define POWERCOIN_P2P_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <thread>
#include <atomic>
#include <functional>
#include <mutex>
#include <chrono>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace powercoin {

    /**
     * P2P protocol version
     */
    constexpr uint32_t P2P_PROTOCOL_VERSION = 70015;
    constexpr uint32_t P2P_MIN_PROTOCOL_VERSION = 70001;
    constexpr uint32_t P2P_NO_TIMESTAMP_VERSION = 70002;

    /**
     * P2P message types
     */
    enum class MessageType : uint32_t {
        VERSION = 0,        // Protocol version
        VERACK = 1,         // Version acknowledgment
        ADDR = 2,           // Addresses
        INV = 3,            // Inventory
        GETDATA = 4,        // Get inventory data
        NOTFOUND = 5,       // Not found
        GETBLOCKS = 6,      // Get blocks
        GETHEADERS = 7,     // Get headers
        TX = 8,             // Transaction
        BLOCK = 9,          // Block
        HEADERS = 10,       // Headers
        SENDHEADERS = 11,   // Send headers
        GETADDR = 12,       // Get addresses
        MEMPOOL = 13,       // Mempool
        PING = 14,          // Ping
        PONG = 15,          // Pong
        FILTERLOAD = 16,    // Bloom filter load
        FILTERADD = 17,     // Bloom filter add
        FILTERCLEAR = 18,   // Bloom filter clear
        MERKLEBLOCK = 19,   // Merkle block
        ALERT = 20,         // Alert
        REJECT = 21,        // Reject
        SENDCMPCT = 22,     // Send compact blocks
        CMPCTBLOCK = 23,    // Compact block
        GETBLOCKTXN = 24,   // Get block transactions
        BLOCKTXN = 25,      // Block transactions
        FEEFILTER = 26,     // Fee filter
        
        // Power Coin specific
        GETPEERS = 100,      // Get peer list
        PEERS = 101,         // Peer list response
        GETSTATS = 102,      // Get node statistics
        STATS = 103,         // Statistics response
        SYNC = 104,          // Sync request
        SYNCCOMPLETE = 105   // Sync complete
    };

    /**
     * Peer connection state
     */
    enum class PeerState {
        DISCONNECTED,
        CONNECTING,
        HANDSHAKE,
        CONNECTED,
        SYNCING,
        SYNCED,
        BANNED
    };

    /**
     * Peer information
     */
    struct PeerInfo {
        std::string id;
        std::string ip;
        uint16_t port;
        uint32_t version;
        uint64_t services;
        uint64_t height;
        std::string userAgent;
        uint64_t lastSeen;
        uint64_t lastPing;
        uint64_t pingTime;
        PeerState state;
        uint64_t bytesSent;
        uint64_t bytesReceived;
        uint32_t messagesSent;
        uint32_t messagesReceived;
        uint32_t failedConnections;
        uint64_t connectionTime;
        bool isOutbound;
        bool isWhitelisted;

        PeerInfo();
        std::string toString() const;
    };

    /**
     * Network address
     */
    struct NetworkAddress {
        uint32_t time;
        uint64_t services;
        uint8_t ip[16];  // IPv6
        uint16_t port;

        NetworkAddress();
        std::string getIP() const;
        void setIP(const std::string& ip);
        bool isIPv4() const;
        std::string toString() const;
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data, size_t& pos);
    };

    /**
     * Inventory type
     */
    enum class InventoryType : uint32_t {
        ERROR = 0,
        MSG_TX = 1,
        MSG_BLOCK = 2,
        MSG_FILTERED_BLOCK = 3,
        MSG_CMPCT_BLOCK = 4,
        MSG_WITNESS_TX = 5,
        MSG_WITNESS_BLOCK = 6
    };

    /**
     * Inventory vector
     */
    struct Inventory {
        InventoryType type;
        std::string hash;

        Inventory();
        Inventory(InventoryType t, const std::string& h);
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data, size_t& pos);
        bool operator<(const Inventory& other) const;
    };

    /**
     * P2P message header
     */
    struct MessageHeader {
        uint32_t magic;
        std::string command;
        uint32_t length;
        uint32_t checksum;

        MessageHeader();
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data, size_t& pos);
        bool validateChecksum(const std::vector<uint8_t>& payload) const;
        static uint32_t calculateChecksum(const std::vector<uint8_t>& payload);
    };

    /**
     * P2P message
     */
    struct Message {
        MessageHeader header;
        std::vector<uint8_t> payload;

        Message();
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data);
    };

    /**
     * Version message
     */
    struct VersionMessage {
        uint32_t version;
        uint64_t services;
        int64_t timestamp;
        NetworkAddress addrRecv;
        NetworkAddress addrFrom;
        uint64_t nonce;
        std::string userAgent;
        uint32_t startHeight;
        bool relay;

        VersionMessage();
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data, size_t& pos);
    };

    /**
     * Address message
     */
    struct AddrMessage {
        std::vector<NetworkAddress> addresses;

        AddrMessage();
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data, size_t& pos);
    };

    /**
     * Inventory message
     */
    struct InvMessage {
        std::vector<Inventory> inventories;

        InvMessage();
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data, size_t& pos);
    };

    /**
     * GetData message
     */
    struct GetDataMessage {
        std::vector<Inventory> inventories;

        GetDataMessage();
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data, size_t& pos);
    };

    /**
     * P2P network configuration
     */
    struct P2PConfig {
        uint16_t port;
        uint32_t maxPeers;
        uint32_t minPeers;
        uint32_t connectTimeout;
        uint32_t handshakeTimeout;
        uint32_t pingInterval;
        uint32_t banTime;
        uint32_t maxFailures;
        bool allowLocalhost;
        bool allowLan;
        std::vector<std::string> bootstrapNodes;
        std::vector<std::string> whitelist;
        std::vector<std::string> blacklist;
        std::string userAgent;
        uint32_t protocolVersion;
        uint64_t services;

        P2PConfig();
    };

    /**
     * P2P network statistics
     */
    struct P2PStats {
        uint64_t bytesSent;
        uint64_t bytesReceived;
        uint32_t messagesSent;
        uint32_t messagesReceived;
        uint32_t peersConnected;
        uint32_t peersDisconnected;
        uint32_t peersBanned;
        uint32_t failedConnections;
        uint64_t uptime;
        uint64_t bandwidthIn;
        uint64_t bandwidthOut;

        P2PStats();
    };

    /**
     * Main P2P network class
     */
    class P2PNetwork {
    private:
        struct Impl;
        std::unique_ptr<Impl> impl;

        // Thread-safe methods
        void addPeer(const std::shared_ptr<class Peer>& peer);
        void removePeer(const std::string& peerId);
        std::shared_ptr<class Peer> getPeer(const std::string& peerId);

    public:
        /**
         * Constructor
         * @param config P2P configuration
         */
        explicit P2PNetwork(const P2PConfig& config = P2PConfig());

        /**
         * Destructor
         */
        ~P2PNetwork();

        // Disable copy
        P2PNetwork(const P2PNetwork&) = delete;
        P2PNetwork& operator=(const P2PNetwork&) = delete;

        /**
         * Start the P2P network
         * @return true if successful
         */
        bool start();

        /**
         * Stop the P2P network
         */
        void stop();

        /**
         * Check if network is running
         * @return true if running
         */
        bool isRunning() const;

        /**
         * Connect to a peer
         * @param ip IP address
         * @param port Port number
         * @return true if connection initiated
         */
        bool connectToPeer(const std::string& ip, uint16_t port);

        /**
         * Disconnect from a peer
         * @param peerId Peer ID
         * @return true if disconnected
         */
        bool disconnectPeer(const std::string& peerId);

        /**
         * Ban a peer
         * @param peerId Peer ID
         * @param reason Ban reason
         */
        void banPeer(const std::string& peerId, const std::string& reason);

        /**
         * Unban a peer
         * @param peerId Peer ID
         */
        void unbanPeer(const std::string& peerId);

        /**
         * Get peer information
         * @param peerId Peer ID
         * @return Peer info or nullptr if not found
         */
        std::shared_ptr<PeerInfo> getPeerInfo(const std::string& peerId) const;

        /**
         * Get all peer information
         * @return Vector of peer info
         */
        std::vector<PeerInfo> getAllPeerInfo() const;

        /**
         * Get connected peer count
         * @return Number of connected peers
         */
        size_t getConnectedCount() const;

        /**
         * Get total peer count (including disconnected)
         * @return Total peer count
         */
        size_t getTotalPeerCount() const;

        /**
         * Broadcast a block to all peers
         * @param block Block data
         * @param excludePeer Peer to exclude (optional)
         */
        void broadcastBlock(const std::vector<uint8_t>& block, 
                           const std::string& excludePeer = "");

        /**
         * Broadcast a transaction to all peers
         * @param transaction Transaction data
         * @param excludePeer Peer to exclude (optional)
         */
        void broadcastTransaction(const std::vector<uint8_t>& transaction,
                                  const std::string& excludePeer = "");

        /**
         * Broadcast inventory to all peers
         * @param inv Inventory vector
         * @param excludePeer Peer to exclude (optional)
         */
        void broadcastInventory(const std::vector<Inventory>& inv,
                                const std::string& excludePeer = "");

        /**
         * Send message to specific peer
         * @param peerId Peer ID
         * @param message Message to send
         * @return true if sent successfully
         */
        bool sendMessage(const std::string& peerId, const Message& message);

        /**
         * Request blocks from peers
         * @param blockHashes Vector of block hashes
         */
        void requestBlocks(const std::vector<std::string>& blockHashes);

        /**
         * Request transactions from peers
         * @param txHashes Vector of transaction hashes
         */
        void requestTransactions(const std::vector<std::string>& txHashes);

        /**
         * Request headers from peers
         * @param startHash Starting block hash
         * @param stopHash Stopping block hash (optional)
         */
        void requestHeaders(const std::string& startHash,
                           const std::string& stopHash = "");

        /**
         * Send ping to a peer
         * @param peerId Peer ID
         */
        void sendPing(const std::string& peerId);

        /**
         * Get network statistics
         * @return P2P statistics
         */
        P2PStats getStats() const;

        /**
         * Get local address
         * @return Local IP address
         */
        std::string getLocalAddress() const;

        /**
         * Get local port
         * @return Local port
         */
        uint16_t getLocalPort() const { return config.port; }

        /**
         * Get node ID
         * @return Node ID
         */
        std::string getNodeId() const;

        /**
         * Get node services
         * @return Services bitfield
         */
        uint64_t getServices() const { return config.services; }

        /**
         * Get best height from peers
         * @return Best known height
         */
        uint32_t getBestHeight() const;

        /**
         * Get peer with best height
         * @return Peer ID of best peer
         */
        std::string getBestPeer() const;

        /**
         * Discover peers from network
         */
        void discoverPeers();

        /**
         * Add bootstrap nodes
         * @param nodes Vector of node addresses (ip:port)
         */
        void addBootstrapNodes(const std::vector<std::string>& nodes);

        /**
         * Get bootstrap nodes
         * @return Vector of bootstrap node addresses
         */
        std::vector<std::string> getBootstrapNodes() const;

        /**
         * Save peer list to file
         * @param filename File name
         * @return true if successful
         */
        bool savePeerList(const std::string& filename) const;

        /**
         * Load peer list from file
         * @param filename File name
         * @return true if successful
         */
        bool loadPeerList(const std::string& filename);

        /**
         * Clear peer list
         */
        void clearPeerList();

        /**
         * Check if IP is banned
         * @param ip IP address
         * @return true if banned
         */
        bool isBanned(const std::string& ip) const;

        /**
         * Check if IP is whitelisted
         * @param ip IP address
         * @return true if whitelisted
         */
        bool isWhitelisted(const std::string& ip) const;

        /**
         * Set ban list
         * @param bans Vector of banned IPs
         */
        void setBanList(const std::vector<std::string>& bans);

        /**
         * Get ban list
         * @return Vector of banned IPs
         */
        std::vector<std::string> getBanList() const;

        // Callbacks
        void setOnPeerConnected(std::function<void(const PeerInfo&)> callback);
        void setOnPeerDisconnected(std::function<void(const PeerInfo&, const std::string&)> callback);
        void setOnBlockReceived(std::function<void(const std::vector<uint8_t>&, const std::string&)> callback);
        void setOnTransactionReceived(std::function<void(const std::vector<uint8_t>&, const std::string&)> callback);
        void setOnInventoryReceived(std::function<void(const std::vector<Inventory>&, const std::string&)> callback);
        void setOnHeadersReceived(std::function<void(const std::vector<std::string>&, const std::string&)> callback);
        void setOnPingReceived(std::function<void(uint64_t, const std::string&)> callback);
        void setOnPongReceived(std::function<void(uint64_t, const std::string&)> callback);
        void setOnError(std::function<void(const std::string&, const std::string&)> callback);

    private:
        P2PConfig config;
        mutable std::mutex mutex;
    };

    /**
     * Peer connection handler
     */
    class Peer {
    private:
        std::string id;
        std::string ip;
        uint16_t port;
        int socket;
        PeerState state;
        PeerInfo info;
        std::thread recvThread;
        std::thread sendThread;
        std::atomic<bool> running;
        std::vector<uint8_t> recvBuffer;
        std::vector<uint8_t> sendBuffer;
        std::mutex sendMutex;
        std::chrono::steady_clock::time_point lastPing;
        std::chrono::steady_clock::time_point lastPong;
        uint64_t pingNonce;

    public:
        Peer(const std::string& peerIp, uint16_t peerPort, bool outbound = true);
        ~Peer();

        bool connect();
        void disconnect();
        bool isConnected() const;
        bool sendMessage(const Message& message);
        void processMessages(std::function<void(const Message&)> messageHandler);
        void updateState(PeerState newState);
        
        const std::string& getId() const { return id; }
        const std::string& getIp() const { return ip; }
        uint16_t getPort() const { return port; }
        PeerState getState() const { return state; }
        const PeerInfo& getInfo() const { return info; }
        void setVersion(uint32_t version) { info.version = version; }
        void setHeight(uint64_t height) { info.height = height; }
        void setUserAgent(const std::string& ua) { info.userAgent = ua; }
        void updateLastSeen() { info.lastSeen = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count(); }
        
        uint64_t getPingTime() const;
        void startPing();
        void handlePong(uint64_t nonce);
    };

} // namespace powercoin

#endif // POWERCOIN_P2P_H