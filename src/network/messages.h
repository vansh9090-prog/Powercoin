#ifndef POWERCOIN_MESSAGES_H
#define POWERCOIN_MESSAGES_H

#include <string>
#include <vector>
#include <cstdint>
#include <map>
#include <set>
#include <memory>
#include "../crypto/sha256.h"

namespace powercoin {

    /**
     * Network message magic bytes for different networks
     */
    constexpr uint32_t MAGIC_MAINNET = 0xD9B4BEF9;
    constexpr uint32_t MAGIC_TESTNET = 0xDAB5BFFA;
    constexpr uint32_t MAGIC_REGTEST = 0xDAB5BFFC;
    constexpr uint32_t MAGIC_POWERCOIN = 0x5057524F; // "PWRO"

    /**
     * Service flags
     */
    constexpr uint64_t SERVICE_NODE_NETWORK = 1;
    constexpr uint64_t SERVICE_NODE_BLOOM = 2;
    constexpr uint64_t SERVICE_NODE_WITNESS = 4;
    constexpr uint64_t SERVICE_NODE_COMPACT_FILTERS = 8;
    constexpr uint64_t SERVICE_NODE_NETWORK_LIMITED = 1024;

    /**
     * Message command strings
     */
    constexpr const char* MSG_VERSION = "version";
    constexpr const char* MSG_VERACK = "verack";
    constexpr const char* MSG_ADDR = "addr";
    constexpr const char* MSG_INV = "inv";
    constexpr const char* MSG_GETDATA = "getdata";
    constexpr const char* MSG_NOTFOUND = "notfound";
    constexpr const char* MSG_GETBLOCKS = "getblocks";
    constexpr const char* MSG_GETHEADERS = "getheaders";
    constexpr const char* MSG_TX = "tx";
    constexpr const char* MSG_BLOCK = "block";
    constexpr const char* MSG_HEADERS = "headers";
    constexpr const char* MSG_SENDHEADERS = "sendheaders";
    constexpr const char* MSG_GETADDR = "getaddr";
    constexpr const char* MSG_MEMPOOL = "mempool";
    constexpr const char* MSG_PING = "ping";
    constexpr const char* MSG_PONG = "pong";
    constexpr const char* MSG_FILTERLOAD = "filterload";
    constexpr const char* MSG_FILTERADD = "filteradd";
    constexpr const char* MSG_FILTERCLEAR = "filterclear";
    constexpr const char* MSG_MERKLEBLOCK = "merkleblock";
    constexpr const char* MSG_ALERT = "alert";
    constexpr const char* MSG_REJECT = "reject";
    constexpr const char* MSG_SENDCMPCT = "sendcmpct";
    constexpr const char* MSG_CMPCTBLOCK = "cmpctblock";
    constexpr const char* MSG_GETBLOCKTXN = "getblocktxn";
    constexpr const char* MSG_BLOCKTXN = "blocktxn";
    constexpr const char* MSG_FEEFILTER = "feefilter";

    /**
     * Reject codes
     */
    enum class RejectCode : uint8_t {
        REJECT_MALFORMED = 0x01,
        REJECT_INVALID = 0x10,
        REJECT_OBSOLETE = 0x11,
        REJECT_DUPLICATE = 0x12,
        REJECT_NONSTANDARD = 0x40,
        REJECT_DUST = 0x41,
        REJECT_INSUFFICIENTFEE = 0x42,
        REJECT_CHECKPOINT = 0x43
    };

    /**
     * Base class for all network messages
     */
    class NetworkMessage {
    protected:
        uint32_t magic;
        std::string command;
        uint32_t checksum;

    public:
        NetworkMessage();
        virtual ~NetworkMessage() = default;

        virtual std::vector<uint8_t> serialize() const = 0;
        virtual bool deserialize(const std::vector<uint8_t>& data) = 0;

        uint32_t getMagic() const { return magic; }
        void setMagic(uint32_t m) { magic = m; }
        
        const std::string& getCommand() const { return command; }
        void setCommand(const std::string& cmd) { command = cmd; }
        
        uint32_t getChecksum() const { return checksum; }
        void setChecksum(uint32_t cs) { checksum = cs; }

        virtual uint32_t calculateChecksum(const std::vector<uint8_t>& payload) const;
        virtual size_t getSize() const = 0;
        virtual std::string toString() const;
    };

    /**
     * Version message
     * First message sent when connecting to a peer
     */
    class VersionMessage : public NetworkMessage {
    public:
        int32_t version;
        uint64_t services;
        int64_t timestamp;
        uint64_t addrRecvServices;
        std::string addrRecvIp;
        uint16_t addrRecvPort;
        uint64_t addrFromServices;
        std::string addrFromIp;
        uint16_t addrFromPort;
        uint64_t nonce;
        std::string userAgent;
        int32_t startHeight;
        bool relay;

        VersionMessage();
        virtual ~VersionMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;

        bool isInitial() const { return timestamp == 0; }
        bool supportsWitness() const { return version >= 70012; }
    };

    /**
     * Verack message
     * Acknowledgment of version message
     */
    class VerackMessage : public NetworkMessage {
    public:
        VerackMessage();
        virtual ~VerackMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * Network address structure
     */
    struct NetworkAddress {
        uint32_t time;
        uint64_t services;
        std::string ip;
        uint16_t port;

        NetworkAddress();
        bool operator==(const NetworkAddress& other) const;
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data, size_t& pos);
        std::string toString() const;
        bool isIPv4() const;
        bool isValid() const;
    };

    /**
     * Addr message
     * Contains network addresses of other nodes
     */
    class AddrMessage : public NetworkMessage {
    public:
        std::vector<NetworkAddress> addresses;

        AddrMessage();
        virtual ~AddrMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;

        void addAddress(const NetworkAddress& addr);
        void clear();
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
    struct InventoryVector {
        InventoryType type;
        std::string hash; // 32-byte hash in hex

        InventoryVector();
        InventoryVector(InventoryType t, const std::string& h);
        
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data, size_t& pos);
        std::string toString() const;
        bool operator<(const InventoryVector& other) const;
        bool operator==(const InventoryVector& other) const;
        
        static std::string generateHash();
    };

    /**
     * Inv message
     * Announces known inventories
     */
    class InvMessage : public NetworkMessage {
    public:
        std::vector<InventoryVector> inventories;

        InvMessage();
        virtual ~InvMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;

        void addInventory(const InventoryVector& inv);
        void addTransaction(const std::string& txHash);
        void addBlock(const std::string& blockHash);
        bool contains(const InventoryVector& inv) const;
        size_t count() const { return inventories.size(); }
    };

    /**
     * GetData message
     * Requests specific inventories
     */
    class GetDataMessage : public NetworkMessage {
    public:
        std::vector<InventoryVector> inventories;

        GetDataMessage();
        virtual ~GetDataMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;

        void addInventory(const InventoryVector& inv);
        void addTransaction(const std::string& txHash);
        void addBlock(const std::string& blockHash);
    };

    /**
     * NotFound message
     * Response when requested inventory not found
     */
    class NotFoundMessage : public NetworkMessage {
    public:
        std::vector<InventoryVector> inventories;

        NotFoundMessage();
        virtual ~NotFoundMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * GetBlocks message
     * Requests block inventory starting from locator
     */
    class GetBlocksMessage : public NetworkMessage {
    public:
        uint32_t version;
        std::vector<std::string> blockLocatorHashes;
        std::string hashStop;

        GetBlocksMessage();
        virtual ~GetBlocksMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * GetHeaders message
     * Requests block headers starting from locator
     */
    class GetHeadersMessage : public NetworkMessage {
    public:
        uint32_t version;
        std::vector<std::string> blockLocatorHashes;
        std::string hashStop;

        GetHeadersMessage();
        virtual ~GetHeadersMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * Headers message
     * Contains block headers
     */
    class HeadersMessage : public NetworkMessage {
    public:
        struct BlockHeader {
            uint32_t version;
            std::string previousBlockHash;
            std::string merkleRoot;
            uint32_t timestamp;
            uint32_t bits;
            uint32_t nonce;
            uint32_t txCount;

            std::vector<uint8_t> serialize() const;
            bool deserialize(const std::vector<uint8_t>& data, size_t& pos);
        };

        std::vector<BlockHeader> headers;

        HeadersMessage();
        virtual ~HeadersMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * SendHeaders message
     * Tells peer to send headers instead of inv
     */
    class SendHeadersMessage : public NetworkMessage {
    public:
        SendHeadersMessage();
        virtual ~SendHeadersMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * GetAddr message
     * Requests addresses from peer
     */
    class GetAddrMessage : public NetworkMessage {
    public:
        GetAddrMessage();
        virtual ~GetAddrMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * Mempool message
     * Requests mempool transactions
     */
    class MempoolMessage : public NetworkMessage {
    public:
        MempoolMessage();
        virtual ~MempoolMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * Ping message
     * Checks if peer is alive
     */
    class PingMessage : public NetworkMessage {
    public:
        uint64_t nonce;

        PingMessage();
        explicit PingMessage(uint64_t n);
        virtual ~PingMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * Pong message
     * Response to ping
     */
    class PongMessage : public NetworkMessage {
    public:
        uint64_t nonce;

        PongMessage();
        explicit PongMessage(uint64_t n);
        virtual ~PongMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * Reject message
     * Indicates rejected message
     */
    class RejectMessage : public NetworkMessage {
    public:
        std::string message;  // Command of rejected message
        RejectCode code;
        std::string reason;
        std::string data;     // Optional extra data (e.g., txid)

        RejectMessage();
        virtual ~RejectMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;

        static std::string codeToString(RejectCode code);
    };

    /**
     * FeeFilter message
     * Sets minimum fee rate for relaying transactions
     */
    class FeeFilterMessage : public NetworkMessage {
    public:
        uint64_t feerate; // Fee rate in satoshis per kilobyte

        FeeFilterMessage();
        explicit FeeFilterMessage(uint64_t rate);
        virtual ~FeeFilterMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * Alert message (deprecated but kept for compatibility)
     */
    class AlertMessage : public NetworkMessage {
    public:
        std::vector<uint8_t> payload;
        std::vector<uint8_t> signature;

        AlertMessage();
        virtual ~AlertMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;

        bool verifySignature() const;
    };

    /**
     * FilterLoad message
     * Loads a bloom filter
     */
    class FilterLoadMessage : public NetworkMessage {
    public:
        std::vector<uint8_t> filter;
        uint32_t hashFuncs;
        uint32_t tweak;
        uint8_t flags;

        FilterLoadMessage();
        virtual ~FilterLoadMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * FilterAdd message
     * Adds data to bloom filter
     */
    class FilterAddMessage : public NetworkMessage {
    public:
        std::vector<uint8_t> data;

        FilterAddMessage();
        explicit FilterAddMessage(const std::vector<uint8_t>& d);
        virtual ~FilterAddMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * FilterClear message
     * Clears bloom filter
     */
    class FilterClearMessage : public NetworkMessage {
    public:
        FilterClearMessage();
        virtual ~FilterClearMessage() = default;

        virtual std::vector<uint8_t> serialize() const override;
        virtual bool deserialize(const std::vector<uint8_t>& data) override;
        virtual size_t getSize() const override;
        virtual std::string toString() const override;
    };

    /**
     * Message factory for creating messages from raw data
     */
    class MessageFactory {
    public:
        /**
         * Create message from raw data
         * @param data Raw message data
         * @return Unique pointer to created message, nullptr if invalid
         */
        static std::unique_ptr<NetworkMessage> createMessage(const std::vector<uint8_t>& data);

        /**
         * Get message command from raw data
         * @param data Raw message data
         * @return Command string, empty if invalid
         */
        static std::string getCommand(const std::vector<uint8_t>& data);

        /**
         * Validate message checksum
         * @param data Raw message data
         * @return true if checksum is valid
         */
        static bool validateChecksum(const std::vector<uint8_t>& data);
    };

    /**
     * Message builder for creating messages
     */
    class MessageBuilder {
    private:
        uint32_t magic;

    public:
        explicit MessageBuilder(uint32_t networkMagic = MAGIC_POWERCOIN);

        std::vector<uint8_t> buildVersion(const VersionMessage& msg);
        std::vector<uint8_t> buildVerack();
        std::vector<uint8_t> buildAddr(const std::vector<NetworkAddress>& addrs);
        std::vector<uint8_t> buildInv(const std::vector<InventoryVector>& invs);
        std::vector<uint8_t> buildGetData(const std::vector<InventoryVector>& invs);
        std::vector<uint8_t> buildNotFound(const std::vector<InventoryVector>& invs);
        std::vector<uint8_t> buildGetBlocks(const std::vector<std::string>& locator, 
                                            const std::string& hashStop);
        std::vector<uint8_t> buildGetHeaders(const std::vector<std::string>& locator,
                                             const std::string& hashStop);
        std::vector<uint8_t> buildHeaders(const std::vector<HeadersMessage::BlockHeader>& headers);
        std::vector<uint8_t> buildSendHeaders();
        std::vector<uint8_t> buildGetAddr();
        std::vector<uint8_t> buildMempool();
        std::vector<uint8_t> buildPing(uint64_t nonce);
        std::vector<uint8_t> buildPong(uint64_t nonce);
        std::vector<uint8_t> buildReject(const std::string& msg, RejectCode code,
                                         const std::string& reason,
                                         const std::string& data = "");
        std::vector<uint8_t> buildFeeFilter(uint64_t feerate);
    };

} // namespace powercoin

#endif // POWERCOIN_MESSAGES_H