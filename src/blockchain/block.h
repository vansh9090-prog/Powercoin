#ifndef POWERCOIN_BLOCK_H
#define POWERCOIN_BLOCK_H

#include <string>
#include <vector>
#include <cstdint>
#include <ctime>
#include <memory>
#include "transaction.h"

namespace powercoin {

    /**
     * Block header structure (80 bytes - Bitcoin compatible)
     */
    struct BlockHeader {
        uint32_t version;
        std::string previousBlockHash;  // 32 bytes
        std::string merkleRoot;          // 32 bytes
        uint32_t timestamp;
        uint32_t bits;                   // Difficulty target
        uint32_t nonce;
        
        BlockHeader();
        std::string serialize() const;
        bool deserialize(const std::string& data);
        std::string calculateHash() const;
        uint64_t getWork() const;
    };

    /**
     * Block statistics
     */
    struct BlockStats {
        uint32_t height;
        uint32_t version;
        std::string hash;
        std::string previousHash;
        std::string merkleRoot;
        uint32_t timestamp;
        uint32_t bits;
        uint32_t nonce;
        uint32_t txCount;
        uint64_t totalOutput;
        uint64_t totalFees;
        uint32_t size;
        uint64_t work;
        double difficulty;
    };

    /**
     * Main block class
     * Represents a block in the blockchain
     */
    class Block {
    private:
        BlockHeader header;
        std::vector<Transaction> transactions;
        uint32_t height;
        std::string blockHash;
        uint64_t cachedWork;
        
        // Validation cache
        mutable bool merkleRootValidated;
        mutable std::string cachedMerkleRoot;
        
    public:
        Block();
        explicit Block(uint32_t height);
        Block(const Block& other);
        Block& operator=(const Block& other);
        
        // Move constructor and assignment
        Block(Block&& other) noexcept;
        Block& operator=(Block&& other) noexcept;
        
        // Comparison operators
        bool operator==(const Block& other) const;
        bool operator!=(const Block& other) const;
        
        // Getters
        uint32_t getVersion() const { return header.version; }
        const std::string& getPreviousHash() const { return header.previousBlockHash; }
        const std::string& getMerkleRoot() const { return header.merkleRoot; }
        uint32_t getTimestamp() const { return header.timestamp; }
        uint32_t getBits() const { return header.bits; }
        uint32_t getNonce() const { return header.nonce; }
        uint32_t getHeight() const { return height; }
        const std::string& getHash() const { return blockHash; }
        const std::vector<Transaction>& getTransactions() const { return transactions; }
        
        // Setters
        void setVersion(uint32_t v) { header.version = v; }
        void setPreviousHash(const std::string& hash) { header.previousBlockHash = hash; }
        void setMerkleRoot(const std::string& root) { header.merkleRoot = root; }
        void setTimestamp(uint32_t ts) { header.timestamp = ts; }
        void setBits(uint32_t bits) { header.bits = bits; }
        void setNonce(uint32_t n) { header.nonce = n; }
        void setHeight(uint32_t h) { height = h; }
        
        // Transaction management
        void addTransaction(const Transaction& tx);
        void addTransaction(Transaction&& tx);
        bool removeTransaction(const std::string& txHash);
        void clearTransactions();
        size_t getTransactionCount() const { return transactions.size(); }
        bool hasTransaction(const std::string& txHash) const;
        const Transaction* getTransaction(const std::string& txHash) const;
        
        // Merkle tree
        void calculateMerkleRoot();
        bool validateMerkleRoot() const;
        std::string buildMerkleTree() const;
        
        // Block hash
        void calculateHash();
        bool validateHash() const;
        
        // Mining
        bool mine(uint32_t targetBits);
        bool mineWithNonce(uint32_t startNonce, uint32_t targetBits);
        uint64_t getWork() const;
        
        // Validation
        bool validate(const Block& previousBlock) const;
        bool validateTimestamp() const;
        bool validateTransactions() const;
        bool validateSize() const;
        
        // Serialization
        std::string serialize() const;
        bool deserialize(const std::string& data);
        std::vector<uint8_t> serializeBinary() const;
        bool deserializeBinary(const std::vector<uint8_t>& data);
        
        // Size calculation
        uint32_t getSize() const;
        uint32_t getBaseSize() const;
        uint32_t getTotalSize() const;
        
        // Statistics
        BlockStats getStats() const;
        uint64_t getTotalOutput() const;
        uint64_t getTotalFees() const;
        double getDifficulty() const;
        
        // Utility
        std::string toString() const;
        void print() const;
        
        // Static helpers
        static Block createGenesis();
        static bool isValidTimestamp(uint32_t timestamp);
        static uint32_t getMaxTimestamp();
        static uint32_t getMinTimestamp();
        
        // Genesis block constants
        static constexpr uint32_t GENESIS_VERSION = 1;
        static constexpr uint32_t GENESIS_TIMESTAMP = 1231006505; // Bitcoin genesis timestamp
        static constexpr uint32_t GENESIS_BITS = 0x1d00ffff;
        static constexpr uint32_t GENESIS_NONCE = 2083236893;
        static const std::string GENESIS_HASH;
        static const std::string GENESIS_PREVIOUS_HASH;
    };

} // namespace powercoin

#endif // POWERCOIN_BLOCK_H