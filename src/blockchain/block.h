#ifndef POWERCOIN_BLOCK_H
#define POWERCOIN_BLOCK_H

#include <string>
#include <vector>
#include <cstdint>
#include <ctime>
#include "transaction.h"

namespace PowerCoin {
    
    struct BlockHeader {
        uint32_t version;
        std::string previousBlockHash;
        std::string merkleRoot;
        uint32_t timestamp;
        uint32_t bits;  // Difficulty target
        uint32_t nonce;
        
        BlockHeader();
        std::string serialize() const;
        std::string calculateHash() const;
    };
    
    class Block {
    private:
        BlockHeader header;
        std::vector<Transaction> transactions;
        uint32_t height;
        std::string blockHash;
        
    public:
        Block(uint32_t height = 0);
        
        // Getters
        const BlockHeader& getHeader() const { return header; }
        const std::vector<Transaction>& getTransactions() const { return transactions; }
        uint32_t getHeight() const { return height; }
        std::string getHash() const { return blockHash; }
        
        // Setters
        void setPreviousHash(const std::string& hash) { header.previousBlockHash = hash; }
        void setTimestamp(uint32_t ts) { header.timestamp = ts; }
        void setDifficulty(uint32_t diff) { header.bits = diff; }
        
        // Block operations
        void addTransaction(const Transaction& tx);
        void calculateMerkleRoot();
        bool mine(uint32_t difficulty);
        bool validate(const Block& previousBlock, uint32_t difficulty) const;
        
        // Serialization
        std::string serialize() const;
        static Block deserialize(const std::string& data);
        
        // Genesis block
        static Block createGenesis();
    };
    
}

#endif // POWERCOIN_BLOCK_H