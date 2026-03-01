#ifndef POWERCOIN_BLOCK_H
#define POWERCOIN_BLOCK_H

#include <string>
#include <vector>
#include <ctime>
#include "transaction.h"

namespace PowerCoin {
    
    class Block {
    private:
        uint32_t index;
        std::string previousHash;
        std::string merkleRoot;
        uint32_t timestamp;
        uint32_t difficulty;
        uint32_t nonce;
        std::vector<Transaction> transactions;
        std::string blockHash;

    public:
        Block(uint32_t idx = 0, const std::string& prevHash = "");
        
        void addTransaction(const Transaction& tx);
        void calculateMerkleRoot();
        bool mine(uint32_t diff);
        bool validate(const Block& previous, uint32_t diff) const;
        
        std::string getHash() const { return blockHash; }
        uint32_t getIndex() const { return index; }
        uint32_t getTimestamp() const { return timestamp; }
        const std::string& getPreviousHash() const { return previousHash; }
        
        static Block createGenesis();
    };
    
}

#endif // POWERCOIN_BLOCK_H