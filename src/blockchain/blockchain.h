#ifndef POWERCOIN_BLOCKCHAIN_H
#define POWERCOIN_BLOCKCHAIN_H

#include <vector>
#include <string>
#include <memory>
#include <map>
#include "block.h"
#include "transaction.h"

namespace PowerCoin {
    
    class Blockchain {
    private:
        std::vector<Block> chain;
        std::vector<Transaction> mempool;
        std::map<std::string, TxOutput> utxoSet;
        uint32_t difficulty;
        uint32_t height;
        
        void updateUTXOSet(const Block& block);
        bool validateBlock(const Block& block, const Block& previousBlock) const;
        
    public:
        Blockchain();
        
        // Getters
        const std::vector<Block>& getChain() const { return chain; }
        Block getLastBlock() const { return chain.empty() ? Block() : chain.back(); }
        uint32_t getHeight() const { return height; }
        uint32_t getDifficulty() const { return difficulty; }
        size_t getMempoolSize() const { return mempool.size(); }
        
        // Blockchain operations
        bool addBlock(const Block& block);
        bool addTransaction(const Transaction& tx);
        Block createNewBlock(const std::string& minerAddress);
        bool mineBlock(Block& block);
        
        // Validation
        bool validateChain() const;
        bool validateTransaction(const Transaction& tx) const;
        
        // Balance
        double getBalance(const std::string& address) const;
        
        // Difficulty adjustment
        void adjustDifficulty();
        
        // UTXO
        std::vector<std::pair<std::string, TxOutput>> getUTXOsForAddress(const std::string& address) const;
        
        // Serialization
        bool saveToFile(const std::string& filename) const;
        bool loadFromFile(const std::string& filename);
        
        // Genesis
        static Blockchain createGenesis();
    };
    
}

#endif // POWERCOIN_BLOCKCHAIN_H