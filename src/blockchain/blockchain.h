#ifndef POWERCOIN_BLOCKCHAIN_H
#define POWERCOIN_BLOCKCHAIN_H

#include <vector>
#include <string>
#include "block.h"
#include "transaction.h"

namespace PowerCoin {
    
    class Blockchain {
    private:
        std::vector<Block> chain;
        std::vector<Transaction> mempool;
        uint32_t difficulty;

    public:
        Blockchain();
        
        const std::vector<Block>& getChain() const { return chain; }
        uint32_t getHeight() const { return chain.size(); }
        uint32_t getDifficulty() const { return difficulty; }
        
        bool addBlock(const Block& block);
        bool addTransaction(const Transaction& tx);
        Block createNewBlock(const std::string& minerAddress);
        bool mineBlock(Block& block);
        
        double getBalance(const std::string& address) const;
        
        static Blockchain createGenesis();
    };
    
}

#endif // POWERCOIN_BLOCKCHAIN_H