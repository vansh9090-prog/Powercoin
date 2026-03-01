#ifndef POWERCOIN_MINING_H
#define POWERCOIN_MINING_H

#include <thread>
#include <atomic>
#include <functional>
#include "../blockchain/blockchain.h"

namespace PowerCoin {
    
    class Miner {
    private:
        std::thread miningThread;
        std::atomic<bool> isMining;
        std::string miningAddress;
        Blockchain* blockchain;
        
        uint64_t blocksMined;
        double totalRewards;
        
        void miningLoop();

    public:
        Miner(Blockchain* bc);
        ~Miner();
        
        void startMining(const std::string& address);
        void stopMining();
        bool isActive() const { return isMining; }
        
        uint64_t getBlocksMined() const { return blocksMined; }
        double getTotalRewards() const { return totalRewards; }
    };
    
}

#endif // POWERCOIN_MINING_H