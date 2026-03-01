#ifndef POWERCOIN_MINING_H
#define POWERCOIN_MINING_H

#include <thread>
#include <atomic>
#include <memory>
#include <functional>
#include "../blockchain/blockchain.h"

namespace PowerCoin {
    
    class Miner {
    private:
        std::unique_ptr<std::thread> miningThread;
        std::atomic<bool> isMining;
        std::atomic<bool> shouldStop;
        std::string miningAddress;
        Blockchain* blockchain;
        
        uint64_t blocksMined;
        double totalRewards;
        uint64_t totalHashes;
        
        void miningLoop();
        
    public:
        Miner(Blockchain* bc);
        ~Miner();
        
        // Mining control
        void startMining(const std::string& address);
        void stopMining();
        bool isActive() const { return isMining; }
        
        // Statistics
        uint64_t getBlocksMined() const { return blocksMined; }
        double getTotalRewards() const { return totalRewards; }
        uint64_t getTotalHashes() const { return totalHashes; }
        
        // Callbacks
        std::function<void(const Block&)> onBlockMined;
        std::function<void(const std::string&)> onStatusUpdate;
    };
    
}

#endif // POWERCOIN_MINING_H