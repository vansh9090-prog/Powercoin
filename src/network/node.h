#ifndef POWERCOIN_NODE_H
#define POWERCOIN_NODE_H

#include <memory>
#include <string>
#include <atomic>
#include "../blockchain/blockchain.h"
#include "../consensus/mining.h"
#include "p2p.h"

namespace PowerCoin {
    
    struct NodeInfo {
        std::string nodeId;
        uint32_t blocks;
        uint32_t difficulty;
        double totalSupply;
        size_t peers;
        uint64_t uptime;
    };
    
    struct MiningStats {
        bool mining;
        uint64_t blocksMined;
        double totalRewards;
        uint32_t difficulty;
    };
    
    class Node {
    private:
        std::unique_ptr<Blockchain> blockchain;
        std::unique_ptr<P2PNetwork> p2p;
        std::unique_ptr<Miner> miner;
        
        std::atomic<bool> isRunning;
        uint64_t startTime;

    public:
        Node();
        ~Node();
        
        bool start();
        void stop();
        
        void startMining(const std::string& address);
        void stopMining();
        
        double getBalance(const std::string& address) const;
        
        NodeInfo getBlockchainInfo() const;
        MiningStats getMiningStats() const;
    };
    
}

#endif // POWERCOIN_NODE_H