#ifndef POWERCOIN_NODE_H
#define POWERCOIN_NODE_H

#include <memory>
#include <string>
#include <atomic>
#include "p2p.h"
#include "../blockchain/blockchain.h"
#include "../consensus/mining.h"

namespace PowerCoin {
    
    struct NodeInfo {
        std::string nodeId;
        uint32_t blocks;
        uint32_t difficulty;
        size_t pendingTransactions;
        double totalSupply;
        size_t peers;
        uint64_t uptime;
        std::string lastBlockHash;
        uint32_t lastBlockTime;
    };
    
    struct MiningStats {
        bool mining;
        uint64_t blocksMined;
        double totalRewards;
        double hashRate;
        uint32_t difficulty;
    };
    
    struct NetworkInfo {
        std::string nodeId;
        size_t connectedPeers;
        size_t totalPeers;
        uint64_t uptime;
    };
    
    class Node {
    private:
        std::unique_ptr<Blockchain> blockchain;
        std::unique_ptr<P2PNetwork> p2p;
        std::unique_ptr<Miner> miner;
        
        std::atomic<bool> isRunning;
        uint64_t startTime;
        
        void setupCallbacks();
        
    public:
        Node();
        ~Node();
        
        // Node control
        bool start();
        void stop();
        
        // Mining
        void startMining(const std::string& address);
        void stopMining();
        
        // Blockchain operations
        bool submitTransaction(const Transaction& tx);
        double getBalance(const std::string& address) const;
        
        // Info
        NodeInfo getBlockchainInfo() const;
        MiningStats getMiningStats() const;
        NetworkInfo getNetworkInfo() const;
    };
    
}

#endif // POWERCOIN_NODE_H