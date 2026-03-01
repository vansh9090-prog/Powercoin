#include "node.h"
#include <iostream>  // ✅ Add this at the top
#include <chrono>

namespace PowerCoin {
    
    Node::Node() : isRunning(false) {
        blockchain = std::make_unique<Blockchain>();
        p2p = std::make_unique<P2PNetwork>();
        miner = std::make_unique<Miner>(blockchain.get());
        
        startTime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
    
    Node::~Node() {
        stop();
    }
    
    bool Node::start() {
        if (isRunning) return true;
        
        isRunning = true;
        
        if (!p2p->start()) {
            std::cerr << "Failed to start P2P network" << std::endl;
            return false;
        }
        
        setupCallbacks();
        
        std::cout << "Node started successfully" << std::endl;
        std::cout << "Blockchain height: " << blockchain->getHeight() << std::endl;
        
        return true;
    }
    
    void Node::stop() {
        if (!isRunning) return;
        
        isRunning = false;
        
        stopMining();
        p2p->stop();
        
        std::cout << "Node stopped" << std::endl;
    }
    
    void Node::setupCallbacks() {
        p2p->onBlockReceived = [this](const std::string& fromPeer, const std::string& blockData) {
            std::cout << "Received block from " << fromPeer << std::endl;
            // Process block...
        };
        
        p2p->onTransactionReceived = [this](const std::string& fromPeer, const std::string& txData) {
            std::cout << "Received transaction from " << fromPeer << std::endl;
            // Process transaction...
        };
        
        p2p->onNewPeer = [](const Peer& peer) {
            std::cout << "New peer connected: " << peer.id << std::endl;
        };
    }
    
    void Node::startMining(const std::string& address) {
        miner->startMining(address);
    }
    
    void Node::stopMining() {
        miner->stopMining();
    }
    
    bool Node::submitTransaction(const Transaction& tx) {
        return blockchain->addTransaction(tx);
    }
    
    double Node::getBalance(const std::string& address) const {
        return blockchain->getBalance(address);
    }
    
    NodeInfo Node::getBlockchainInfo() const {
        NodeInfo info;
        info.nodeId = p2p->getNodeId();
        info.blocks = blockchain->getHeight();
        info.difficulty = blockchain->getDifficulty();
        info.pendingTransactions = blockchain->getMempoolSize();
        info.totalSupply = blockchain->getHeight() * 50; // 50 PWR per block
        info.peers = p2p->getPeerCount();
        info.uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() - startTime;
        
        Block lastBlock = blockchain->getLastBlock();
        info.lastBlockHash = lastBlock.getHash();
        info.lastBlockTime = lastBlock.getHeader().timestamp;
        
        return info;
    }
    
    MiningStats Node::getMiningStats() const {
        MiningStats stats;
        stats.mining = miner->isActive();
        stats.blocksMined = miner->getBlocksMined();
        stats.totalRewards = miner->getTotalRewards();
        stats.hashRate = 0;
        stats.difficulty = blockchain->getDifficulty();
        return stats;
    }
    
    NetworkInfo Node::getNetworkInfo() const {
        NetworkInfo info;
        info.nodeId = p2p->getNodeId();
        info.connectedPeers = p2p->getPeerCount();
        info.totalPeers = p2p->getPeerCount();
        info.uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() - startTime;
        return info;
    }
    
}