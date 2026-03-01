#include "node.h"
#include "../config.h"
#include <iostream>
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
        isRunning = true;
        p2p->start();
        std::cout << "✅ Node started\n";
        return true;
    }
    
    void Node::stop() {
        isRunning = false;
        stopMining();
        p2p->stop();
    }
    
    void Node::startMining(const std::string& address) {
        miner->startMining(address);
    }
    
    void Node::stopMining() {
        miner->stopMining();
    }
    
    double Node::getBalance(const std::string& address) const {
        return blockchain->getBalance(address);
    }
    
    NodeInfo Node::getBlockchainInfo() const {
        NodeInfo info;
        info.nodeId = "PWR-001";
        info.blocks = blockchain->getHeight();
        info.difficulty = blockchain->getDifficulty();
        info.totalSupply = info.blocks * INITIAL_BLOCK_REWARD;
        info.peers = p2p->getPeerCount();
        info.uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() - startTime;
        return info;
    }
    
    MiningStats Node::getMiningStats() const {
        MiningStats stats;
        stats.mining = miner->isActive();
        stats.blocksMined = miner->getBlocksMined();
        stats.totalRewards = miner->getTotalRewards();
        stats.difficulty = blockchain->getDifficulty();
        return stats;
    }
    
}