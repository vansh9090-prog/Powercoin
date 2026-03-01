#include "mining.h"
#include "../config.h"
#include <iostream>
#include <chrono>
#include <thread>

namespace PowerCoin {
    
    Miner::Miner(Blockchain* bc) 
        : isMining(false), blockchain(bc), blocksMined(0), totalRewards(0) {}
    
    Miner::~Miner() {
        stopMining();
    }
    
    void Miner::startMining(const std::string& address) {
        if (isMining) return;
        
        miningAddress = address;
        isMining = true;
        
        miningThread = std::thread([this]() {
            this->miningLoop();
        });
    }
    
    void Miner::stopMining() {
        isMining = false;
        if (miningThread.joinable()) {
            miningThread.join();
        }
    }
    
    void Miner::miningLoop() {
        while (isMining) {
            Block newBlock = blockchain->createNewBlock(miningAddress);
            if (newBlock.mine(blockchain->getDifficulty())) {
                if (blockchain->addBlock(newBlock)) {
                    blocksMined++;
                    totalRewards += INITIAL_BLOCK_REWARD;
                    std::cout << "\n✅ Block #" << newBlock.getIndex() << " mined! +" 
                              << INITIAL_BLOCK_REWARD << " PWR\n";
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    
}