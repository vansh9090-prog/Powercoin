#include "mining.h"
#include <iostream>
#include <chrono>
#include <thread>

namespace PowerCoin {
    
    Miner::Miner(Blockchain* bc) 
        : isMining(false), shouldStop(false), blockchain(bc),
          blocksMined(0), totalRewards(0), totalHashes(0) {}
    
    Miner::~Miner() {
        stopMining();
    }
    
    void Miner::startMining(const std::string& address) {
        if (isMining) {
            std::cout << "Mining already active" << std::endl;
            return;
        }
        
        miningAddress = address;
        isMining = true;
        shouldStop = false;
        
        miningThread = std::make_unique<std::thread>(&Miner::miningLoop, this);
        
        std::cout << "⛏️  Mining started for address: " 
                  << miningAddress.substr(0, 20) << "..." << std::endl;
    }
    
    void Miner::stopMining() {
        if (isMining) {
            shouldStop = true;
            isMining = false;
            
            if (miningThread && miningThread->joinable()) {
                miningThread->join();
            }
            
            std::cout << "⛏️  Mining stopped" << std::endl;
        }
    }
    
    void Miner::miningLoop() {
        while (!shouldStop) {
            try {
                // Create new block
                Block newBlock = blockchain->createNewBlock(miningAddress);
                
                // Mine the block
                auto startTime = std::chrono::high_resolution_clock::now();
                
                if (newBlock.mine(blockchain->getDifficulty())) {
                    auto endTime = std::chrono::high_resolution_clock::now();
                    auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                        endTime - startTime);
                    
                    // Add block to blockchain
                    if (blockchain->addBlock(newBlock)) {
                        blocksMined++;
                        totalRewards += INITIAL_BLOCK_REWARD;
                        
                        if (onBlockMined) {
                            onBlockMined(newBlock);
                        }
                        
                        std::cout << "\n✅ Block #" << newBlock.getHeight() 
                                  << " mined!" << std::endl;
                        std::cout << "   Time: " << duration.count() << " seconds" << std::endl;
                        std::cout << "   Reward: " << INITIAL_BLOCK_REWARD << " PWR" << std::endl;
                    }
                }
                
                // Small pause to prevent CPU overload
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                
            } catch (const std::exception& e) {
                std::cerr << "Mining error: " << e.what() << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
    }
    
}