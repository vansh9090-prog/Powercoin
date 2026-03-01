#include "pow.h"
#include "../crypto/sha256.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <chrono>

namespace PowerCoin {
    
    ProofOfWork::ProofOfWork(uint32_t diff) 
        : difficulty(diff), hashesCalculated(0) {
        updateTarget();
    }
    
    void ProofOfWork::updateTarget() {
        target = std::string(difficulty, '0');
    }
    
    void ProofOfWork::setDifficulty(uint32_t diff) {
        difficulty = diff;
        updateTarget();
    }
    
    bool ProofOfWork::validateHash(const std::string& hash) const {
        return hash.substr(0, difficulty) == target;
    }
    
    std::pair<uint32_t, std::string> ProofOfWork::mine(const std::string& data) {
        uint32_t nonce = 0;
        hashesCalculated = 0;
        
        auto startTime = std::chrono::high_resolution_clock::now();
        
        while (nonce < UINT32_MAX) {
            std::string hash = hashWithNonce(data, nonce);
            hashesCalculated++;
            
            if (validateHash(hash)) {
                auto endTime = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::seconds>(
                    endTime - startTime);
                
                std::cout << "\n✅ Found nonce: " << nonce << std::endl;
                std::cout << "   Hash: " << hash << std::endl;
                std::cout << "   Time: " << duration.count() << " seconds" << std::endl;
                std::cout << "   Hashes: " << hashesCalculated << std::endl;
                
                return {nonce, hash};
            }
            
            nonce++;
            
            if (nonce % 100000 == 0) {
                std::cout << "   Mining... " << nonce << " hashes\r" << std::flush;
            }
        }
        
        return {0, ""};
    }
    
    std::string ProofOfWork::hashWithNonce(const std::string& data, uint32_t nonce) {
        std::stringstream ss;
        ss << data << nonce;
        return SHA256::doubleHash(ss.str());
    }
    
    uint32_t ProofOfWork::calculateNextDifficulty(
        const std::vector<uint32_t>& timestamps,
        uint32_t targetTime,
        uint32_t interval) {
        
        if (timestamps.size() < interval) {
            return 4; // Default difficulty
        }
        
        uint32_t timeActual = timestamps.back() - timestamps[timestamps.size() - interval];
        uint32_t timeTarget = targetTime * interval;
        
        if (timeActual < timeTarget / 2) {
            return timestamps.back() + 1;
        } else if (timeActual > timeTarget * 2) {
            return std::max(1u, timestamps.back() - 1);
        }
        
        return timestamps.back();
    }
    
}