#include "pow.h"
#include "../crypto/sha256.h"
#include <iostream>

namespace PowerCoin {
    
    ProofOfWork::ProofOfWork(uint32_t diff) : difficulty(diff) {}
    
    bool ProofOfWork::validateHash(const std::string& hash) const {
        std::string target(difficulty, '0');
        return hash.substr(0, difficulty) == target;
    }
    
    std::pair<uint32_t, std::string> ProofOfWork::mine(const std::string& data) {
        uint32_t nonce = 0;
        while (nonce < UINT32_MAX) {
            std::string hash = hashWithNonce(data, nonce);
            if (validateHash(hash)) {
                return {nonce, hash};
            }
            nonce++;
        }
        return {0, ""};
    }
    
    std::string ProofOfWork::hashWithNonce(const std::string& data, uint32_t nonce) {
        return SHA256::doubleHash(data + std::to_string(nonce));
    }
    
}