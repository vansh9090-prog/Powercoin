#ifndef POWERCOIN_POW_H
#define POWERCOIN_POW_H

#include <cstdint>
#include <string>
#include <vector>

namespace PowerCoin {
    
    class ProofOfWork {
    private:
        uint32_t difficulty;
        uint64_t hashesCalculated;
        std::string target;
        
        void updateTarget();
        
    public:
        ProofOfWork(uint32_t diff = 4);
        
        // Getters
        uint32_t getDifficulty() const { return difficulty; }
        uint64_t getHashesCalculated() const { return hashesCalculated; }
        
        // Setters
        void setDifficulty(uint32_t diff);
        
        // Mining
        bool validateHash(const std::string& hash) const;
        std::pair<uint32_t, std::string> mine(const std::string& data);
        
        // Difficulty calculation
        static uint32_t calculateNextDifficulty(
            const std::vector<uint32_t>& timestamps,
            uint32_t targetTime,
            uint32_t interval
        );
        
        // Utility
        static std::string hashWithNonce(const std::string& data, uint32_t nonce);
    };
    
}

#endif // POWERCOIN_POW_H