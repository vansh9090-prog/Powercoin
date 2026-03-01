#ifndef POWERCOIN_POW_H
#define POWERCOIN_POW_H

#include <string>
#include <cstdint>

namespace PowerCoin {
    
    class ProofOfWork {
    private:
        uint32_t difficulty;

    public:
        ProofOfWork(uint32_t diff = 4);
        
        bool validateHash(const std::string& hash) const;
        std::pair<uint32_t, std::string> mine(const std::string& data);
        
        static std::string hashWithNonce(const std::string& data, uint32_t nonce);
    };
    
}

#endif // POWERCOIN_POW_H