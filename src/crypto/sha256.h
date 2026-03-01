#ifndef POWERCOIN_SHA256_H
#define POWERCOIN_SHA256_H

#include <string>
#include <vector>
#include <cstdint>

namespace PowerCoin {
    
    class SHA256 {
    private:
        static const uint32_t SHA256_K[64];
        uint32_t h[8];
        uint64_t data_len;
        std::vector<uint8_t> buffer;
        
        void transform(const uint8_t* chunk);
        void reset();  // ✅ Declare reset function
        
    public:
        SHA256();
        ~SHA256() = default;
        
        void update(const std::vector<uint8_t>& data);
        void update(const std::string& data);
        std::vector<uint8_t> finalize();
        
        static std::string hash(const std::string& input);
        static std::string doubleHash(const std::string& input);
    };
    
}

#endif // POWERCOIN_SHA256_H