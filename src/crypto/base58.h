#ifndef POWERCOIN_BASE58_H
#define POWERCOIN_BASE58_H

#include <string>
#include <vector>
#include <cstdint>

namespace PowerCoin {
    
    class Base58 {
    private:
        static const char* ALPHABET;
        static const int8_t TABLE[128];
        
    public:
        static std::string encode(const std::vector<uint8_t>& data);
        static std::vector<uint8_t> decode(const std::string& str);
        
        // Bitcoin-style Base58Check
        static std::string encodeCheck(const std::vector<uint8_t>& data);
        static std::vector<uint8_t> decodeCheck(const std::string& str);
        
        // Utility
        static bool isValid(const std::string& str);
    };
    
}

#endif // POWERCOIN_BASE58_H