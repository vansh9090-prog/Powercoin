#ifndef POWERCOIN_BASE58_H
#define POWERCOIN_BASE58_H

#include <string>
#include <vector>

namespace PowerCoin {
    
    class Base58 {
    public:
        static std::string encode(const std::vector<uint8_t>& data);
        static std::vector<uint8_t> decode(const std::string& str);
    };
    
}

#endif // POWERCOIN_BASE58_H