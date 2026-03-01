#ifndef POWERCOIN_SHA256_H
#define POWERCOIN_SHA256_H

#include <string>
#include <vector>
#include <cstdint>

namespace PowerCoin {
    
    class SHA256 {
    public:
        static std::string hash(const std::string& input);
        static std::string doubleHash(const std::string& input);
    };
    
}

#endif // POWERCOIN_SHA256_H