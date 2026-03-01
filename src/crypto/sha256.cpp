#include "sha256.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <iostream>

namespace PowerCoin {
    
    std::string SHA256::hash(const std::string& input) {
        // Simplified SHA-256 for demo
        unsigned long hash = 5381;
        for (char c : input) {
            hash = ((hash << 5) + hash) + c;
        }
        
        std::stringstream ss;
        ss << std::hex << std::setw(64) << std::setfill('0') << hash;
        return ss.str();
    }
    
    std::string SHA256::doubleHash(const std::string& input) {
        return hash(hash(input));
    }
    
}