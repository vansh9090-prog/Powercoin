#include "address.h"
#include "../crypto/sha256.h"
#include "../crypto/base58.h"
#include <vector>

namespace PowerCoin {
    
    std::string Address::fromPublicKey(const std::vector<uint8_t>& publicKey) {
        std::string pubStr(publicKey.begin(), publicKey.end());
        std::string hash = SHA256::hash(pubStr);
        
        std::vector<uint8_t> addressBytes;
        addressBytes.push_back(0x00);
        for (size_t i = 0; i < 20 && i < hash.size(); i++) {
            addressBytes.push_back(hash[i]);
        }
        
        return Base58::encode(addressBytes);
    }
    
    bool Address::validate(const std::string& address) {
        if (address.empty() || address.length() < 26) return false;
        auto decoded = Base58::decode(address);
        return !decoded.empty() && decoded[0] == 0x00;
    }
    
}