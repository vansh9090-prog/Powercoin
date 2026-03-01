#include "address.h"
#include "../crypto/sha256.h"
#include "../crypto/base58.h"
#include <cstring>

namespace PowerCoin {
    
    Address::Address() {
        hash160.resize(20);
    }
    
    std::string Address::fromPublicKey(const std::vector<uint8_t>& publicKey) {
        std::vector<uint8_t> hash160 = publicKeyToHash160(publicKey);
        return hash160ToAddress(hash160);
    }
    
    std::string Address::fromPrivateKey(const std::vector<uint8_t>& privateKey) {
        // Derive public key from private key
        std::string privStr(privateKey.begin(), privateKey.end());
        std::string pubHash = SHA256::hash(privStr);
        
        std::vector<uint8_t> publicKey(33);
        publicKey[0] = 0x02; // Assume even y
        for (size_t i = 0; i < 32; i++) {
            publicKey[i + 1] = static_cast<uint8_t>(pubHash[i]);
        }
        
        return fromPublicKey(publicKey);
    }
    
    std::vector<uint8_t> Address::publicKeyToHash160(const std::vector<uint8_t>& publicKey) {
        // SHA-256
        std::string pubStr(publicKey.begin(), publicKey.end());
        std::string sha256Hash = SHA256::hash(pubStr);
        
        // RIPEMD-160 (simplified - using SHA-256 again for demo)
        std::string ripemd160 = SHA256::hash(sha256Hash);
        
        std::vector<uint8_t> hash160(20);
        for (size_t i = 0; i < 20; i++) {
            hash160[i] = static_cast<uint8_t>(ripemd160[i]);
        }
        
        return hash160;
    }
    
    std::string Address::hash160ToAddress(const std::vector<uint8_t>& hash160) {
        std::vector<uint8_t> extended;
        extended.push_back(0x00); // Mainnet version
        
        extended.insert(extended.end(), hash160.begin(), hash160.end());
        
        return Base58::encodeCheck(extended);
    }
    
    bool Address::validate(const std::string& address) {
        if (address.empty() || address.length() < 26 || address.length() > 35) {
            return false;
        }
        
        // Check Base58 validity
        if (!Base58::isValid(address)) {
            return false;
        }
        
        // Decode and verify checksum
        std::vector<uint8_t> decoded = Base58::decodeCheck(address);
        
        if (decoded.empty() || decoded[0] != 0x00) {
            return false;
        }
        
        return decoded.size() == 21; // 1 version + 20 hash
    }
    
}