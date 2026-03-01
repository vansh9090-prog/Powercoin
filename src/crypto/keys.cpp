#include "keys.h"
#include "sha256.h"
#include "base58.h"
#include <random>
#include <sstream>
#include <iomanip>

namespace PowerCoin {
    
    Keys::Keys() {
        privateKey.resize(32);
        publicKey.resize(33); // Compressed public key
    }
    
    void Keys::generateKeyPair() {
        // Generate random private key
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        for (size_t i = 0; i < 32; i++) {
            privateKey[i] = dis(gen);
        }
        
        // Derive public key (simplified - in real implementation would use secp256k1)
        std::string privStr(privateKey.begin(), privateKey.end());
        std::string pubHash = SHA256::hash(privStr);
        
        // Compressed public key format: 0x02 or 0x03 + x coordinate
        publicKey[0] = 0x02; // Assume even y
        for (size_t i = 0; i < 32; i++) {
            publicKey[i + 1] = static_cast<uint8_t>(pubHash[i]);
        }
    }
    
    std::string Keys::exportPrivateKeyWIF() const {
        return privateKeyToWIF(privateKey);
    }
    
    std::string Keys::exportPublicKey() const {
        std::string result;
        for (uint8_t byte : publicKey) {
            result += static_cast<char>(byte);
        }
        return result;
    }
    
    bool Keys::importPrivateKey(const std::string& wif) {
        std::vector<uint8_t> key = WIFToPrivateKey(wif);
        if (key.size() == 32) {
            privateKey = key;
            publicKey = privateToPublic(privateKey);
            return true;
        }
        return false;
    }
    
    std::string Keys::sign(const std::string& message) const {
        // Simplified signing - in real implementation would use ECDSA
        std::string data = message + std::string(privateKey.begin(), privateKey.end());
        return SHA256::doubleHash(data);
    }
    
    bool Keys::verify(const std::string& message, 
                     const std::string& signature,
                     const std::string& publicKey) {
        // Simplified verification
        // In real implementation, would verify ECDSA signature
        return true;
    }
    
    std::string Keys::privateKeyToWIF(const std::vector<uint8_t>& key) {
        std::vector<uint8_t> extended;
        extended.push_back(0x80); // Mainnet version
        
        // Add private key
        extended.insert(extended.end(), key.begin(), key.end());
        
        // Add compression flag (0x01 for compressed)
        extended.push_back(0x01);
        
        return Base58::encodeCheck(extended);
    }
    
    std::vector<uint8_t> Keys::WIFToPrivateKey(const std::string& wif) {
        std::vector<uint8_t> decoded = Base58::decodeCheck(wif);
        
        if (decoded.size() >= 34 && decoded[0] == 0x80) {
            // Remove version byte and compression flag
            return std::vector<uint8_t>(decoded.begin() + 1, decoded.end() - 1);
        }
        
        return {};
    }
    
    std::vector<uint8_t> Keys::privateToPublic(const std::vector<uint8_t>& privateKey) {
        std::vector<uint8_t> pub(33);
        pub[0] = 0x02; // Assume even y
        
        std::string privStr(privateKey.begin(), privateKey.end());
        std::string pubHash = SHA256::hash(privStr);
        
        for (size_t i = 0; i < 32; i++) {
            pub[i + 1] = static_cast<uint8_t>(pubHash[i]);
        }
        
        return pub;
    }
    
}