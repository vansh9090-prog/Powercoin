#include "keys.h"
#include "sha256.h"
#include "base58.h"
#include <random>
#include <sstream>

namespace PowerCoin {
    
    void Keys::generateKeyPair() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dis(0, 255);
        
        privateKey.resize(32);
        for (size_t i = 0; i < 32; i++) {
            privateKey[i] = dis(gen);
        }
        
        publicKey.resize(33);
        publicKey[0] = 0x02;
        std::string privStr(privateKey.begin(), privateKey.end());
        std::string pubHash = SHA256::hash(privStr);
        for (size_t i = 0; i < 32; i++) {
            publicKey[i+1] = pubHash[i];
        }
    }
    
    std::string Keys::exportPrivateKeyWIF() const {
        std::vector<uint8_t> extended;
        extended.push_back(0x80);
        extended.insert(extended.end(), privateKey.begin(), privateKey.end());
        extended.push_back(0x01);
        return Base58::encode(extended);
    }
    
    bool Keys::importPrivateKey(const std::string& wif) {
        auto decoded = Base58::decode(wif);
        if (decoded.size() >= 34 && decoded[0] == 0x80) {
            privateKey.assign(decoded.begin() + 1, decoded.end() - 1);
            publicKey.resize(33);
            publicKey[0] = 0x02;
            std::string privStr(privateKey.begin(), privateKey.end());
            std::string pubHash = SHA256::hash(privStr);
            for (size_t i = 0; i < 32; i++) {
                publicKey[i+1] = pubHash[i];
            }
            return true;
        }
        return false;
    }
    
    std::string Keys::sign(const std::string& message) const {
        std::string data = message + std::string(privateKey.begin(), privateKey.end());
        return SHA256::doubleHash(data);
    }
    
}