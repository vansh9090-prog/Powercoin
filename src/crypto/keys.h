#ifndef POWERCOIN_KEYS_H
#define POWERCOIN_KEYS_H

#include <string>
#include <vector>

namespace PowerCoin {
    
    class Keys {
    private:
        std::vector<uint8_t> privateKey;
        std::vector<uint8_t> publicKey;

    public:
        void generateKeyPair();
        
        std::string exportPrivateKeyWIF() const;
        bool importPrivateKey(const std::string& wif);
        
        std::string sign(const std::string& message) const;
        
        const std::vector<uint8_t>& getPublicKey() const { return publicKey; }
    };
    
}

#endif // POWERCOIN_KEYS_H