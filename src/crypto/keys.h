#ifndef POWERCOIN_KEYS_H
#define POWERCOIN_KEYS_H

#include <string>
#include <vector>
#include <cstdint>

namespace PowerCoin {
    
    class Keys {
    private:
        std::vector<uint8_t> privateKey;
        std::vector<uint8_t> publicKey;
        
    public:
        Keys();
        
        // Generation
        void generateKeyPair();
        
        // Import/Export
        bool importPrivateKey(const std::string& wif);
        std::string exportPrivateKeyWIF() const;
        std::string exportPublicKey() const;
        
        // Signing
        std::string sign(const std::string& message) const;
        static bool verify(const std::string& message, 
                          const std::string& signature,
                          const std::string& publicKey);
        
        // Getters
        const std::vector<uint8_t>& getPrivateKey() const { return privateKey; }
        const std::vector<uint8_t>& getPublicKey() const { return publicKey; }
        
        // Utility
        static std::string privateKeyToWIF(const std::vector<uint8_t>& key);
        static std::vector<uint8_t> WIFToPrivateKey(const std::string& wif);
        static std::vector<uint8_t> privateToPublic(const std::vector<uint8_t>& privateKey);
    };
    
}

#endif // POWERCOIN_KEYS_H