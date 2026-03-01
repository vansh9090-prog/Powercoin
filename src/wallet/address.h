#ifndef POWERCOIN_ADDRESS_H
#define POWERCOIN_ADDRESS_H

#include <string>
#include <vector>
#include <cstdint>

namespace PowerCoin {
    
    class Address {
    private:
        std::vector<uint8_t> hash160;
        std::string address;
        
    public:
        Address();
        
        // Generation
        static std::string fromPublicKey(const std::vector<uint8_t>& publicKey);
        static std::string fromPrivateKey(const std::vector<uint8_t>& privateKey);
        
        // Validation
        static bool validate(const std::string& address);
        
        // Utility
        static std::vector<uint8_t> publicKeyToHash160(const std::vector<uint8_t>& publicKey);
        static std::string hash160ToAddress(const std::vector<uint8_t>& hash160);
    };
    
}

#endif // POWERCOIN_ADDRESS_H