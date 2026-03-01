#ifndef POWERCOIN_ADDRESS_H
#define POWERCOIN_ADDRESS_H

#include <string>
#include <vector>

namespace PowerCoin {
    
    class Address {
    public:
        static std::string fromPublicKey(const std::vector<uint8_t>& publicKey);
        static bool validate(const std::string& address);
    };
    
}

#endif // POWERCOIN_ADDRESS_H