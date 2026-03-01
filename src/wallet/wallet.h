#ifndef POWERCOIN_WALLET_H
#define POWERCOIN_WALLET_H

#include <string>
#include <memory>
#include <vector>
#include "../crypto/keys.h"

namespace PowerCoin {
    
    struct WalletKeys {
        std::string privateKey;
        std::string publicKey;
        std::string address;
    };
    
    class Wallet {
    private:
        std::unique_ptr<Keys> keys;
        std::string address;

    public:
        Wallet();
        
        WalletKeys createNewWallet();
        bool loadFromPrivateKey(const std::string& privateKeyWIF);
        
        std::string getAddress() const { return address; }
        std::string signTransaction(const std::string& txData) const;
    };
    
}

#endif // POWERCOIN_WALLET_H