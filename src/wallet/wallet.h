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
        ~Wallet();
        
        // Wallet operations
        WalletKeys createNewWallet();
        bool loadFromPrivateKey(const std::string& privateKeyWIF);
        
        // Getters
        std::string getAddress() const { return address; }
        
        // Signing
        std::string signTransaction(const std::string& txData) const;
        
        // Static utilities
        static std::vector<std::string> listWallets();
        static bool saveWallet(const std::string& filename, const WalletKeys& keys);
        static WalletKeys loadWallet(const std::string& filename);
    };
    
}

#endif // POWERCOIN_WALLET_H