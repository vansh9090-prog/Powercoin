#include "wallet.h"
#include "address.h"
#include <iostream>

namespace PowerCoin {
    
    Wallet::Wallet() {
        keys = std::make_unique<Keys>();
    }
    
    WalletKeys Wallet::createNewWallet() {
        keys->generateKeyPair();
        
        WalletKeys walletKeys;
        walletKeys.privateKey = keys->exportPrivateKeyWIF();
        
        auto pubKey = keys->getPublicKey();
        walletKeys.publicKey = std::string(pubKey.begin(), pubKey.end());
        walletKeys.address = Address::fromPublicKey(pubKey);
        address = walletKeys.address;
        
        return walletKeys;
    }
    
    bool Wallet::loadFromPrivateKey(const std::string& privateKeyWIF) {
        if (keys->importPrivateKey(privateKeyWIF)) {
            auto pubKey = keys->getPublicKey();
            address = Address::fromPublicKey(pubKey);
            return true;
        }
        return false;
    }
    
    std::string Wallet::signTransaction(const std::string& txData) const {
        return keys->sign(txData);
    }
    
}