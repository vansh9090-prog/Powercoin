#include "wallet.h"
#include "address.h"
#include <fstream>
#include <iostream>
#include <filesystem>
#include <sstream>

namespace PowerCoin {
    
    Wallet::Wallet() {
        keys = std::make_unique<Keys>();
    }
    
    Wallet::~Wallet() = default;
    
    WalletKeys Wallet::createNewWallet() {
        keys->generateKeyPair();
        
        WalletKeys walletKeys;
        walletKeys.privateKey = keys->exportPrivateKeyWIF();
        walletKeys.publicKey = keys->exportPublicKey();
        
        // Generate address from public key
        std::vector<uint8_t> pubKeyBytes;
        for (char c : walletKeys.publicKey) {
            pubKeyBytes.push_back(static_cast<uint8_t>(c));
        }
        address = Address::fromPublicKey(pubKeyBytes);
        walletKeys.address = address;
        
        return walletKeys;
    }
    
    bool Wallet::loadFromPrivateKey(const std::string& privateKeyWIF) {
        if (keys->importPrivateKey(privateKeyWIF)) {
            std::vector<uint8_t> pubKeyBytes = keys->getPublicKey();
            address = Address::fromPublicKey(pubKeyBytes);
            return true;
        }
        return false;
    }
    
    std::string Wallet::signTransaction(const std::string& txData) const {
        return keys->sign(txData);
    }
    
    std::vector<std::string> Wallet::listWallets() {
        std::vector<std::string> wallets;
        
        namespace fs = std::filesystem;
        fs::path walletDir = "wallets";
        
        if (fs::exists(walletDir)) {
            for (const auto& entry : fs::directory_iterator(walletDir)) {
                if (entry.path().extension() == ".pwr") {
                    wallets.push_back(entry.path().filename().string());
                }
            }
        }
        
        return wallets;
    }
    
    bool Wallet::saveWallet(const std::string& filename, const WalletKeys& keys) {
        namespace fs = std::filesystem;
        fs::create_directories("wallets");
        
        std::ofstream file("wallets/" + filename + ".pwr");
        if (!file.is_open()) return false;
        
        file << "POWER COIN WALLET\n";
        file << "================\n";
        file << "Address: " << keys.address << "\n";
        file << "Private Key: " << keys.privateKey << "\n";
        file << "Public Key: " << keys.publicKey << "\n";
        file << "================\n";
        file << "⚠️  NEVER SHARE YOUR PRIVATE KEY!\n";
        
        file.close();
        return true;
    }
    
    WalletKeys Wallet::loadWallet(const std::string& filename) {
        WalletKeys keys;
        
        std::ifstream file("wallets/" + filename);
        if (file.is_open()) {
            std::string line;
            while (std::getline(file, line)) {
                if (line.find("Address:") == 0) {
                    keys.address = line.substr(9);
                } else if (line.find("Private Key:") == 0) {
                    keys.privateKey = line.substr(13);
                } else if (line.find("Public Key:") == 0) {
                    keys.publicKey = line.substr(12);
                }
            }
            file.close();
        }
        
        return keys;
    }
    
}