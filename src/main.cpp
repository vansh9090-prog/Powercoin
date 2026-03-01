#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include "config.h"
#include "network/node.h"
#include "wallet/wallet.h"

using namespace PowerCoin;

class PowerCoinApp {
private:
    std::unique_ptr<Node> node;
    std::unique_ptr<Wallet> wallet;
    bool running;

    void printMenu() {
        std::cout << "\n=== POWER COIN (PWR) ===\n";
        std::cout << "1. Create Wallet\n";
        std::cout << "2. Load Wallet\n";
        std::cout << "3. Check Balance\n";
        std::cout << "4. Start Mining\n";
        std::cout << "5. Stop Mining\n";
        std::cout << "6. Blockchain Info\n";
        std::cout << "7. Exit\n";
        std::cout << "Choice: ";
    }

public:
    PowerCoinApp() : running(true) {
        node = std::make_unique<Node>();
    }

    void run() {
        std::cout << "\n🚀 Starting Power Coin Node...\n";
        node->start();

        while (running) {
            printMenu();
            std::string choice;
            std::cin >> choice;

            if (choice == "1") {
                wallet = std::make_unique<Wallet>();
                auto keys = wallet->createNewWallet();
                std::cout << "\n✅ Wallet Created!\n";
                std::cout << "Address: " << keys.address << "\n";
                std::cout << "Private Key: " << keys.privateKey << "\n";
            }
            else if (choice == "2") {
                std::string key;
                std::cout << "Enter private key: ";
                std::cin >> key;
                wallet = std::make_unique<Wallet>();
                if (wallet->loadFromPrivateKey(key)) {
                    std::cout << "✅ Wallet loaded: " << wallet->getAddress() << "\n";
                } else {
                    std::cout << "❌ Invalid key\n";
                }
            }
            else if (choice == "3") {
                if (wallet) {
                    double balance = node->getBalance(wallet->getAddress());
                    std::cout << "💰 Balance: " << balance << " PWR\n";
                } else {
                    std::cout << "❌ Load wallet first\n";
                }
            }
            else if (choice == "4") {
                if (wallet) {
                    node->startMining(wallet->getAddress());
                    std::cout << "⛏️ Mining started\n";
                } else {
                    std::cout << "❌ Load wallet first\n";
                }
            }
            else if (choice == "5") {
                node->stopMining();
                std::cout << "⏹️ Mining stopped\n";
            }
            else if (choice == "6") {
                auto info = node->getBlockchainInfo();
                std::cout << "\n📊 Blockchain Info\n";
                std::cout << "Blocks: " << info.blocks << "\n";
                std::cout << "Difficulty: " << info.difficulty << "\n";
                std::cout << "Supply: " << info.totalSupply << " PWR\n";
            }
            else if (choice == "7") {
                running = false;
                node->stop();
                std::cout << "👋 Goodbye!\n";
            }
        }
    }
};

int main() {
    PowerCoinApp app;
    app.run();
    return 0;
}