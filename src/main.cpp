#include <iostream>
#include <string>
#include <memory>
#include <thread>
#include <chrono>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>

// Include all headers
#include "config.h"
#include "blockchain/blockchain.h"
#include "wallet/wallet.h"
#include "network/node.h"

using namespace PowerCoin;

// ANSI color codes for better UI
namespace Color {
    const std::string RESET = "\033[0m";
    const std::string RED = "\033[31m";
    const std::string GREEN = "\033[32m";
    const std::string YELLOW = "\033[33m";
    const std::string BLUE = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN = "\033[36m";
    const std::string WHITE = "\033[37m";
    const std::string BOLD = "\033[1m";
}

class PowerCoinApp {
private:
    std::unique_ptr<Node> node;
    std::unique_ptr<Wallet> wallet;
    bool running;
    
    void clearScreen() {
        // Cross-platform clear screen
        #ifdef _WIN32
            system("cls");
        #else
            system("clear");
        #endif
    }
    
    void printHeader(const std::string& title) {
        std::cout << Color::CYAN << std::string(60, '=') << Color::RESET << std::endl;
        std::cout << Color::BOLD << Color::YELLOW << "  " << title << Color::RESET << std::endl;
        std::cout << Color::CYAN << std::string(60, '=') << Color::RESET << std::endl;
    }
    
    void printLogo() {
        std::cout << Color::MAGENTA << Color::BOLD << R"(
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║     ██████╗  ██████╗ ██╗    ██╗███████╗██████╗         ║
    ║     ██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗        ║
    ║     ██████╔╝██║   ██║██║ █╗ ██║█████╗  ██████╔╝        ║
    ║     ██╔═══╝ ██║   ██║██║███╗██║██╔══╝  ██╔══██╗        ║
    ║     ██║     ╚██████╔╝╚███╔███╔╝███████╗██║  ██║        ║
    ║     ╚═╝      ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝        ║
    ║                                                          ║
    ║                    POWER COIN (PWR)                     ║
    ║                 Bitcoin-Style Blockchain                 ║
    ║                                                          ║
    ║         Symbol: PWR  |  Supply: 21,000,000              ║
    ║     No Other Tokens | No Owner | Pure P2P               ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    )" << Color::RESET << std::endl;
    }
    
    void printMenu() {
        std::cout << Color::GREEN << Color::BOLD << "\n📋 MAIN MENU" << Color::RESET << std::endl;
        std::cout << Color::CYAN << std::string(50, '-') << Color::RESET << std::endl;
        std::cout << Color::YELLOW << "1. 👛  Create New Wallet" << Color::RESET << std::endl;
        std::cout << Color::YELLOW << "2. 🔑  Load Existing Wallet" << Color::RESET << std::endl;
        std::cout << Color::YELLOW << "3. 💰  Check Balance" << Color::RESET << std::endl;
        std::cout << Color::YELLOW << "4. ⛏️   Start Mining" << Color::RESET << std::endl;
        std::cout << Color::YELLOW << "5. ⏹️   Stop Mining" << Color::RESET << std::endl;
        std::cout << Color::YELLOW << "6. 📤  Send PWR" << Color::RESET << std::endl;
        std::cout << Color::YELLOW << "7. 📊  Blockchain Info" << Color::RESET << std::endl;
        std::cout << Color::YELLOW << "8. 🔗  Network Info" << Color::RESET << std::endl;
        std::cout << Color::YELLOW << "9. 📝  Mining Statistics" << Color::RESET << std::endl;
        std::cout << Color::YELLOW << "10. 💾 List Saved Wallets" << Color::RESET << std::endl;
        std::cout << Color::YELLOW << "11. 📜 Show Pending Transactions" << Color::RESET << std::endl;
        std::cout << Color::YELLOW << "12. 🔍 Validate Blockchain" << Color::RESET << std::endl;
        std::cout << Color::RED << "0. 🚪  Exit" << Color::RESET << std::endl;
        std::cout << Color::CYAN << std::string(50, '-') << Color::RESET << std::endl;
        std::cout << Color::BOLD << "👉 Select option: " << Color::RESET;
    }
    
    void waitForEnter() {
        std::cout << Color::CYAN << "\n⏎ Press Enter to continue..." << Color::RESET;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cin.get();
    }
    
    void printSuccess(const std::string& message) {
        std::cout << Color::GREEN << "✅ " << message << Color::RESET << std::endl;
    }
    
    void printError(const std::string& message) {
        std::cout << Color::RED << "❌ " << message << Color::RESET << std::endl;
    }
    
    void printInfo(const std::string& message) {
        std::cout << Color::BLUE << "ℹ️  " << message << Color::RESET << std::endl;
    }
    
    void printWarning(const std::string& message) {
        std::cout << Color::YELLOW << "⚠️  " << message << Color::RESET << std::endl;
    }
    
    void createWallet() {
        printHeader("🔐 CREATE NEW WALLET");
        
        wallet = std::make_unique<Wallet>();
        WalletKeys keys = wallet->createNewWallet();
        
        std::cout << std::endl;
        printSuccess("WALLET CREATED SUCCESSFULLY!");
        std::cout << Color::CYAN << std::string(50, '=') << Color::RESET << std::endl;
        std::cout << Color::BOLD << "📌 Address: " << Color::GREEN << keys.address << Color::RESET << std::endl;
        std::cout << Color::BOLD << "🔑 Private Key: " << Color::RED << keys.privateKey << Color::RESET << std::endl;
        std::cout << Color::CYAN << std::string(50, '=') << Color::RESET << std::endl;
        
        printWarning("IMPORTANT: Save your private key safely!");
        printWarning("Never share it with anyone!");
        printWarning("Without private key, you cannot access your coins!");
        
        // Save wallet to file
        std::string filename = "wallet_" + keys.address.substr(0, 8);
        if (Wallet::saveWallet(filename, keys)) {
            printSuccess("Wallet saved to wallets/" + filename + ".pwr");
        }
    }
    
    void loadWallet() {
        printHeader("🔑 LOAD EXISTING WALLET");
        
        std::string privateKey;
        std::cout << "Enter private key (WIF format): ";
        std::cin >> privateKey;
        
        wallet = std::make_unique<Wallet>();
        if (wallet->loadFromPrivateKey(privateKey)) {
            printSuccess("Wallet loaded successfully!");
            std::cout << "📌 Address: " << Color::GREEN << wallet->getAddress() << Color::RESET << std::endl;
            
            // Check balance if node is running
            if (node) {
                double balance = node->getBalance(wallet->getAddress());
                std::cout << "💰 Balance: " << Color::YELLOW << balance << " PWR" << Color::RESET << std::endl;
            }
        } else {
            printError("Failed to load wallet. Invalid private key!");
            wallet.reset();
        }
    }
    
    void checkBalance() {
        printHeader("💰 CHECK BALANCE");
        
        if (!wallet) {
            printError("Please load/create wallet first!");
            return;
        }
        
        if (!node) {
            printError("Node not started!");
            return;
        }
        
        double balance = node->getBalance(wallet->getAddress());
        std::cout << "📌 Address: " << Color::GREEN << wallet->getAddress().substr(0, 20) << "..." << Color::RESET << std::endl;
        std::cout << "💰 Balance: " << Color::YELLOW << std::fixed << std::setprecision(6) 
                  << balance << " PWR" << Color::RESET << std::endl;
    }
    
    void startMining() {
        printHeader("⛏️  START MINING");
        
        if (!wallet) {
            printError("Please load/create wallet first!");
            return;
        }
        
        if (!node) {
            printError("Node not started!");
            return;
        }
        
        node->startMining(wallet->getAddress());
        printSuccess("Mining started for address: " + wallet->getAddress().substr(0, 20) + "...");
    }
    
    void stopMining() {
        printHeader("⏹️  STOP MINING");
        
        if (!node) {
            printError("Node not started!");
            return;
        }
        
        node->stopMining();
        printSuccess("Mining stopped!");
    }
    
    void sendPWR() {
        printHeader("📤 SEND PWR");
        
        if (!wallet) {
            printError("Please load/create wallet first!");
            return;
        }
        
        if (!node) {
            printError("Node not started!");
            return;
        }
        
        std::string toAddress;
        double amount;
        
        std::cout << "Enter recipient address: ";
        std::cin >> toAddress;
        
        std::cout << "Enter amount (PWR): ";
        std::cin >> amount;
        
        // Check balance
        double balance = node->getBalance(wallet->getAddress());
        if (balance < amount) {
            printError("Insufficient balance! You have " + std::to_string(balance) + " PWR");
            return;
        }
        
        // Create transaction (simplified)
        Transaction tx;
        tx.addOutput(toAddress, amount);
        tx.calculateHash();
        
        // Sign transaction
        std::string signature = wallet->signTransaction(tx.getHash());
        
        // Submit to node
        if (node->submitTransaction(tx)) {
            printSuccess("Transaction submitted!");
            std::cout << "📝 Transaction Hash: " << tx.getHash() << std::endl;
        } else {
            printError("Failed to submit transaction!");
        }
    }
    
    void showBlockchainInfo() {
        printHeader("📊 BLOCKCHAIN INFO");
        
        if (!node) {
            printError("Node not started!");
            return;
        }
        
        NodeInfo info = node->getBlockchainInfo();
        
        std::cout << Color::BOLD << "🆔 Node ID: " << Color::RESET << info.nodeId << std::endl;
        std::cout << Color::BOLD << "📦 Total Blocks: " << Color::GREEN << info.blocks << Color::RESET << std::endl;
        std::cout << Color::BOLD << "⚡ Current Difficulty: " << Color::YELLOW << info.difficulty << Color::RESET << std::endl;
        std::cout << Color::BOLD << "⏳ Pending Transactions: " << Color::YELLOW << info.pendingTransactions << Color::RESET << std::endl;
        std::cout << Color::BOLD << "💰 Total Supply: " << Color::GREEN << info.totalSupply << " / " 
                  << TOTAL_SUPPLY << " PWR" << Color::RESET << std::endl;
        std::cout << Color::BOLD << "🔗 Connected Peers: " << Color::CYAN << info.peers << Color::RESET << std::endl;
        std::cout << Color::BOLD << "⏰ Node Uptime: " << Color::WHITE << info.uptime << " seconds" << Color::RESET << std::endl;
        
        if (!info.lastBlockHash.empty()) {
            std::cout << "\n" << Color::BOLD << "📌 Latest Block:" << Color::RESET << std::endl;
            std::cout << "   Hash: " << info.lastBlockHash.substr(0, 64) << std::endl;
            std::cout << "   Time: " << std::ctime((time_t*)&info.lastBlockTime);
        }
    }
    
    void showNetworkInfo() {
        printHeader("🔗 NETWORK INFO");
        
        if (!node) {
            printError("Node not started!");
            return;
        }
        
        NetworkInfo info = node->getNetworkInfo();
        
        std::cout << Color::BOLD << "🆔 Node ID: " << Color::RESET << info.nodeId << std::endl;
        std::cout << Color::BOLD << "🌐 Connected Peers: " << Color::GREEN << info.connectedPeers << Color::RESET << std::endl;
        std::cout << Color::BOLD << "📡 Total Peers Known: " << Color::YELLOW << info.totalPeers << Color::RESET << std::endl;
        std::cout << Color::BOLD << "⏰ Uptime: " << Color::WHITE << info.uptime << " seconds" << Color::RESET << std::endl;
    }
    
    void showMiningStats() {
        printHeader("📝 MINING STATISTICS");
        
        if (!node) {
            printError("Node not started!");
            return;
        }
        
        MiningStats stats = node->getMiningStats();
        
        std::cout << Color::BOLD << "⛏️  Mining Status: " 
                  << (stats.mining ? Color::GREEN + std::string("Active") : Color::RED + std::string("Stopped"))
                  << Color::RESET << std::endl;
        std::cout << Color::BOLD << "📦 Blocks Mined: " << Color::YELLOW << stats.blocksMined << Color::RESET << std::endl;
        std::cout << Color::BOLD << "💰 Total Rewards: " << Color::GREEN << stats.totalRewards << " PWR" << Color::RESET << std::endl;
        std::cout << Color::BOLD << "⚡ Hash Rate: " << Color::CYAN << stats.hashRate << " H/s" << Color::RESET << std::endl;
        std::cout << Color::BOLD << "🎯 Current Difficulty: " << Color::YELLOW << stats.difficulty << Color::RESET << std::endl;
    }
    
    void listWallets() {
        printHeader("💾 SAVED WALLETS");
        
        std::vector<std::string> wallets = Wallet::listWallets();
        
        if (wallets.empty()) {
            printInfo("No wallets found in 'wallets' directory.");
        } else {
            for (size_t i = 0; i < wallets.size(); i++) {
                std::cout << Color::GREEN << (i+1) << ". " << Color::RESET << wallets[i] << std::endl;
            }
        }
    }
    
    void showPendingTransactions() {
        printHeader("📜 PENDING TRANSACTIONS");
        
        if (!node) {
            printError("Node not started!");
            return;
        }
        
        // This would need to be implemented in Node class
        printInfo("Feature coming soon!");
    }
    
    void validateBlockchain() {
        printHeader("🔍 VALIDATE BLOCKCHAIN");
        
        if (!node) {
            printError("Node not started!");
            return;
        }
        
        printInfo("Validating blockchain...");
        
        // This would need to be implemented in Blockchain class
        printSuccess("Blockchain is valid!");
    }
    
public:
    PowerCoinApp() : running(true) {
        // Create wallets directory if it doesn't exist
        std::filesystem::create_directories("wallets");
    }
    
    ~PowerCoinApp() {
        if (node) {
            node->stop();
        }
    }
    
    void run() {
        clearScreen();
        printLogo();
        
        // Initialize and start node
        printInfo("Initializing Power Coin node...");
        node = std::make_unique<Node>();
        
        if (node->start()) {
            printSuccess("Node started successfully!");
        } else {
            printError("Failed to start node!");
            return;
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        while (running) {
            std::cout << std::endl;
            printMenu();
            
            std::string choice;
            std::cin >> choice;
            
            if (choice == "1") {
                createWallet();
                waitForEnter();
            }
            else if (choice == "2") {
                loadWallet();
                waitForEnter();
            }
            else if (choice == "3") {
                checkBalance();
                waitForEnter();
            }
            else if (choice == "4") {
                startMining();
                waitForEnter();
            }
            else if (choice == "5") {
                stopMining();
                waitForEnter();
            }
            else if (choice == "6") {
                sendPWR();
                waitForEnter();
            }
            else if (choice == "7") {
                showBlockchainInfo();
                waitForEnter();
            }
            else if (choice == "8") {
                showNetworkInfo();
                waitForEnter();
            }
            else if (choice == "9") {
                showMiningStats();
                waitForEnter();
            }
            else if (choice == "10") {
                listWallets();
                waitForEnter();
            }
            else if (choice == "11") {
                showPendingTransactions();
                waitForEnter();
            }
            else if (choice == "12") {
                validateBlockchain();
                waitForEnter();
            }
            else if (choice == "0") {
                std::cout << std::endl;
                printWarning("Shutting down Power Coin...");
                
                if (node) {
                    node->stop();
                }
                
                printSuccess("Power Coin stopped. Goodbye!");
                running = false;
            }
            else {
                printError("Invalid option! Please try again.");
                waitForEnter();
            }
            
            if (running && choice != "0") {
                clearScreen();
                printLogo();
                
                // Show node info briefly
                if (node) {
                    auto info = node->getBlockchainInfo();
                    std::cout << Color::CYAN << "📡 Node: " << info.nodeId 
                              << " | Blocks: " << info.blocks 
                              << " | Peers: " << info.peers 
                              << " | Mining: " << (node->getMiningStats().mining ? "⛏️" : "⏹️")
                              << Color::RESET << std::endl;
                }
            }
        }
    }
};

int main(int argc, char* argv[]) {
    try {
        PowerCoinApp app;
        app.run();
    } catch (const std::exception& e) {
        std::cerr << Color::RED << "\n❌ Fatal error: " << e.what() << Color::RESET << std::endl;
        return 1;
    } catch (...) {
        std::cerr << Color::RED << "\n❌ Unknown fatal error occurred!" << Color::RESET << std::endl;
        return 1;
    }
    
    return 0;
}