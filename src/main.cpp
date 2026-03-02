#include <iostream>
#include <memory>
#include <csignal>
#include <thread>
#include <chrono>
#include <atomic>
#include <fstream>

#include "config.h"
#include "blockchain/blockchain.h"
#include "blockchain/validation.h"
#include "network/node.h"
#include "wallet/wallet.h"
#include "mining/miner.h"
#include "crypto/random.h"

using namespace powercoin;

// Global instances
std::unique_ptr<Config> g_config;
std::unique_ptr<Blockchain> g_blockchain;
std::unique_ptr<Node> g_node;
std::unique_ptr<Wallet> g_wallet;
std::unique_ptr<Miner> g_miner;
std::atomic<bool> g_running{true};
std::atomic<bool> g_initialized{false};

/**
 * Signal handler for graceful shutdown
 */
void signalHandler(int signum) {
    std::cout << "\n⚠️  Interrupt signal (" << signum << ") received.\n";
    std::cout << "Shutting down gracefully...\n";
    g_running = false;
}

/**
 * Print welcome banner
 */
void printBanner() {
    std::cout << R"(
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║     ██████╗  ██████╗ ██╗    ██╗███████╗██████╗  ██████╗ ██████╗ ██╗███╗   ██╗
    ║     ██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗██╔════╝██╔═══██╗██║████╗  ██║
    ║     ██████╔╝██║   ██║██║ █╗ ██║█████╗  ██████╔╝██║     ██║   ██║██║██╔██╗ ██║
    ║     ██╔═══╝ ██║   ██║██║███╗██║██╔══╝  ██╔══██╗██║     ██║   ██║██║██║╚██╗██║
    ║     ██║     ╚██████╔╝╚███╔███╔╝███████╗██║  ██║╚██████╗╚██████╔╝██║██║ ╚████║
    ║     ╚═╝      ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝
    ║                                                                   ║
    ║                      POWER COIN (PWR) v1.0                        ║
    ║              Bitcoin-Style Blockchain with Advanced Features      ║
    ║                                                                   ║
    ║         Symbol: PWR  |  Supply: 21,000,000  |  PoW + PoS         ║
    ║     Smart Contracts | Privacy | Governance | Cross-Chain         ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝
    )" << std::endl;
}

/**
 * Print usage information
 */
void printUsage(const char* programName) {
    std::cout << "Usage: " << programName << " [options]\n";
    std::cout << "\nOptions:\n";
    std::cout << "  -n, --network <net>    Network type (mainnet, testnet, regtest)\n";
    std::cout << "  -d, --datadir <dir>    Data directory path\n";
    std::cout << "  -c, --config <file>    Configuration file path\n";
    std::cout << "  -D, --daemon           Run in daemon mode\n";
    std::cout << "  -v, --verbose          Increase verbosity (can be used multiple times)\n";
    std::cout << "  -q, --quiet            Suppress output\n";
    std::cout << "  -t, --testnet          Use testnet\n";
    std::cout << "  -r, --regtest          Use regtest\n";
    std::cout << "  -u, --rpccreds <u:p>   RPC username and password\n";
    std::cout << "  -b, --rpcbind <addr>   RPC bind address\n";
    std::cout << "  -p, --rpcport <port>   RPC port\n";
    std::cout << "  -m, --mine              Enable mining\n";
    std::cout << "  -a, --miningaddr <addr> Mining address\n";
    std::cout << "  -h, --help              Show this help\n";
    std::cout << "  -V, --version           Show version\n";
    std::cout << std::endl;
}

/**
 * Initialize all components
 */
bool initialize() {
    std::cout << "Initializing Power Coin...\n";

    // Initialize random number generator
    Random::getBytes(0); // Initialize RNG

    // Create blockchain
    std::cout << "  📦 Initializing blockchain...\n";
    g_blockchain = std::make_unique<Blockchain>();
    if (!g_blockchain->initialize()) {
        std::cerr << "Failed to initialize blockchain\n";
        return false;
    }

    // Create node
    std::cout << "  🌐 Initializing P2P node...\n";
    g_node = std::make_unique<Node>(g_config->getPort());
    if (!g_node->start()) {
        std::cerr << "Failed to start node\n";
        return false;
    }

    // Create wallet if not in daemon mode
    if (!g_config->isDaemon()) {
        std::cout << "  👛 Initializing wallet...\n";
        g_wallet = std::make_unique<Wallet>();
        
        // Try to load existing wallet
        std::string walletPath = g_config->getWalletDir() + "/" + g_config->getWalletFile();
        std::ifstream walletFile(walletPath);
        if (walletFile.good()) {
            if (!g_wallet->load(walletPath, g_config->getWalletPassword())) {
                std::cerr << "Failed to load wallet\n";
            }
        } else {
            std::cout << "  No existing wallet found. Create one using the wallet command.\n";
        }
    }

    // Create miner if enabled
    if (g_config->isMiningEnabled()) {
        std::cout << "  ⛏️  Initializing miner...\n";
        
        MiningConfig miningCfg;
        MinerConfig minerCfg;
        minerCfg.minerAddress = g_config->getMiningAddress();
        minerCfg.numThreads = g_config->getMiningThreads();
        
        g_miner = std::make_unique<Miner>(minerCfg, miningCfg);
        if (!g_miner->initialize(g_blockchain.get(), g_wallet.get())) {
            std::cerr << "Failed to initialize miner\n";
            return false;
        }
    }

    g_initialized = true;
    std::cout << "✅ Initialization complete!\n";
    return true;
}

/**
 * Shutdown all components
 */
void shutdown() {
    std::cout << "\n🛑 Shutting down...\n";

    if (g_miner) {
        std::cout << "  ⛏️  Stopping miner...\n";
        g_miner->stop();
    }

    if (g_node) {
        std::cout << "  🌐 Stopping node...\n";
        g_node->stop();
    }

    if (g_wallet) {
        std::cout << "  👛 Saving wallet...\n";
        std::string walletPath = g_config->getWalletDir() + "/" + g_config->getWalletFile();
        g_wallet->save(walletPath, g_config->getWalletPassword());
    }

    if (g_blockchain) {
        std::cout << "  📦 Saving blockchain...\n";
        g_blockchain->saveToDisk(g_config->getChainFile());
    }

    std::cout << "✅ Shutdown complete. Goodbye!\n";
}

/**
 * Interactive console mode
 */
void interactiveMode() {
    std::string command;
    
    while (g_running) {
        std::cout << "\nPWR> ";
        std::getline(std::cin, command);
        
        if (command == "exit" || command == "quit") {
            g_running = false;
            break;
        } else if (command == "help") {
            std::cout << "\nAvailable commands:\n";
            std::cout << "  help                 Show this help\n";
            std::cout << "  info                 Show blockchain info\n";
            std::cout << "  wallet               Show wallet info\n";
            std::cout << "  newwallet            Create new wallet\n";
            std::cout << "  balance              Check wallet balance\n";
            std::cout << "  send <addr> <amount> Send PWR to address\n";
            std::cout << "  receive              Show receive address\n";
            std::cout << "  mine <start/stop>    Start/stop mining\n";
            std::cout << "  peers                Show connected peers\n";
            std::cout << "  mempool              Show mempool status\n";
            std::cout << "  config               Show configuration\n";
            std::cout << "  exit                 Exit program\n";
        } else if (command == "info") {
            auto info = g_blockchain->getInfo();
            std::cout << "\n📊 Blockchain Info:\n";
            std::cout << "  Height: " << info.height << "\n";
            std::cout << "  Best Block: " << info.bestBlockHash.substr(0, 20) << "...\n";
            std::cout << "  Difficulty: " << info.difficulty << "\n";
            std::cout << "  Supply: " << info.totalSupply / BlockchainConfig::COIN << " PWR\n";
            std::cout << "  Mempool: " << info.mempoolSize << " transactions\n";
        } else if (command == "wallet") {
            if (!g_wallet) {
                std::cout << "❌ No wallet loaded\n";
            } else {
                std::cout << "\n👛 Wallet Info:\n";
                std::cout << "  Address: " << g_wallet->getAddress() << "\n";
                std::cout << "  Status: " << (g_wallet->isLocked() ? "Locked" : "Unlocked") << "\n";
            }
        } else if (command == "newwallet") {
            g_wallet = std::make_unique<Wallet>();
            auto keys = g_wallet->createNewWallet();
            std::cout << "\n✅ New wallet created!\n";
            std::cout << "  Address: " << keys.address << "\n";
            std::cout << "  Private Key: " << keys.privateKey << "\n";
            std::cout << "⚠️  SAVE YOUR PRIVATE KEY SAFELY!\n";
        } else if (command == "balance") {
            if (!g_wallet) {
                std::cout << "❌ No wallet loaded\n";
            } else {
                uint64_t balance = g_blockchain->getBalance(g_wallet->getAddress());
                std::cout << "\n💰 Balance: " << balance / BlockchainConfig::COIN << "." 
                         << std::setfill('0') << std::setw(8) << (balance % BlockchainConfig::COIN) << " PWR\n";
            }
        } else if (command.substr(0, 4) == "send") {
            // Parse send command
            size_t space1 = command.find(' ', 5);
            size_t space2 = command.find(' ', space1 + 1);
            if (space1 != std::string::npos && space2 != std::string::npos) {
                std::string addr = command.substr(5, space1 - 5);
                uint64_t amount = std::stoull(command.substr(space1 + 1)) * BlockchainConfig::COIN;
                
                if (!g_wallet) {
                    std::cout << "❌ No wallet loaded\n";
                } else {
                    auto tx = g_wallet->createTransaction(addr, amount);
                    if (g_wallet->signTransaction(tx) && g_wallet->sendTransaction(tx)) {
                        std::cout << "✅ Transaction sent: " << tx.getHash() << "\n";
                    } else {
                        std::cout << "❌ Failed to send transaction\n";
                    }
                }
            }
        } else if (command == "receive") {
            if (!g_wallet) {
                std::cout << "❌ No wallet loaded\n";
            } else {
                std::cout << "\n📥 Receive Address:\n";
                std::cout << "  " << g_wallet->getAddress() << "\n";
            }
        } else if (command == "mine start") {
            if (!g_miner) {
                std::cout << "❌ Miner not initialized\n";
            } else {
                g_miner->start();
                std::cout << "⛏️  Mining started\n";
            }
        } else if (command == "mine stop") {
            if (!g_miner) {
                std::cout << "❌ Miner not initialized\n";
            } else {
                g_miner->stop();
                std::cout << "⏹️  Mining stopped\n";
            }
        } else if (command == "peers") {
            auto peers = g_node->getPeerInfo();
            std::cout << "\n🔗 Connected Peers (" << peers.size() << "):\n";
            for (const auto& peer : peers) {
                std::cout << "  " << peer << "\n";
            }
        } else if (command == "mempool") {
            auto mempool = g_blockchain->getMempoolTransactions();
            std::cout << "\n📜 Mempool (" << mempool.size() << " transactions):\n";
            for (const auto& tx : mempool) {
                std::cout << "  " << tx->getHash().substr(0, 20) << "...\n";
            }
        } else if (command == "config") {
            g_config->print();
        } else if (!command.empty()) {
            std::cout << "Unknown command. Type 'help' for available commands.\n";
        }
    }
}

/**
 * Daemon mode
 */
void daemonMode() {
    std::cout << "Running in daemon mode...\n";
    
    // Fork process
    pid_t pid = fork();
    if (pid < 0) {
        std::cerr << "Failed to fork daemon process\n";
        return;
    }
    
    if (pid > 0) {
        // Parent process exits
        std::cout << "Daemon started with PID: " << pid << "\n";
        return;
    }
    
    // Child process continues
    umask(0);
    
    // Create new session
    if (setsid() < 0) {
        std::cerr << "Failed to create new session\n";
        return;
    }
    
    // Change to root directory
    chdir("/");
    
    // Close standard file descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    // Write PID file
    std::ofstream pidFile(g_config->getPidFile());
    if (pidFile.is_open()) {
        pidFile << getpid() << "\n";
        pidFile.close();
    }
    
    // Main daemon loop
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        
        // Update statistics every minute
        static time_t lastStats = 0;
        time_t now = time(nullptr);
        if (now - lastStats >= 60) {
            lastStats = now;
            // Log stats
        }
    }
    
    // Remove PID file
    remove(g_config->getPidFile().c_str());
}

/**
 * Main entry point
 */
int main(int argc, char** argv) {
    // Set signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    // Print banner
    printBanner();
    
    // Load configuration
    g_config = std::make_unique<Config>();
    if (!g_config->load(argc, argv)) {
        printUsage(argv[0]);
        return 1;
    }
    
    // Print configuration
    if (g_config->getVerbosity() > 0) {
        g_config->print();
    }
    
    // Validate configuration
    if (!g_config->validate()) {
        std::cerr << "Configuration validation failed\n";
        return 1;
    }
    
    // Initialize components
    if (!initialize()) {
        std::cerr << "Initialization failed\n";
        return 1;
    }
    
    // Run in appropriate mode
    if (g_config->isDaemon()) {
        daemonMode();
    } else {
        interactiveMode();
    }
    
    // Shutdown
    shutdown();
    
    return 0;
}