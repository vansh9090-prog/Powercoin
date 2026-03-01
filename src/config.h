#ifndef POWERCOIN_CONFIG_H
#define POWERCOIN_CONFIG_H

#include <string>
#include <vector>

// Power Coin Configuration - Bitcoin style
namespace PowerCoin {
    
    // Coin Information
    const std::string COIN_NAME = "Power Coin";
    const std::string COIN_SYMBOL = "PWR";
    const uint64_t TOTAL_SUPPLY = 21000000;  // 21 million (like Bitcoin)
    const uint64_t INITIAL_BLOCK_REWARD = 50;  // 50 PWR per block
    const uint32_t HALVING_INTERVAL = 210000;  // Halving every 210,000 blocks
    
    // Blockchain Parameters
    const uint32_t INITIAL_DIFFICULTY = 4;  // 4 leading zeros
    const uint32_t BLOCK_TIME_TARGET = 600;  // 10 minutes (in seconds)
    const uint32_t DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;  // Adjust every 2016 blocks
    const uint32_t MAX_BLOCK_SIZE = 1000000;  // 1 MB
    const uint32_t MAX_TRANSACTIONS_PER_BLOCK = 2000;
    
    // Network
    const uint16_t P2P_PORT = 8333;  // Default P2P port
    const uint32_t MAX_PEERS = 125;
    const uint32_t CONNECTION_TIMEOUT = 30;  // seconds
    
    // Mining
    const uint32_t COINBASE_MATURITY = 100;  // Blocks before coinbase can be spent
    const double MIN_TRANSACTION_FEE = 0.0001;  // Minimum fee in PWR
    
    // Features
    const bool NO_OTHER_TOKENS = true;  // Only PWR tokens allowed
    const bool NO_OWNER = true;  // No central owner
    const bool P2P_ONLY = true;  // Pure P2P
    
    // File paths
    const std::string CHAIN_FILE = "blockchain.dat";
    const std::string MEMPOOL_FILE = "mempool.dat";
    const std::string WALLET_DIR = "wallets/";
    
}

#endif // POWERCOIN_CONFIG_H