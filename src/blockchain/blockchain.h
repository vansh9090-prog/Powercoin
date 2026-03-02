#ifndef POWERCOIN_BLOCKCHAIN_H
#define POWERCOIN_BLOCKCHAIN_H

#include <vector>
#include <string>
#include <memory>
#include <map>
#include <mutex>
#include <atomic>
#include <functional>
#include "block.h"
#include "transaction.h"
#include "consensus.h"

namespace powercoin {

    /**
     * Blockchain configuration parameters
     */
    struct BlockchainConfig {
        static constexpr uint32_t MAGIC_NUMBER = 0x5057524F; // "PWRO"
        static constexpr uint32_t PROTOCOL_VERSION = 70015;
        static constexpr uint32_t GENESIS_TIMESTAMP = 1735689600; // 2025-01-01
        static constexpr uint32_t TARGET_BLOCK_TIME = 600; // 10 minutes
        static constexpr uint32_t DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;
        static constexpr uint64_t INITIAL_REWARD = 50 * COIN;
        static constexpr uint32_t HALVING_INTERVAL = 210000;
        static constexpr uint64_t COIN = 100000000; // 1 PWR = 10^8 satoshis
        static constexpr uint32_t MAX_BLOCK_SIZE = 4 * 1024 * 1024; // 4 MB
        static constexpr uint32_t MAX_TRANSACTIONS_PER_BLOCK = 5000;
        static constexpr uint32_t COINBASE_MATURITY = 100;
    };

    /**
     * Blockchain state information
     */
    struct BlockchainInfo {
        uint32_t height;
        std::string bestBlockHash;
        uint32_t difficulty;
        uint64_t totalSupply;
        uint64_t mempoolSize;
        uint64_t transactions;
        double verificationProgress;
        bool isInitialBlockDownload;
        uint64_t sizeOnDisk;
        std::string chainWork;
    };

    /**
     * Main blockchain class
     * Manages chain state, validation, and synchronization
     */
    class Blockchain {
    private:
        // Chain storage
        std::vector<std::shared_ptr<Block>> chain;
        std::map<std::string, uint32_t> blockIndex; // hash -> height
        std::map<std::string, std::shared_ptr<Transaction>> mempool;
        
        // UTXO set
        std::map<std::string, std::vector<UTXO>> utxoSet;
        std::atomic<uint64_t> utxoCount;
        
        // Consensus state
        std::unique_ptr<Consensus> consensus;
        std::atomic<uint32_t> currentDifficulty;
        std::atomic<uint64_t> totalWork;
        
        // Synchronization
        std::recursive_mutex chainMutex;
        std::recursive_mutex mempoolMutex;
        std::recursive_mutex utxoMutex;
        
        // Callbacks
        std::function<void(const Block&)> onNewBlock;
        std::function<void(const Transaction&)> onNewTransaction;
        std::function<void(uint32_t, uint32_t)> onDifficultyChange;
        
        // Internal methods
        bool validateBlock(const Block& block, const Block& previousBlock) const;
        bool validateTransaction(const Transaction& tx, const std::string& blockHash = "") const;
        void updateUTXOSet(const Block& block);
        void addToBlockIndex(const Block& block);
        uint32_t calculateNextDifficulty(uint32_t timestamp, uint32_t previousTimestamp);
        uint64_t calculateBlockReward(uint32_t height) const;
        
    public:
        Blockchain();
        ~Blockchain();
        
        // Disable copy
        Blockchain(const Blockchain&) = delete;
        Blockchain& operator=(const Blockchain&) = delete;
        
        // Initialization
        bool initialize();
        bool loadFromDisk(const std::string& path);
        bool saveToDisk(const std::string& path);
        
        // Block operations
        bool addBlock(const Block& block);
        bool addBlock(const std::shared_ptr<Block>& block);
        std::shared_ptr<Block> getBlock(uint32_t height) const;
        std::shared_ptr<Block> getBlock(const std::string& hash) const;
        uint32_t getBlockHeight(const std::string& hash) const;
        std::vector<std::shared_ptr<Block>> getBlocks(uint32_t from, uint32_t to) const;
        
        // Transaction operations
        bool addTransaction(const Transaction& tx);
        bool addTransaction(const std::shared_ptr<Transaction>& tx);
        bool removeTransaction(const std::string& txHash);
        std::shared_ptr<Transaction> getTransaction(const std::string& txHash) const;
        std::vector<std::shared_ptr<Transaction>> getMempoolTransactions() const;
        void clearMempool();
        
        // UTXO operations
        std::vector<UTXO> getUTXOs(const std::string& address) const;
        uint64_t getBalance(const std::string& address) const;
        bool isUTXOSpent(const std::string& txHash, uint32_t index) const;
        
        // Mining
        Block createNewBlock(const std::string& minerAddress);
        bool submitMinedBlock(const Block& block);
        
        // Chain information
        uint32_t getHeight() const { return chain.empty() ? 0 : chain.size() - 1; }
        std::shared_ptr<Block> getGenesisBlock() const { return chain.empty() ? nullptr : chain[0]; }
        std::shared_ptr<Block> getBestBlock() const { return chain.empty() ? nullptr : chain.back(); }
        std::string getBestBlockHash() const { return chain.empty() ? "" : chain.back()->getHash(); }
        uint32_t getDifficulty() const { return currentDifficulty.load(); }
        uint64_t getTotalWork() const { return totalWork.load(); }
        uint64_t getUTXOCount() const { return utxoCount.load(); }
        size_t getMempoolSize() const { return mempool.size(); }
        
        // Blockchain statistics
        BlockchainInfo getInfo() const;
        uint64_t calculateTotalSupply() const;
        double calculateVerificationProgress() const;
        bool isInitialBlockDownload() const;
        
        // Validation
        bool validateChain() const;
        bool validateBlock(const Block& block) const;
        bool validateTransaction(const Transaction& tx) const;
        
        // Reorganization
        bool reorganizeChain(uint32_t newHeight);
        std::vector<std::shared_ptr<Block>> getOrphanBlocks() const;
        
        // Synchronization
        std::vector<std::string> getMissingBlocks() const;
        uint32_t getSyncProgress() const;
        
        // Callback registration
        void setOnNewBlock(std::function<void(const Block&)> callback);
        void setOnNewTransaction(std::function<void(const Transaction&)> callback);
        void setOnDifficultyChange(std::function<void(uint32_t, uint32_t)> callback);
        
        // Serialization
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data);
        
        // Static helpers
        static uint64_t GetBlockReward(uint32_t height);
        static uint32_t GetDifficultyAdjustmentInterval() { return BlockchainConfig::DIFFICULTY_ADJUSTMENT_INTERVAL; }
        static uint32_t GetTargetBlockTime() { return BlockchainConfig::TARGET_BLOCK_TIME; }
        static uint64_t GetCoin() { return BlockchainConfig::COIN; }
    };

} // namespace powercoin

#endif // POWERCOIN_BLOCKCHAIN_H