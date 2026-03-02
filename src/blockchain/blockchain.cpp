#include "blockchain.h"
#include "../crypto/sha256.h"
#include "../crypto/ripemd160.h"
#include "../database/leveldb.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>

namespace powercoin {

    Blockchain::Blockchain() 
        : utxoCount(0),
          currentDifficulty(1),
          totalWork(0) {
        consensus = std::make_unique<Consensus>();
    }

    Blockchain::~Blockchain() {
        saveToDisk("blockchain.dat");
    }

    bool Blockchain::initialize() {
        std::lock_guard<std::recursive_mutex> lock(chainMutex);
        
        if (!chain.empty()) {
            return true; // Already initialized
        }

        // Create genesis block
        auto genesis = std::make_shared<Block>();
        genesis->setVersion(1);
        genesis->setPreviousHash(std::string(64, '0'));
        genesis->setTimestamp(BlockchainConfig::GENESIS_TIMESTAMP);
        genesis->setDifficulty(1);
        genesis->setNonce(0);

        // Genesis coinbase transaction
        Transaction coinbase;
        coinbase.setType(TransactionType::COINBASE);
        coinbase.addOutput("PWRGenesisAddress", BlockchainConfig::INITIAL_REWARD);
        coinbase.calculateHash();
        genesis->addTransaction(coinbase);
        genesis->calculateMerkleRoot();
        genesis->calculateHash();

        chain.push_back(genesis);
        addToBlockIndex(*genesis);
        updateUTXOSet(*genesis);
        totalWork += genesis->getWork();

        return true;
    }

    bool Blockchain::addBlock(const Block& block) {
        std::lock_guard<std::recursive_mutex> lock(chainMutex);
        
        auto blockPtr = std::make_shared<Block>(block);
        return addBlock(blockPtr);
    }

    bool Blockchain::addBlock(const std::shared_ptr<Block>& block) {
        if (!block) return false;

        // Check if block already exists
        if (blockIndex.find(block->getHash()) != blockIndex.end()) {
            return false; // Block already in chain
        }

        // Get previous block
        auto prevBlock = getBlock(block->getPreviousHash());
        if (!prevBlock) {
            // Orphan block - store for later
            // TODO: Implement orphan block storage
            return false;
        }

        // Validate block
        if (!validateBlock(*block, *prevBlock)) {
            return false;
        }

        // Add to chain
        uint32_t newHeight = prevBlock->getHeight() + 1;
        block->setHeight(newHeight);
        
        chain.push_back(block);
        addToBlockIndex(*block);
        updateUTXOSet(*block);
        
        // Update total work
        totalWork += block->getWork();

        // Adjust difficulty if needed
        if (newHeight % BlockchainConfig::DIFFICULTY_ADJUSTMENT_INTERVAL == 0) {
            uint32_t oldDifficulty = currentDifficulty.load();
            uint32_t newDifficulty = calculateNextDifficulty(
                block->getTimestamp(),
                chain[newHeight - BlockchainConfig::DIFFICULTY_ADJUSTMENT_INTERVAL]->getTimestamp()
            );
            currentDifficulty = newDifficulty;
            
            if (onDifficultyChange) {
                onDifficultyChange(oldDifficulty, newDifficulty);
            }
        }

        // Remove transactions from mempool
        for (const auto& tx : block->getTransactions()) {
            if (tx.getType() != TransactionType::COINBASE) {
                removeTransaction(tx.getHash());
            }
        }

        // Trigger callback
        if (onNewBlock) {
            onNewBlock(*block);
        }

        return true;
    }

    std::shared_ptr<Block> Blockchain::getBlock(uint32_t height) const {
        std::lock_guard<std::recursive_mutex> lock(chainMutex);
        
        if (height < chain.size()) {
            return chain[height];
        }
        return nullptr;
    }

    std::shared_ptr<Block> Blockchain::getBlock(const std::string& hash) const {
        auto it = blockIndex.find(hash);
        if (it != blockIndex.end()) {
            return getBlock(it->second);
        }
        return nullptr;
    }

    uint32_t Blockchain::getBlockHeight(const std::string& hash) const {
        auto it = blockIndex.find(hash);
        return (it != blockIndex.end()) ? it->second : UINT32_MAX;
    }

    std::vector<std::shared_ptr<Block>> Blockchain::getBlocks(uint32_t from, uint32_t to) const {
        std::lock_guard<std::recursive_mutex> lock(chainMutex);
        
        std::vector<std::shared_ptr<Block>> result;
        from = std::min(from, static_cast<uint32_t>(chain.size()));
        to = std::min(to, static_cast<uint32_t>(chain.size()));
        
        for (uint32_t i = from; i < to; ++i) {
            result.push_back(chain[i]);
        }
        return result;
    }

    bool Blockchain::addTransaction(const Transaction& tx) {
        return addTransaction(std::make_shared<Transaction>(tx));
    }

    bool Blockchain::addTransaction(const std::shared_ptr<Transaction>& tx) {
        if (!tx) return false;

        std::lock_guard<std::recursive_mutex> lock(mempoolMutex);

        // Check if already in mempool
        if (mempool.find(tx->getHash()) != mempool.end()) {
            return false;
        }

        // Validate transaction
        if (!validateTransaction(*tx)) {
            return false;
        }

        mempool[tx->getHash()] = tx;

        // Trigger callback
        if (onNewTransaction) {
            onNewTransaction(*tx);
        }

        return true;
    }

    bool Blockchain::removeTransaction(const std::string& txHash) {
        std::lock_guard<std::recursive_mutex> lock(mempoolMutex);
        
        auto it = mempool.find(txHash);
        if (it != mempool.end()) {
            mempool.erase(it);
            return true;
        }
        return false;
    }

    std::shared_ptr<Transaction> Blockchain::getTransaction(const std::string& txHash) const {
        std::lock_guard<std::recursive_mutex> lock(mempoolMutex);
        
        auto it = mempool.find(txHash);
        if (it != mempool.end()) {
            return it->second;
        }
        return nullptr;
    }

    std::vector<std::shared_ptr<Transaction>> Blockchain::getMempoolTransactions() const {
        std::lock_guard<std::recursive_mutex> lock(mempoolMutex);
        
        std::vector<std::shared_ptr<Transaction>> result;
        for (const auto& [hash, tx] : mempool) {
            result.push_back(tx);
        }
        return result;
    }

    void Blockchain::clearMempool() {
        std::lock_guard<std::recursive_mutex> lock(mempoolMutex);
        mempool.clear();
    }

    std::vector<UTXO> Blockchain::getUTXOs(const std::string& address) const {
        std::lock_guard<std::recursive_mutex> lock(utxoMutex);
        
        auto it = utxoSet.find(address);
        if (it != utxoSet.end()) {
            return it->second;
        }
        return {};
    }

    uint64_t Blockchain::getBalance(const std::string& address) const {
        uint64_t balance = 0;
        auto utxos = getUTXOs(address);
        for (const auto& utxo : utxos) {
            balance += utxo.amount;
        }
        return balance;
    }

    bool Blockchain::isUTXOSpent(const std::string& txHash, uint32_t index) const {
        std::lock_guard<std::recursive_mutex> lock(utxoMutex);
        
        // TODO: Implement UTXO spent checking
        return false;
    }

    Block Blockchain::createNewBlock(const std::string& minerAddress) {
        Block newBlock;
        
        newBlock.setVersion(BlockchainConfig::PROTOCOL_VERSION);
        newBlock.setPreviousHash(getBestBlockHash());
        newBlock.setTimestamp(static_cast<uint32_t>(std::time(nullptr)));
        newBlock.setDifficulty(currentDifficulty.load());

        // Add coinbase transaction
        Transaction coinbase;
        coinbase.setType(TransactionType::COINBASE);
        coinbase.addOutput(minerAddress, calculateBlockReward(getHeight() + 1));
        coinbase.calculateHash();
        newBlock.addTransaction(coinbase);

        // Add transactions from mempool
        auto mempoolTxs = getMempoolTransactions();
        size_t txCount = 1; // Already have coinbase
        for (const auto& tx : mempoolTxs) {
            if (txCount >= BlockchainConfig::MAX_TRANSACTIONS_PER_BLOCK) {
                break;
            }
            if (validateTransaction(*tx)) {
                newBlock.addTransaction(*tx);
                txCount++;
            }
        }

        newBlock.calculateMerkleRoot();
        return newBlock;
    }

    bool Blockchain::submitMinedBlock(const Block& block) {
        return addBlock(block);
    }

    bool Blockchain::validateBlock(const Block& block, const Block& previousBlock) const {
        // Check previous hash
        if (block.getPreviousHash() != previousBlock.getHash()) {
            return false;
        }

        // Check timestamp
        if (block.getTimestamp() <= previousBlock.getTimestamp()) {
            return false;
        }

        // Check block size
        if (block.getSize() > BlockchainConfig::MAX_BLOCK_SIZE) {
            return false;
        }

        // Check difficulty
        if (!consensus->validateProofOfWork(block)) {
            return false;
        }

        // Check merkle root
        Block temp = block;
        temp.calculateMerkleRoot();
        if (temp.getMerkleRoot() != block.getMerkleRoot()) {
            return false;
        }

        // Validate all transactions
        uint64_t totalFees = 0;
        for (size_t i = 0; i < block.getTransactions().size(); ++i) {
            const auto& tx = block.getTransactions()[i];
            
            if (i == 0) {
                // Coinbase transaction
                if (tx.getType() != TransactionType::COINBASE) {
                    return false;
                }
                if (tx.getOutputs().size() != 1) {
                    return false;
                }
            } else {
                // Regular transaction
                if (!validateTransaction(tx, block.getHash())) {
                    return false;
                }
                totalFees += tx.getFee();
            }
        }

        // Check coinbase reward
        uint64_t expectedReward = calculateBlockReward(previousBlock.getHeight() + 1) + totalFees;
        if (block.getTransactions()[0].getTotalOutput() != expectedReward) {
            return false;
        }

        return true;
    }

    bool Blockchain::validateTransaction(const Transaction& tx, const std::string& blockHash) const {
        if (tx.getType() == TransactionType::COINBASE) {
            return true; // Coinbase transactions are always valid in blocks
        }

        // Check inputs
        uint64_t totalInput = 0;
        for (const auto& input : tx.getInputs()) {
            // TODO: Verify input signatures
            // TODO: Check if UTXO exists and not spent
            totalInput += 100000000; // Placeholder
        }

        // Check outputs
        uint64_t totalOutput = tx.getTotalOutput();
        
        // Check fee
        if (totalInput < totalOutput) {
            return false;
        }

        return true;
    }

    void Blockchain::updateUTXOSet(const Block& block) {
        std::lock_guard<std::recursive_mutex> lock(utxoMutex);
        
        for (const auto& tx : block.getTransactions()) {
            // Remove spent UTXOs
            for (const auto& input : tx.getInputs()) {
                std::string utxoKey = input.previousTxHash + ":" + std::to_string(input.outputIndex);
                // TODO: Mark UTXO as spent
            }

            // Add new UTXOs
            uint32_t outputIndex = 0;
            for (const auto& output : tx.getOutputs()) {
                UTXO utxo;
                utxo.txHash = tx.getHash();
                utxo.outputIndex = outputIndex++;
                utxo.address = output.address;
                utxo.amount = output.amount;
                utxo.blockHeight = block.getHeight();
                
                utxoSet[output.address].push_back(utxo);
                utxoCount++;
            }
        }
    }

    void Blockchain::addToBlockIndex(const Block& block) {
        blockIndex[block.getHash()] = block.getHeight();
    }

    uint32_t Blockchain::calculateNextDifficulty(uint32_t timestamp, uint32_t previousTimestamp) {
        uint32_t timeSpan = timestamp - previousTimestamp;
        uint32_t targetTimeSpan = BlockchainConfig::TARGET_BLOCK_TIME * 
                                  BlockchainConfig::DIFFICULTY_ADJUSTMENT_INTERVAL;

        // Limit adjustment factor
        if (timeSpan < targetTimeSpan / 4) {
            timeSpan = targetTimeSpan / 4;
        }
        if (timeSpan > targetTimeSpan * 4) {
            timeSpan = targetTimeSpan * 4;
        }

        // Calculate new difficulty
        uint32_t newDifficulty = (currentDifficulty.load() * targetTimeSpan) / timeSpan;
        
        // Ensure difficulty doesn't go below minimum
        if (newDifficulty < 1) {
            newDifficulty = 1;
        }

        return newDifficulty;
    }

    uint64_t Blockchain::calculateBlockReward(uint32_t height) const {
        uint32_t halvings = height / BlockchainConfig::HALVING_INTERVAL;
        if (halvings >= 64) {
            return 0;
        }
        return BlockchainConfig::INITIAL_REWARD >> halvings;
    }

    BlockchainInfo Blockchain::getInfo() const {
        BlockchainInfo info;
        info.height = getHeight();
        info.bestBlockHash = getBestBlockHash();
        info.difficulty = currentDifficulty.load();
        info.totalSupply = calculateTotalSupply();
        info.mempoolSize = mempool.size();
        info.transactions = utxoCount.load();
        info.verificationProgress = calculateVerificationProgress();
        info.isInitialBlockDownload = isInitialBlockDownload();
        info.sizeOnDisk = 0; // TODO: Calculate actual size
        info.chainWork = std::to_string(totalWork.load());
        return info;
    }

    uint64_t Blockchain::calculateTotalSupply() const {
        uint64_t supply = 0;
        for (uint32_t i = 0; i <= getHeight(); ++i) {
            auto block = getBlock(i);
            if (block && !block->getTransactions().empty()) {
                supply += block->getTransactions()[0].getTotalOutput();
            }
        }
        return supply;
    }

    double Blockchain::calculateVerificationProgress() const {
        // Simplified progress calculation
        return 1.0;
    }

    bool Blockchain::isInitialBlockDownload() const {
        // Simplified IBD check
        return getHeight() < 1000;
    }

    bool Blockchain::validateChain() const {
        for (uint32_t i = 1; i < chain.size(); ++i) {
            if (!validateBlock(*chain[i], *chain[i-1])) {
                return false;
            }
        }
        return true;
    }

    bool Blockchain::validateBlock(const Block& block) const {
        auto prevBlock = getBlock(block.getPreviousHash());
        if (!prevBlock) {
            return false;
        }
        return validateBlock(block, *prevBlock);
    }

    bool Blockchain::validateTransaction(const Transaction& tx) const {
        return validateTransaction(tx, "");
    }

    bool Blockchain::reorganizeChain(uint32_t newHeight) {
        // TODO: Implement chain reorganization
        return false;
    }

    std::vector<std::shared_ptr<Block>> Blockchain::getOrphanBlocks() const {
        // TODO: Implement orphan block retrieval
        return {};
    }

    std::vector<std::string> Blockchain::getMissingBlocks() const {
        // TODO: Implement missing block detection
        return {};
    }

    uint32_t Blockchain::getSyncProgress() const {
        // TODO: Implement sync progress calculation
        return 100;
    }

    void Blockchain::setOnNewBlock(std::function<void(const Block&)> callback) {
        onNewBlock = callback;
    }

    void Blockchain::setOnNewTransaction(std::function<void(const Transaction&)> callback) {
        onNewTransaction = callback;
    }

    void Blockchain::setOnDifficultyChange(std::function<void(uint32_t, uint32_t)> callback) {
        onDifficultyChange = callback;
    }

    bool Blockchain::loadFromDisk(const std::string& path) {
        // TODO: Implement disk loading
        return false;
    }

    bool Blockchain::saveToDisk(const std::string& path) {
        // TODO: Implement disk saving
        return false;
    }

    std::vector<uint8_t> Blockchain::serialize() const {
        std::vector<uint8_t> data;
        // TODO: Implement serialization
        return data;
    }

    bool Blockchain::deserialize(const std::vector<uint8_t>& data) {
        // TODO: Implement deserialization
        return false;
    }

    uint64_t Blockchain::GetBlockReward(uint32_t height) {
        uint32_t halvings = height / BlockchainConfig::HALVING_INTERVAL;
        if (halvings >= 64) {
            return 0;
        }
        return BlockchainConfig::INITIAL_REWARD >> halvings;
    }

} // namespace powercoin