#include "blockchain.h"
#include "../consensus/pow.h"
#include "../crypto/sha256.h"
#include <fstream>
#include <iostream>
#include <sstream>

namespace PowerCoin {
    
    Blockchain::Blockchain() : difficulty(INITIAL_DIFFICULTY), height(0) {}
    
    bool Blockchain::addBlock(const Block& block) {
        if (chain.empty()) {
            // Genesis block
            chain.push_back(block);
            updateUTXOSet(block);
            height++;
            return true;
        }
        
        const Block& previousBlock = chain.back();
        
        if (validateBlock(block, previousBlock)) {
            chain.push_back(block);
            updateUTXOSet(block);
            height++;
            adjustDifficulty();
            return true;
        }
        
        return false;
    }
    
    bool Blockchain::validateBlock(const Block& block, const Block& previousBlock) const {
        // Check previous hash
        if (block.getHeader().previousBlockHash != previousBlock.getHash()) {
            std::cerr << "Invalid previous hash" << std::endl;
            return false;
        }
        
        // Check difficulty
        ProofOfWork pow(difficulty);
        if (!pow.validateHash(block.getHash())) {
            std::cerr << "Hash doesn't meet difficulty" << std::endl;
            return false;
        }
        
        // Check timestamp
        if (block.getHeader().timestamp <= previousBlock.getHeader().timestamp) {
            std::cerr << "Invalid timestamp" << std::endl;
            return false;
        }
        
        // Validate all transactions
        for (const auto& tx : block.getTransactions()) {
            if (!validateTransaction(tx)) {
                std::cerr << "Invalid transaction in block" << std::endl;
                return false;
            }
        }
        
        return true;
    }
    
    bool Blockchain::validateChain() const {
        if (chain.empty()) return true;
        
        for (size_t i = 1; i < chain.size(); i++) {
            if (!validateBlock(chain[i], chain[i-1])) {
                return false;
            }
        }
        
        return true;
    }
    
    bool Blockchain::addTransaction(const Transaction& tx) {
        if (!validateTransaction(tx)) {
            return false;
        }
        
        // Check for double spend in mempool
        for (const auto& existingTx : mempool) {
            for (const auto& input : tx.getInputs()) {
                for (const auto& existingInput : existingTx.getInputs()) {
                    if (input.previousTxHash == existingInput.previousTxHash &&
                        input.outputIndex == existingInput.outputIndex) {
                        std::cerr << "Double spend detected" << std::endl;
                        return false;
                    }
                }
            }
        }
        
        mempool.push_back(tx);
        return true;
    }
    
    bool Blockchain::validateTransaction(const Transaction& tx) const {
        // Coinbase transactions are always valid
        if (tx.getType() == TransactionType::COINBASE) {
            return true;
        }
        
        double totalInput = 0;
        
        // Verify each input
        for (const auto& input : tx.getInputs()) {
            std::string utxoKey = input.previousTxHash + ":" + std::to_string(input.outputIndex);
            
            auto it = utxoSet.find(utxoKey);
            if (it == utxoSet.end() || it->second.spent) {
                std::cerr << "UTXO not found or already spent" << std::endl;
                return false;
            }
            
            totalInput += it->second.amount;
        }
        
        double totalOutput = tx.getTotalOutput();
        
        // Check if inputs >= outputs
        if (totalInput < totalOutput) {
            std::cerr << "Insufficient funds" << std::endl;
            return false;
        }
        
        return true;
    }
    
    void Blockchain::updateUTXOSet(const Block& block) {
        for (const auto& tx : block.getTransactions()) {
            // Remove spent UTXOs
            for (const auto& input : tx.getInputs()) {
                std::string utxoKey = input.previousTxHash + ":" + std::to_string(input.outputIndex);
                auto it = utxoSet.find(utxoKey);
                if (it != utxoSet.end()) {
                    it->second.spent = true;
                }
            }
            
            // Add new UTXOs
            size_t outputIndex = 0;
            for (const auto& output : tx.getOutputs()) {
                std::string utxoKey = tx.getHash() + ":" + std::to_string(outputIndex++);
                utxoSet[utxoKey] = output;
            }
        }
    }
    
    double Blockchain::getBalance(const std::string& address) const {
        double balance = 0;
        for (const auto& [key, utxo] : utxoSet) {
            if (utxo.address == address && !utxo.spent) {
                balance += utxo.amount;
            }
        }
        return balance;
    }
    
    std::vector<std::pair<std::string, TxOutput>> 
    Blockchain::getUTXOsForAddress(const std::string& address) const {
        std::vector<std::pair<std::string, TxOutput>> result;
        for (const auto& [key, utxo] : utxoSet) {
            if (utxo.address == address && !utxo.spent) {
                result.push_back({key, utxo});
            }
        }
        return result;
    }
    
    Block Blockchain::createNewBlock(const std::string& minerAddress) {
        Block newBlock(height);
        newBlock.setPreviousHash(getLastBlock().getHash());
        
        // Add coinbase transaction
        Transaction coinbase;
        coinbase.setType(TransactionType::COINBASE);
        coinbase.addOutput(minerAddress, INITIAL_BLOCK_REWARD);
        coinbase.calculateHash();
        newBlock.addTransaction(coinbase);
        
        // Add mempool transactions
        size_t txCount = 1; // Start with coinbase
        for (const auto& tx : mempool) {
            if (txCount >= MAX_TRANSACTIONS_PER_BLOCK) break;
            newBlock.addTransaction(tx);
            txCount++;
        }
        
        newBlock.setDifficulty(difficulty);
        return newBlock;
    }
    
    bool Blockchain::mineBlock(Block& block) {
        if (block.mine(difficulty)) {
            // Remove mined transactions from mempool
            for (size_t i = 1; i < block.getTransactions().size(); i++) {
                auto it = std::find_if(mempool.begin(), mempool.end(),
                    [&](const Transaction& tx) {
                        return tx.getHash() == block.getTransactions()[i].getHash();
                    });
                if (it != mempool.end()) {
                    mempool.erase(it);
                }
            }
            
            addBlock(block);
            return true;
        }
        return false;
    }
    
    void Blockchain::adjustDifficulty() {
        if (height % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 || height == 0) {
            return;
        }
        
        const Block& firstBlock = chain[height - DIFFICULTY_ADJUSTMENT_INTERVAL];
        const Block& lastBlock = chain.back();
        
        uint32_t timeTaken = lastBlock.getHeader().timestamp - 
                             firstBlock.getHeader().timestamp;
        uint32_t expectedTime = BLOCK_TIME_TARGET * DIFFICULTY_ADJUSTMENT_INTERVAL;
        
        if (timeTaken < expectedTime / 2) {
            difficulty++;
            std::cout << "📈 Difficulty increased to " << difficulty << std::endl;
        } else if (timeTaken > expectedTime * 2) {
            difficulty = std::max(1u, difficulty - 1);
            std::cout << "📉 Difficulty decreased to " << difficulty << std::endl;
        }
    }
    
    bool Blockchain::saveToFile(const std::string& filename) const {
        std::ofstream file(filename);
        if (!file.is_open()) return false;
        
        file << chain.size() << "\n";
        for (const auto& block : chain) {
            file << block.serialize() << "\n";
        }
        
        return true;
    }
    
    bool Blockchain::loadFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) return false;
        
        size_t chainSize;
        file >> chainSize;
        
        chain.clear();
        for (size_t i = 0; i < chainSize; i++) {
            std::string blockData;
            std::getline(file, blockData);
            // Deserialize block and add to chain
            // Implementation depends on serialization format
        }
        
        return true;
    }
    
    Blockchain Blockchain::createGenesis() {
        Blockchain bc;
        Block genesis = Block::createGenesis();
        bc.chain.push_back(genesis);
        bc.updateUTXOSet(genesis);
        bc.height = 1;
        return bc;
    }
    
}