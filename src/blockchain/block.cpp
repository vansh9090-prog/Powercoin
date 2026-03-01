#include "block.h"
#include "../crypto/sha256.h"
#include <sstream>
#include <iostream>
#include <thread>
#include <chrono>

namespace PowerCoin {
    
    BlockHeader::BlockHeader() 
        : version(1), timestamp(std::time(nullptr)), bits(4), nonce(0) {}
    
    std::string BlockHeader::serialize() const {
        std::stringstream ss;
        ss << version << previousBlockHash << merkleRoot 
           << timestamp << bits << nonce;
        return ss.str();
    }
    
    std::string BlockHeader::calculateHash() const {
        return SHA256::doubleHash(serialize());
    }
    
    Block::Block(uint32_t height) : height(height) {
        header.timestamp = std::time(nullptr);
    }
    
    void Block::addTransaction(const Transaction& tx) {
        transactions.push_back(tx);
    }
    
    void Block::calculateMerkleRoot() {
        if (transactions.empty()) {
            header.merkleRoot = SHA256::doubleHash("empty");
            return;
        }
        
        std::vector<std::string> txHashes;
        for (const auto& tx : transactions) {
            txHashes.push_back(tx.getHash());
        }
        
        while (txHashes.size() > 1) {
            std::vector<std::string> newHashes;
            for (size_t i = 0; i < txHashes.size(); i += 2) {
                if (i + 1 < txHashes.size()) {
                    newHashes.push_back(SHA256::doubleHash(txHashes[i] + txHashes[i + 1]));
                } else {
                    newHashes.push_back(SHA256::doubleHash(txHashes[i] + txHashes[i]));
                }
            }
            txHashes = newHashes;
        }
        
        header.merkleRoot = txHashes[0];
    }
    
    bool Block::mine(uint32_t difficulty) {
        std::cout << "\n⛏️ Mining block #" << height << "..." << std::endl;
        auto startTime = std::chrono::high_resolution_clock::now();
        
        calculateMerkleRoot();
        std::string target(difficulty, '0');
        
        header.nonce = 0;
        while (header.nonce < UINT32_MAX) {
            blockHash = header.calculateHash();
            
            if (blockHash.substr(0, difficulty) == target) {
                auto endTime = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
                
                std::cout << "✅ Block mined!" << std::endl;
                std::cout << "   Hash: " << blockHash.substr(0, 32) << "..." << std::endl;
                std::cout << "   Nonce: " << header.nonce << std::endl;
                std::cout << "   Time: " << duration.count() << " seconds" << std::endl;
                return true;
            }
            
            header.nonce++;
            
            if (header.nonce % 100000 == 0) {
                std::cout << "   Mining... nonce: " << header.nonce << "\r" << std::flush;
            }
        }
        
        return false;
    }
    
    bool Block::validate(const Block& previousBlock, uint32_t difficulty) const {
        // Check previous hash
        if (header.previousBlockHash != previousBlock.getHash()) {
            std::cerr << "Invalid previous hash" << std::endl;
            return false;
        }
        
        // Check hash meets difficulty
        std::string target(difficulty, '0');
        if (blockHash.substr(0, difficulty) != target) {
            std::cerr << "Hash doesn't meet difficulty" << std::endl;
            return false;
        }
        
        // Check timestamp
        if (header.timestamp <= previousBlock.getHeader().timestamp) {
            std::cerr << "Invalid timestamp" << std::endl;
            return false;
        }
        
        // Verify merkle root
        Block temp = *this;
        temp.calculateMerkleRoot();
        if (temp.getHeader().merkleRoot != header.merkleRoot) {
            std::cerr << "Invalid merkle root" << std::endl;
            return false;
        }
        
        return true;
    }
    
    std::string Block::serialize() const {
        std::stringstream ss;
        ss << height << "\n"
           << blockHash << "\n"
           << header.version << "\n"
           << header.previousBlockHash << "\n"
           << header.merkleRoot << "\n"
           << header.timestamp << "\n"
           << header.bits << "\n"
           << header.nonce << "\n"
           << transactions.size() << "\n";
        
        for (const auto& tx : transactions) {
            ss << tx.serialize() << "\n";
        }
        
        return ss.str();
    }
    
    Block Block::createGenesis() {
        Block genesis(0);
        genesis.header.previousBlockHash = std::string(64, '0');
        genesis.header.timestamp = 1231006505;  // Bitcoin genesis timestamp
        
        // Create coinbase transaction
        Transaction coinbase;
        coinbase.setType(TransactionType::COINBASE);
        coinbase.addOutput("PWRGenesisAddress", 50);
        coinbase.calculateHash();
        genesis.addTransaction(coinbase);
        
        genesis.calculateMerkleRoot();
        genesis.blockHash = genesis.header.calculateHash();
        
        std::cout << "🔨 Genesis block created!" << std::endl;
        return genesis;
    }
    
}