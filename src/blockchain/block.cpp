#include "block.h"
#include "../crypto/sha256.h"
#include <sstream>
#include <iostream>
#include <thread>

namespace PowerCoin {
    
    Block::Block(uint32_t idx, const std::string& prevHash) 
        : index(idx), previousHash(prevHash), nonce(0) {
        timestamp = std::time(nullptr);
        difficulty = 4;
    }
    
    void Block::addTransaction(const Transaction& tx) {
        transactions.push_back(tx);
    }
    
    void Block::calculateMerkleRoot() {
        if (transactions.empty()) {
            merkleRoot = SHA256::doubleHash("empty");
            return;
        }
        
        std::vector<std::string> hashes;
        for (const auto& tx : transactions) {
            hashes.push_back(tx.getHash());
        }
        
        while (hashes.size() > 1) {
            std::vector<std::string> newHashes;
            for (size_t i = 0; i < hashes.size(); i += 2) {
                if (i + 1 < hashes.size()) {
                    newHashes.push_back(SHA256::doubleHash(hashes[i] + hashes[i+1]));
                } else {
                    newHashes.push_back(SHA256::doubleHash(hashes[i] + hashes[i]));
                }
            }
            hashes = newHashes;
        }
        
        merkleRoot = hashes[0];
    }
    
    bool Block::mine(uint32_t diff) {
        difficulty = diff;
        calculateMerkleRoot();
        
        std::string target(diff, '0');
        std::stringstream ss;
        ss << index << previousHash << merkleRoot << timestamp;
        std::string base = ss.str();
        
        while (nonce < UINT32_MAX) {
            std::string hash = SHA256::doubleHash(base + std::to_string(nonce));
            if (hash.substr(0, diff) == target) {
                blockHash = hash;
                return true;
            }
            nonce++;
        }
        return false;
    }
    
    bool Block::validate(const Block& previous, uint32_t diff) const {
        if (previousHash != previous.getHash()) return false;
        if (timestamp <= previous.getTimestamp()) return false;
        
        std::string target(diff, '0');
        std::stringstream ss;
        ss << index << previousHash << merkleRoot << timestamp << nonce;
        std::string hash = SHA256::doubleHash(ss.str());
        
        return hash.substr(0, diff) == target;
    }
    
    Block Block::createGenesis() {
        Block genesis(0, "0");
        genesis.timestamp = 1231006505;
        genesis.blockHash = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
        return genesis;
    }
    
}