#include "blockchain.h"
#include "../config.h"
#include <iostream>

namespace PowerCoin {
    
    Blockchain::Blockchain() : difficulty(INITIAL_DIFFICULTY) {
        chain.push_back(Block::createGenesis());
    }
    
    bool Blockchain::addBlock(const Block& block) {
        if (chain.empty()) {
            chain.push_back(block);
            return true;
        }
        
        const Block& previous = chain.back();
        if (block.validate(previous, difficulty)) {
            chain.push_back(block);
            return true;
        }
        return false;
    }
    
    bool Blockchain::addTransaction(const Transaction& tx) {
        mempool.push_back(tx);
        return true;
    }
    
    Block Blockchain::createNewBlock(const std::string& minerAddress) {
        Block newBlock(chain.size(), chain.back().getHash());
        
        Transaction coinbase;
        coinbase.addOutput(minerAddress, INITIAL_BLOCK_REWARD);
        coinbase.calculateHash();
        newBlock.addTransaction(coinbase);
        
        for (const auto& tx : mempool) {
            newBlock.addTransaction(tx);
        }
        
        return newBlock;
    }
    
    bool Blockchain::mineBlock(Block& block) {
        if (block.mine(difficulty)) {
            mempool.clear();
            chain.push_back(block);
            return true;
        }
        return false;
    }
    
    double Blockchain::getBalance(const std::string& address) const {
        double balance = 0;
        for (const auto& block : chain) {
            for (const auto& tx : block.getTransactions()) {
                for (const auto& output : tx.getOutputs()) {
                    if (output.address == address) {
                        balance += output.amount;
                    }
                }
            }
        }
        return balance;
    }
    
}