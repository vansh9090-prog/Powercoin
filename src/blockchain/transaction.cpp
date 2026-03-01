#include "transaction.h"
#include "../crypto/sha256.h"
#include <sstream>

namespace PowerCoin {
    
    std::string TxInput::serialize() const {
        std::stringstream ss;
        ss << previousTxHash << outputIndex << signature << publicKey;
        return ss.str();
    }
    
    std::string TxOutput::serialize() const {
        std::stringstream ss;
        ss << address << amount << (spent ? "1" : "0");
        return ss.str();
    }
    
    Transaction::Transaction() 
        : type(TransactionType::TRANSFER), version(1), 
          timestamp(std::time(nullptr)), fee(0) {}
    
    void Transaction::addInput(const std::string& prevTxHash, uint32_t index) {
        TxInput input;
        input.previousTxHash = prevTxHash;
        input.outputIndex = index;
        inputs.push_back(input);
    }
    
    void Transaction::addOutput(const std::string& address, double amount) {
        TxOutput output;
        output.address = address;
        output.amount = amount;
        output.spent = false;
        outputs.push_back(output);
    }
    
    void Transaction::setSignature(uint32_t inputIndex, const std::string& sig, 
                                   const std::string& pubKey) {
        if (inputIndex < inputs.size()) {
            inputs[inputIndex].signature = sig;
            inputs[inputIndex].publicKey = pubKey;
        }
    }
    
    void Transaction::calculateHash() {
        std::stringstream ss;
        ss << static_cast<int>(type) << version << timestamp;
        
        for (const auto& input : inputs) {
            ss << input.serialize();
        }
        
        for (const auto& output : outputs) {
            ss << output.serialize();
        }
        
        txHash = SHA256::doubleHash(ss.str());
    }
    
    bool Transaction::verify() const {
        // Simplified verification - in real implementation,
        // would verify signatures using public keys
        return true;
    }
    
    double Transaction::getTotalInput() const {
        double total = 0;
        for (const auto& output : outputs) {
            total += output.amount;
        }
        return total;
    }
    
    double Transaction::getTotalOutput() const {
        double total = 0;
        for (const auto& output : outputs) {
            total += output.amount;
        }
        return total;
    }
    
    std::string Transaction::serialize() const {
        std::stringstream ss;
        ss << txHash << "\n"
           << static_cast<int>(type) << "\n"
           << version << "\n"
           << timestamp << "\n"
           << fee << "\n"
           << inputs.size() << "\n";
        
        for (const auto& input : inputs) {
            ss << input.previousTxHash << "\n"
               << input.outputIndex << "\n"
               << input.signature << "\n"
               << input.publicKey << "\n";
        }
        
        ss << outputs.size() << "\n";
        for (const auto& output : outputs) {
            ss << output.address << "\n"
               << output.amount << "\n"
               << (output.spent ? "1" : "0") << "\n";
        }
        
        return ss.str();
    }
    
}