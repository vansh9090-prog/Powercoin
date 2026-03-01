#include "transaction.h"
#include "../crypto/sha256.h"
#include <sstream>

namespace PowerCoin {
    
    Transaction::Transaction() : timestamp(std::time(nullptr)) {}
    
    void Transaction::addOutput(const std::string& address, double amount) {
        TxOutput output;
        output.address = address;
        output.amount = amount;
        output.spent = false;
        outputs.push_back(output);
    }
    
    void Transaction::calculateHash() {
        std::stringstream ss;
        ss << timestamp;
        for (const auto& out : outputs) {
            ss << out.address << out.amount;
        }
        txHash = SHA256::doubleHash(ss.str());
    }
    
}