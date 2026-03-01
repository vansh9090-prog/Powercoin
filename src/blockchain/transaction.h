#ifndef POWERCOIN_TRANSACTION_H
#define POWERCOIN_TRANSACTION_H

#include <string>
#include <vector>
#include <ctime>

namespace PowerCoin {
    
    struct TxOutput {
        std::string address;
        double amount;
        bool spent;
    };
    
    class Transaction {
    private:
        std::string txHash;
        std::vector<TxOutput> outputs;
        uint32_t timestamp;

    public:
        Transaction();
        
        std::string getHash() const { return txHash; }
        const std::vector<TxOutput>& getOutputs() const { return outputs; }
        
        void addOutput(const std::string& address, double amount);
        void calculateHash();
    };
    
}

#endif // POWERCOIN_TRANSACTION_H