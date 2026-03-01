#ifndef POWERCOIN_TRANSACTION_H
#define POWERCOIN_TRANSACTION_H

#include <string>
#include <vector>
#include <cstdint>

namespace PowerCoin {
    
    enum class TransactionType {
        COINBASE,
        TRANSFER,
        STAKE
    };
    
    struct TxInput {
        std::string previousTxHash;
        uint32_t outputIndex;
        std::string signature;
        std::string publicKey;
        
        std::string serialize() const;
    };
    
    struct TxOutput {
        std::string address;
        double amount;
        bool spent;
        
        std::string serialize() const;
    };
    
    class Transaction {
    private:
        std::string txHash;
        TransactionType type;
        uint32_t version;
        uint32_t timestamp;
        std::vector<TxInput> inputs;
        std::vector<TxOutput> outputs;
        double fee;
        
    public:
        Transaction();
        
        // Getters
        std::string getHash() const { return txHash; }
        TransactionType getType() const { return type; }
        const std::vector<TxInput>& getInputs() const { return inputs; }
        const std::vector<TxOutput>& getOutputs() const { return outputs; }
        double getFee() const { return fee; }
        
        // Setters
        void setType(TransactionType t) { type = t; }
        void addInput(const std::string& prevTxHash, uint32_t index);
        void addOutput(const std::string& address, double amount);
        void setSignature(uint32_t inputIndex, const std::string& sig, const std::string& pubKey);
        
        // Operations
        void calculateHash();
        bool verify() const;
        double getTotalInput() const;
        double getTotalOutput() const;
        
        // Serialization
        std::string serialize() const;
        static Transaction deserialize(const std::string& data);
    };
    
}

#endif // POWERCOIN_TRANSACTION_H