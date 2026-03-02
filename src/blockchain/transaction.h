#ifndef POWERCOIN_TRANSACTION_H
#define POWERCOIN_TRANSACTION_H

#include <string>
#include <vector>
#include <cstdint>
#include <ctime>
#include <memory>
#include <map>

namespace powercoin {

    /**
     * Transaction types supported by Power Coin
     */
    enum class TransactionType : uint8_t {
        COINBASE = 0x00,      // Mining reward
        TRANSFER = 0x01,      // Regular P2P transfer
        STAKE = 0x02,         // Staking transaction
        SMART_CONTRACT = 0x03, // Smart contract deployment/execution
        GOVERNANCE = 0x04,    // Governance voting
        PRIVATE = 0x05,       // Private/stealth transaction
        CROSS_CHAIN = 0x06    // Cross-chain bridge transaction
    };

    /**
     * Transaction input (UTXO reference)
     */
    struct TxInput {
        std::string previousTxHash;  // 32 bytes
        uint32_t outputIndex;        // Which output from previous tx
        uint32_t sequence;           // For replace-by-fee
        std::string scriptSig;       // Unlocking script
        std::vector<uint8_t> signature;
        std::vector<uint8_t> publicKey;
        
        TxInput();
        std::string serialize() const;
        bool deserialize(const std::string& data);
        size_t getSize() const;
        bool isCoinbase() const { return previousTxHash == std::string(64, '0'); }
    };

    /**
     * Transaction output (UTXO)
     */
    struct TxOutput {
        uint64_t amount;              // Value in satoshis
        std::string scriptPubKey;     // Locking script
        std::string address;          // Recipient address
        uint32_t lockTime;            // Lock until block height/time
        
        TxOutput();
        std::string serialize() const;
        bool deserialize(const std::string& data);
        size_t getSize() const;
        bool isSpendable() const;
    };

    /**
     * UTXO (Unspent Transaction Output) for wallet tracking
     */
    struct UTXO {
        std::string txHash;
        uint32_t outputIndex;
        std::string address;
        uint64_t amount;
        uint32_t blockHeight;
        bool isCoinbase;
        uint32_t confirmations;
        
        UTXO();
        std::string toString() const;
        bool isMature() const;
    };

    /**
     * Transaction statistics
     */
    struct TransactionStats {
        std::string hash;
        TransactionType type;
        uint32_t version;
        uint32_t size;
        uint64_t virtualSize;
        uint32_t inputCount;
        uint32_t outputCount;
        uint64_t totalInput;
        uint64_t totalOutput;
        uint64_t fee;
        double feeRate;
        uint32_t lockTime;
        uint32_t timestamp;
        uint32_t blockHeight;
        uint32_t confirmations;
    };

    /**
     * Main transaction class
     * Represents a transaction in the blockchain
     */
    class Transaction {
    private:
        std::string txHash;
        TransactionType type;
        uint32_t version;
        uint32_t lockTime;
        uint32_t timestamp;
        std::vector<TxInput> inputs;
        std::vector<TxOutput> outputs;
        uint64_t fee;
        
        // Validation cache
        mutable bool hashValidated;
        mutable std::string cachedHash;
        
    public:
        Transaction();
        explicit Transaction(TransactionType t);
        Transaction(const Transaction& other);
        Transaction& operator=(const Transaction& other);
        Transaction(Transaction&& other) noexcept;
        Transaction& operator=(Transaction&& other) noexcept;
        
        // Comparison operators
        bool operator==(const Transaction& other) const;
        bool operator!=(const Transaction& other) const;
        
        // Getters
        const std::string& getHash() const { return txHash; }
        TransactionType getType() const { return type; }
        uint32_t getVersion() const { return version; }
        uint32_t getLockTime() const { return lockTime; }
        uint32_t getTimestamp() const { return timestamp; }
        const std::vector<TxInput>& getInputs() const { return inputs; }
        const std::vector<TxOutput>& getOutputs() const { return outputs; }
        uint64_t getFee() const { return fee; }
        
        // Setters
        void setType(TransactionType t) { type = t; }
        void setVersion(uint32_t v) { version = v; }
        void setLockTime(uint32_t lt) { lockTime = lt; }
        void setTimestamp(uint32_t ts) { timestamp = ts; }
        
        // Input management
        void addInput(const TxInput& input);
        void addInput(const std::string& prevTxHash, uint32_t index);
        void addInput(const std::string& prevTxHash, uint32_t index, 
                     const std::vector<uint8_t>& signature,
                     const std::vector<uint8_t>& pubKey);
        bool removeInput(uint32_t index);
        void clearInputs();
        size_t getInputCount() const { return inputs.size(); }
        
        // Output management
        void addOutput(const TxOutput& output);
        void addOutput(const std::string& address, uint64_t amount);
        void addOutput(const std::string& address, uint64_t amount, 
                      const std::string& script);
        bool removeOutput(uint32_t index);
        void clearOutputs();
        size_t getOutputCount() const { return outputs.size(); }
        
        // Signing
        bool signInput(uint32_t inputIndex, const std::vector<uint8_t>& privateKey);
        bool verifyInput(uint32_t inputIndex, const std::vector<uint8_t>& publicKey) const;
        bool verifySignature(const std::string& message, 
                            const std::vector<uint8_t>& signature,
                            const std::vector<uint8_t>& publicKey) const;
        
        // Hash calculation
        void calculateHash();
        bool validateHash() const;
        std::string getWitnessHash() const;
        
        // Fee calculation
        uint64_t calculateFee() const;
        uint64_t calculateMinFee() const;
        bool hasEnoughFee() const;
        
        // Size calculation
        uint32_t getSize() const;
        uint32_t getBaseSize() const;
        uint32_t getWitnessSize() const;
        uint64_t getVirtualSize() const;
        
        // Value calculation
        uint64_t getTotalInput() const;
        uint64_t getTotalOutput() const;
        bool isCoinbase() const { return type == TransactionType::COINBASE; }
        
        // Validation
        bool validate() const;
        bool validateInputs() const;
        bool validateOutputs() const;
        bool validateLockTime(uint32_t currentHeight, uint32_t currentTime) const;
        
        // Serialization
        std::string serialize() const;
        bool deserialize(const std::string& data);
        std::vector<uint8_t> serializeBinary() const;
        bool deserializeBinary(const std::vector<uint8_t>& data);
        
        // Statistics
        TransactionStats getStats() const;
        double getFeeRate() const;
        
        // Utility
        std::string toString() const;
        void print() const;
        
        // Static helpers
        static Transaction createCoinbase(const std::string& address, uint64_t amount);
        static Transaction createTransfer(const std::string& from, 
                                         const std::string& to, 
                                         uint64_t amount,
                                         uint64_t fee);
        static Transaction createPrivateTransfer(const std::string& from,
                                                const std::string& stealthAddress,
                                                uint64_t amount);
        static bool isValidAddress(const std::string& address);
        static bool isValidAmount(uint64_t amount);
        
        // Constants
        static constexpr uint32_t CURRENT_VERSION = 2;
        static constexpr uint32_t MIN_LOCK_TIME = 0;
        static constexpr uint32_t MAX_LOCK_TIME = 500000000;
        static constexpr uint64_t MIN_FEE = 1000; // 0.00001000 PWR
        static constexpr uint64_t MAX_MONEY = 21000000 * 100000000ULL; // 21M PWR
        static constexpr uint32_t COINBASE_MATURITY = 100; // Blocks
    };

    /**
     * Transaction builder for easy transaction creation
     */
    class TransactionBuilder {
    private:
        std::vector<std::pair<std::string, uint32_t>> utxos;
        std::map<std::string, uint64_t> outputs;
        uint64_t fee;
        TransactionType type;
        uint32_t lockTime;
        
    public:
        TransactionBuilder();
        
        TransactionBuilder& addUTXO(const std::string& txHash, uint32_t index);
        TransactionBuilder& addOutput(const std::string& address, uint64_t amount);
        TransactionBuilder& setFee(uint64_t feeRate);
        TransactionBuilder& setType(TransactionType t);
        TransactionBuilder& setLockTime(uint32_t lt);
        
        Transaction build(const std::vector<uint8_t>& privateKey);
        Transaction buildWithChange(const std::vector<uint8_t>& privateKey,
                                   const std::string& changeAddress);
    };

} // namespace powercoin

#endif // POWERCOIN_TRANSACTION_H