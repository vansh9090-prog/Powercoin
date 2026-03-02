#ifndef POWERCOIN_VALIDATION_H
#define POWERCOIN_VALIDATION_H

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <map>
#include "block.h"
#include "transaction.h"
#include "consensus.h"

namespace powercoin {

    /**
     * Validation result codes
     */
    enum class ValidationResult {
        VALID,
        INVALID_BLOCK_VERSION,
        INVALID_PREVIOUS_HASH,
        INVALID_TIMESTAMP,
        INVALID_DIFFICULTY,
        INVALID_MERKLE_ROOT,
        INVALID_PROOF_OF_WORK,
        INVALID_PROOF_OF_STAKE,
        INVALID_TRANSACTION,
        INVALID_COINBASE,
        INVALID_SIGNATURE,
        INVALID_SCRIPT,
        INSUFFICIENT_FEE,
        DOUBLE_SPEND,
        NON_STANDARD_TRANSACTION,
        EXCEEDS_MAX_BLOCK_SIZE,
        EXCEEDS_MAX_BLOCK_SIGOPS,
        EXCEEDS_MAX_BLOCK_GAS,
        ORPHAN_BLOCK,
        DUPLICATE_BLOCK,
        DUPLICATE_TRANSACTION,
        CHAIN_REORGANIZATION,
        CONSENSUS_ERROR,
        INTERNAL_ERROR,
        UNKNOWN_ERROR
    };

    /**
     * Validation state for blocks
     */
    struct BlockValidationState {
        ValidationResult result;
        std::string errorMessage;
        uint32_t validationTime;
        uint32_t height;
        std::string blockHash;
        std::vector<std::string> details;
        
        BlockValidationState();
        void setError(ValidationResult code, const std::string& message);
        void setValid();
        bool isValid() const;
        std::string toString() const;
    };

    /**
     * Validation state for transactions
     */
    struct TransactionValidationState {
        ValidationResult result;
        std::string errorMessage;
        uint32_t validationTime;
        std::string txHash;
        uint64_t fee;
        double feeRate;
        std::vector<std::string> details;
        
        TransactionValidationState();
        void setError(ValidationResult code, const std::string& message);
        void setValid();
        bool isValid() const;
        std::string toString() const;
    };

    /**
     * UTXO validation context
     */
    struct UTXOContext {
        std::string txHash;
        uint32_t outputIndex;
        std::string address;
        uint64_t amount;
        uint32_t blockHeight;
        bool isCoinbase;
        uint32_t confirmations;
        
        UTXOContext();
        bool isMature() const;
        std::string toString() const;
    };

    /**
     * Script validation context
     */
    struct ScriptContext {
        std::vector<uint8_t> script;
        std::vector<uint8_t> signature;
        std::vector<uint8_t> publicKey;
        std::string txHash;
        uint32_t inputIndex;
        uint64_t amount;
        uint32_t flags;
        
        ScriptContext();
        void clear();
    };

    /**
     * Main validation class
     * Handles all blockchain validation rules
     */
    class Validation {
    private:
        std::unique_ptr<Consensus> consensus;
        
        // Validation caches
        mutable std::map<std::string, BlockValidationState> blockCache;
        mutable std::map<std::string, TransactionValidationState> txCache;
        mutable std::map<std::string, bool> scriptCache;
        
        // Validation statistics
        mutable uint64_t totalValidations;
        mutable uint64_t failedValidations;
        mutable uint64_t averageValidationTime;
        
        // Callbacks
        std::function<void(const BlockValidationState&)> onBlockValidated;
        std::function<void(const TransactionValidationState&)> onTransactionValidated;
        std::function<void(const std::string&, bool)> onScriptValidated;
        
        // Internal validation methods
        bool validateBlockHeader(const Block& block, 
                                 const Block& previousBlock,
                                 BlockValidationState& state) const;
        
        bool validateBlockTransactions(const Block& block,
                                       const std::vector<Transaction>& mempool,
                                       const std::map<std::string, UTXOContext>& utxos,
                                       BlockValidationState& state) const;
        
        bool validateTransactionInputs(const Transaction& tx,
                                       const std::vector<UTXOContext>& utxos,
                                       TransactionValidationState& state) const;
        
        bool validateTransactionOutputs(const Transaction& tx,
                                        TransactionValidationState& state) const;
        
        bool validateScript(const ScriptContext& context,
                           TransactionValidationState& state) const;
        
        bool validateSignature(const std::vector<uint8_t>& signature,
                              const std::vector<uint8_t>& publicKey,
                              const std::string& message,
                              TransactionValidationState& state) const;
        
        bool validateLockTime(const Transaction& tx,
                             uint32_t currentHeight,
                             uint32_t currentTime,
                             TransactionValidationState& state) const;
        
        bool validateSequence(const Transaction& tx,
                             uint32_t currentHeight,
                             uint32_t currentTime,
                             TransactionValidationState& state) const;
        
        bool validateFee(const Transaction& tx,
                        uint64_t minFee,
                        TransactionValidationState& state) const;
        
        bool validateCoinbase(const Transaction& tx,
                             uint64_t expectedReward,
                             TransactionValidationState& state) const;
        
        bool validateStake(const Transaction& tx,
                          uint64_t stakeAmount,
                          uint32_t stakeAge,
                          TransactionValidationState& state) const;
        
        uint64_t calculateMinFee(const Transaction& tx) const;
        
        void updateValidationStats(uint64_t startTime, bool success) const;
        
    public:
        Validation();
        explicit Validation(std::unique_ptr<Consensus> cons);
        ~Validation();
        
        // Disable copy
        Validation(const Validation&) = delete;
        Validation& operator=(const Validation&) = delete;
        
        // Block validation
        bool validateBlock(const Block& block,
                          const Block& previousBlock,
                          const std::vector<Transaction>& mempool,
                          const std::map<std::string, UTXOContext>& utxos,
                          BlockValidationState& state) const;
        
        bool validateBlock(const Block& block,
                          const std::vector<Block>& chain,
                          const std::map<std::string, UTXOContext>& utxos,
                          BlockValidationState& state) const;
        
        bool validateBlockHeader(const Block& block,
                                const std::vector<Block>& chain,
                                BlockValidationState& state) const;
        
        // Transaction validation
        bool validateTransaction(const Transaction& tx,
                                const std::vector<UTXOContext>& utxos,
                                uint32_t currentHeight,
                                uint32_t currentTime,
                                TransactionValidationState& state) const;
        
        bool validateTransaction(const Transaction& tx,
                                const std::map<std::string, UTXOContext>& utxos,
                                uint32_t currentHeight,
                                uint32_t currentTime,
                                TransactionValidationState& state) const;
        
        bool validateMempoolTransaction(const Transaction& tx,
                                       const std::vector<Transaction>& mempool,
                                       const std::map<std::string, UTXOContext>& utxos,
                                       uint32_t currentHeight,
                                       uint32_t currentTime,
                                       TransactionValidationState& state) const;
        
        // Script validation
        bool validateScript(const std::vector<uint8_t>& script,
                           const std::vector<uint8_t>& signature,
                           const std::vector<uint8_t>& publicKey,
                           const std::string& txHash,
                           uint32_t inputIndex,
                           uint64_t amount) const;
        
        bool validatePayToPubKey(const std::vector<uint8_t>& script,
                                const std::vector<uint8_t>& signature,
                                const std::vector<uint8_t>& publicKey,
                                const std::string& message) const;
        
        bool validatePayToPubKeyHash(const std::vector<uint8_t>& script,
                                     const std::vector<uint8_t>& signature,
                                     const std::vector<uint8_t>& publicKey,
                                     const std::string& message) const;
        
        bool validateMultiSig(const std::vector<uint8_t>& script,
                             const std::vector<std::vector<uint8_t>>& signatures,
                             const std::vector<std::vector<uint8_t>>& publicKeys,
                             const std::string& message) const;
        
        // UTXO validation
        bool validateUTXO(const UTXOContext& utxo,
                         const Transaction& spendingTx,
                         TransactionValidationState& state) const;
        
        bool validateUTXOSet(const std::map<std::string, UTXOContext>& utxos,
                            const std::vector<Transaction>& transactions,
                            TransactionValidationState& state) const;
        
        // Chain validation
        bool validateChain(const std::vector<Block>& chain,
                          BlockValidationState& state) const;
        
        bool validateChainWork(const std::vector<Block>& chain,
                              const ChainWork& expectedWork,
                              BlockValidationState& state) const;
        
        // Double spend detection
        bool isDoubleSpend(const Transaction& tx,
                          const std::vector<Transaction>& mempool,
                          const std::map<std::string, UTXOContext>& utxos) const;
        
        bool findDoubleSpends(const std::vector<Transaction>& transactions,
                             std::vector<std::string>& doubleSpends) const;
        
        // Orphan block handling
        bool isOrphanBlock(const Block& block,
                          const std::vector<Block>& chain) const;
        
        std::vector<Block> getOrphanBlocks(const std::vector<Block>& blocks,
                                          const std::vector<Block>& chain) const;
        
        // Cache management
        void clearCache();
        void clearBlockCache();
        void clearTransactionCache();
        void clearScriptCache();
        
        // Statistics
        uint64_t getTotalValidations() const { return totalValidations; }
        uint64_t getFailedValidations() const { return failedValidations; }
        double getSuccessRate() const;
        std::map<std::string, uint64_t> getErrorStatistics() const;
        
        // Callback registration
        void setOnBlockValidated(std::function<void(const BlockValidationState&)> callback);
        void setOnTransactionValidated(std::function<void(const TransactionValidationState&)> callback);
        void setOnScriptValidated(std::function<void(const std::string&, bool)> callback);
        
        // Utility
        std::string resultToString(ValidationResult result) const;
        void printStatistics() const;
        
        // Static helper methods
        static bool isStandardOutput(const TxOutput& output);
        static bool isStandardInput(const TxInput& input);
        static bool isDust(const TxOutput& output);
        static uint64_t getDustThreshold(const TxOutput& output);
        static bool isStandardScript(const std::vector<uint8_t>& script);
        static bool isWitnessProgram(const std::vector<uint8_t>& script);
        static uint32_t getWitnessVersion(const std::vector<uint8_t>& script);
    };

    /**
     * Validation result wrapper
     */
    class ValidationResultWrapper {
    private:
        ValidationResult result;
        std::string message;
        
    public:
        ValidationResultWrapper(ValidationResult r = ValidationResult::VALID,
                                const std::string& msg = "");
        
        bool operator==(ValidationResult r) const;
        bool operator!=(ValidationResult r) const;
        operator bool() const;
        
        ValidationResult getResult() const { return result; }
        const std::string& getMessage() const { return message; }
        
        static ValidationResultWrapper valid();
        static ValidationResultWrapper error(ValidationResult r, const std::string& msg);
    };

    /**
     * Validation context for batch validation
     */
    class ValidationContext {
    private:
        std::vector<Block> blocks;
        std::vector<Transaction> transactions;
        std::map<std::string, UTXOContext> utxos;
        uint32_t currentHeight;
        uint32_t currentTime;
        
    public:
        ValidationContext();
        
        void addBlock(const Block& block);
        void addTransaction(const Transaction& tx);
        void addUTXO(const UTXOContext& utxo);
        void setCurrentHeight(uint32_t height);
        void setCurrentTime(uint32_t time);
        
        bool validateAll(std::vector<ValidationResultWrapper>& results) const;
        bool validateBlocks(std::vector<ValidationResultWrapper>& results) const;
        bool validateTransactions(std::vector<ValidationResultWrapper>& results) const;
        
        void clear();
    };

} // namespace powercoin

#endif // POWERCOIN_VALIDATION_H