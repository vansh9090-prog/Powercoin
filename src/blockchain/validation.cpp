#include "validation.h"
#include "../crypto/sha256.h"
#include "../crypto/secp256k1.h"
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace powercoin {

    // ============== BlockValidationState Implementation ==============

    BlockValidationState::BlockValidationState()
        : result(ValidationResult::VALID), validationTime(0), height(0) {}

    void BlockValidationState::setError(ValidationResult code, const std::string& message) {
        result = code;
        errorMessage = message;
        details.push_back(message);
    }

    void BlockValidationState::setValid() {
        result = ValidationResult::VALID;
        errorMessage.clear();
    }

    bool BlockValidationState::isValid() const {
        return result == ValidationResult::VALID;
    }

    std::string BlockValidationState::toString() const {
        std::stringstream ss;
        ss << "Block Validation: " << (isValid() ? "VALID" : "INVALID") << "\n";
        ss << "Result: " << static_cast<int>(result) << "\n";
        if (!errorMessage.empty()) {
            ss << "Error: " << errorMessage << "\n";
        }
        ss << "Height: " << height << "\n";
        ss << "Hash: " << blockHash.substr(0, 16) << "...\n";
        ss << "Time: " << validationTime << " ms\n";
        return ss.str();
    }

    // ============== TransactionValidationState Implementation ==============

    TransactionValidationState::TransactionValidationState()
        : result(ValidationResult::VALID), validationTime(0), fee(0), feeRate(0) {}

    void TransactionValidationState::setError(ValidationResult code, const std::string& message) {
        result = code;
        errorMessage = message;
        details.push_back(message);
    }

    void TransactionValidationState::setValid() {
        result = ValidationResult::VALID;
        errorMessage.clear();
    }

    bool TransactionValidationState::isValid() const {
        return result == ValidationResult::VALID;
    }

    std::string TransactionValidationState::toString() const {
        std::stringstream ss;
        ss << "Transaction Validation: " << (isValid() ? "VALID" : "INVALID") << "\n";
        ss << "Result: " << static_cast<int>(result) << "\n";
        if (!errorMessage.empty()) {
            ss << "Error: " << errorMessage << "\n";
        }
        ss << "Hash: " << txHash.substr(0, 16) << "...\n";
        ss << "Fee: " << fee / 100000000.0 << " PWR\n";
        ss << "Fee Rate: " << feeRate << " sat/byte\n";
        ss << "Time: " << validationTime << " ms\n";
        return ss.str();
    }

    // ============== UTXOContext Implementation ==============

    UTXOContext::UTXOContext()
        : outputIndex(0), amount(0), blockHeight(0), isCoinbase(false), confirmations(0) {}

    bool UTXOContext::isMature() const {
        if (isCoinbase) {
            return confirmations >= 100;
        }
        return true;
    }

    std::string UTXOContext::toString() const {
        std::stringstream ss;
        ss << "UTXO: " << txHash.substr(0, 16) << ":" << outputIndex << "\n";
        ss << "  Address: " << address << "\n";
        ss << "  Amount: " << amount / 100000000.0 << " PWR\n";
        ss << "  Block: " << blockHeight << "\n";
        ss << "  Confirmations: " << confirmations << "\n";
        return ss.str();
    }

    // ============== ScriptContext Implementation ==============

    ScriptContext::ScriptContext() : inputIndex(0), amount(0), flags(0) {}

    void ScriptContext::clear() {
        script.clear();
        signature.clear();
        publicKey.clear();
        txHash.clear();
        inputIndex = 0;
        amount = 0;
        flags = 0;
    }

    // ============== Validation Implementation ==============

    Validation::Validation() 
        : totalValidations(0), failedValidations(0), averageValidationTime(0) {
        consensus = std::make_unique<Consensus>();
        consensus->initialize();
    }

    Validation::Validation(std::unique_ptr<Consensus> cons)
        : consensus(std::move(cons)), totalValidations(0), 
          failedValidations(0), averageValidationTime(0) {}

    Validation::~Validation() = default;

    bool Validation::validateBlock(const Block& block,
                                   const Block& previousBlock,
                                   const std::vector<Transaction>& mempool,
                                   const std::map<std::string, UTXOContext>& utxos,
                                   BlockValidationState& state) const {
        auto startTime = std::chrono::high_resolution_clock::now();

        // Check cache
        auto cacheIt = blockCache.find(block.getHash());
        if (cacheIt != blockCache.end()) {
            state = cacheIt->second;
            updateValidationStats(0, state.isValid());
            return state.isValid();
        }

        // Validate block header
        if (!validateBlockHeader(block, previousBlock, state)) {
            state.blockHash = block.getHash();
            state.height = block.getHeight();
            blockCache[block.getHash()] = state;
            updateValidationStats(startTime, false);
            return false;
        }

        // Validate block transactions
        if (!validateBlockTransactions(block, mempool, utxos, state)) {
            state.blockHash = block.getHash();
            state.height = block.getHeight();
            blockCache[block.getHash()] = state;
            updateValidationStats(startTime, false);
            return false;
        }

        // All validations passed
        state.setValid();
        state.blockHash = block.getHash();
        state.height = block.getHeight();
        blockCache[block.getHash()] = state;

        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime);
        state.validationTime = duration.count();

        updateValidationStats(startTime, true);

        if (onBlockValidated) {
            onBlockValidated(state);
        }

        return true;
    }

    bool Validation::validateBlock(const Block& block,
                                   const std::vector<Block>& chain,
                                   const std::map<std::string, UTXOContext>& utxos,
                                   BlockValidationState& state) const {
        if (chain.empty()) {
            return validateBlock(block, Block(), {}, utxos, state);
        }

        // Find previous block
        const Block* previousBlock = nullptr;
        for (const auto& b : chain) {
            if (b.getHash() == block.getPreviousHash()) {
                previousBlock = &b;
                break;
            }
        }

        if (!previousBlock) {
            state.setError(ValidationResult::ORPHAN_BLOCK, 
                          "Previous block not found in chain");
            return false;
        }

        // Get mempool from chain context
        std::vector<Transaction> mempool;
        // TODO: Build mempool from chain

        return validateBlock(block, *previousBlock, mempool, utxos, state);
    }

    bool Validation::validateBlockHeader(const Block& block,
                                         const std::vector<Block>& chain,
                                         BlockValidationState& state) const {
        if (chain.empty()) {
            return true; // Genesis block
        }

        const auto& previousBlock = chain.back();
        return validateBlockHeader(block, previousBlock, state);
    }

    bool Validation::validateBlockHeader(const Block& block,
                                         const Block& previousBlock,
                                         BlockValidationState& state) const {
        // Check previous hash
        if (block.getPreviousHash() != previousBlock.getHash()) {
            state.setError(ValidationResult::INVALID_PREVIOUS_HASH,
                          "Previous hash mismatch");
            return false;
        }

        // Check timestamp
        if (block.getTimestamp() <= previousBlock.getTimestamp()) {
            state.setError(ValidationResult::INVALID_TIMESTAMP,
                          "Timestamp not after previous block");
            return false;
        }

        uint32_t now = static_cast<uint32_t>(std::time(nullptr));
        if (block.getTimestamp() > now + 7200) {
            state.setError(ValidationResult::INVALID_TIMESTAMP,
                          "Timestamp too far in future");
            return false;
        }

        // Check version
        if (block.getVersion() > static_cast<uint32_t>(ConsensusVersion::CURRENT)) {
            state.setError(ValidationResult::INVALID_BLOCK_VERSION,
                          "Unsupported block version");
            return false;
        }

        // Check difficulty
        if (!consensus->validateProofOfWork(block)) {
            state.setError(ValidationResult::INVALID_PROOF_OF_WORK,
                          "Proof of work validation failed");
            return false;
        }

        // Check merkle root
        Block temp = block;
        temp.calculateMerkleRoot();
        if (temp.getMerkleRoot() != block.getMerkleRoot()) {
            state.setError(ValidationResult::INVALID_MERKLE_ROOT,
                          "Merkle root mismatch");
            return false;
        }

        return true;
    }

    bool Validation::validateBlockTransactions(const Block& block,
                                               const std::vector<Transaction>& mempool,
                                               const std::map<std::string, UTXOContext>& utxos,
                                               BlockValidationState& state) const {
        const auto& transactions = block.getTransactions();

        if (transactions.empty()) {
            state.setError(ValidationResult::INVALID_TRANSACTION,
                          "Block has no transactions");
            return false;
        }

        // Check transaction count
        if (transactions.size() > 5000) {
            state.setError(ValidationResult::EXCEEDS_MAX_BLOCK_SIZE,
                          "Too many transactions");
            return false;
        }

        uint64_t totalFees = 0;
        uint32_t totalSigops = 0;

        for (size_t i = 0; i < transactions.size(); i++) {
            const auto& tx = transactions[i];
            TransactionValidationState txState;

            if (i == 0) {
                // Coinbase transaction
                uint64_t expectedReward = consensus->getBlockReward(block.getHeight());
                if (!validateCoinbase(tx, expectedReward + totalFees, txState)) {
                    state.setError(txState.result, "Coinbase: " + txState.errorMessage);
                    return false;
                }
            } else {
                // Regular transaction
                // Build UTXO set for this transaction
                std::vector<UTXOContext> txUtxos;
                for (const auto& input : tx.getInputs()) {
                    auto utxoIt = utxos.find(input.previousTxHash + ":" + 
                                            std::to_string(input.outputIndex));
                    if (utxoIt != utxos.end()) {
                        txUtxos.push_back(utxoIt->second);
                    }
                }

                if (!validateTransaction(tx, txUtxos, block.getHeight(), 
                                        block.getTimestamp(), txState)) {
                    state.setError(txState.result, "Transaction: " + txState.errorMessage);
                    return false;
                }
                totalFees += txState.fee;
            }

            // Check sigops
            totalSigops += tx.getSize() / 100; // Approximate
            if (totalSigops > 20000) {
                state.setError(ValidationResult::EXCEEDS_MAX_BLOCK_SIGOPS,
                              "Too many signature operations");
                return false;
            }
        }

        return true;
    }

    bool Validation::validateTransaction(const Transaction& tx,
                                         const std::vector<UTXOContext>& utxos,
                                         uint32_t currentHeight,
                                         uint32_t currentTime,
                                         TransactionValidationState& state) const {
        auto startTime = std::chrono::high_resolution_clock::now();

        // Check cache
        auto cacheIt = txCache.find(tx.getHash());
        if (cacheIt != txCache.end()) {
            state = cacheIt->second;
            updateValidationStats(0, state.isValid());
            return state.isValid();
        }

        // Check basic structure
        if (tx.getInputs().empty() || tx.getOutputs().empty()) {
            state.setError(ValidationResult::INVALID_TRANSACTION,
                          "Transaction has no inputs or outputs");
            txCache[tx.getHash()] = state;
            updateValidationStats(startTime, false);
            return false;
        }

        // Validate inputs
        if (!validateTransactionInputs(tx, utxos, state)) {
            txCache[tx.getHash()] = state;
            updateValidationStats(startTime, false);
            return false;
        }

        // Validate outputs
        if (!validateTransactionOutputs(tx, state)) {
            txCache[tx.getHash()] = state;
            updateValidationStats(startTime, false);
            return false;
        }

        // Validate lock time
        if (!validateLockTime(tx, currentHeight, currentTime, state)) {
            txCache[tx.getHash()] = state;
            updateValidationStats(startTime, false);
            return false;
        }

        // Validate sequence
        if (!validateSequence(tx, currentHeight, currentTime, state)) {
            txCache[tx.getHash()] = state;
            updateValidationStats(startTime, false);
            return false;
        }

        // Calculate fee
        uint64_t totalInput = 0;
        for (const auto& utxo : utxos) {
            totalInput += utxo.amount;
        }
        uint64_t totalOutput = tx.getTotalOutput();
        state.fee = totalInput - totalOutput;
        state.feeRate = static_cast<double>(state.fee) / tx.getVirtualSize();

        // Validate fee
        if (!validateFee(tx, calculateMinFee(tx), state)) {
            txCache[tx.getHash()] = state;
            updateValidationStats(startTime, false);
            return false;
        }

        state.setValid();
        state.txHash = tx.getHash();
        txCache[tx.getHash()] = state;

        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            endTime - startTime);
        state.validationTime = duration.count();

        updateValidationStats(startTime, true);

        if (onTransactionValidated) {
            onTransactionValidated(state);
        }

        return true;
    }

    bool Validation::validateTransaction(const Transaction& tx,
                                         const std::map<std::string, UTXOContext>& utxos,
                                         uint32_t currentHeight,
                                         uint32_t currentTime,
                                         TransactionValidationState& state) const {
        std::vector<UTXOContext> txUtxos;
        for (const auto& input : tx.getInputs()) {
            auto utxoIt = utxos.find(input.previousTxHash + ":" + 
                                    std::to_string(input.outputIndex));
            if (utxoIt != utxos.end()) {
                txUtxos.push_back(utxoIt->second);
            }
        }
        return validateTransaction(tx, txUtxos, currentHeight, currentTime, state);
    }

    bool Validation::validateMempoolTransaction(const Transaction& tx,
                                                const std::vector<Transaction>& mempool,
                                                const std::map<std::string, UTXOContext>& utxos,
                                                uint32_t currentHeight,
                                                uint32_t currentTime,
                                                TransactionValidationState& state) const {
        // Check for double spend in mempool
        if (isDoubleSpend(tx, mempool, utxos)) {
            state.setError(ValidationResult::DOUBLE_SPEND,
                          "Double spend detected in mempool");
            return false;
        }

        return validateTransaction(tx, utxos, currentHeight, currentTime, state);
    }

    bool Validation::validateTransactionInputs(const Transaction& tx,
                                               const std::vector<UTXOContext>& utxos,
                                               TransactionValidationState& state) const {
        if (tx.isCoinbase()) {
            return true; // Coinbase has special input rules
        }

        if (utxos.size() != tx.getInputs().size()) {
            state.setError(ValidationResult::INVALID_TRANSACTION,
                          "UTXO count mismatch");
            return false;
        }

        for (size_t i = 0; i < tx.getInputs().size(); i++) {
            const auto& input = tx.getInputs()[i];
            const auto& utxo = utxos[i];

            // Check UTXO maturity
            if (!utxo.isMature()) {
                state.setError(ValidationResult::INVALID_TRANSACTION,
                              "UTXO not mature");
                return false;
            }

            // Check signature
            ScriptContext scriptCtx;
            scriptCtx.script = std::vector<uint8_t>(utxo.address.begin(), 
                                                    utxo.address.end());
            scriptCtx.signature = input.signature;
            scriptCtx.publicKey = input.publicKey;
            scriptCtx.txHash = tx.getHash();
            scriptCtx.inputIndex = i;
            scriptCtx.amount = utxo.amount;

            if (!validateScript(scriptCtx, state)) {
                return false;
            }
        }

        return true;
    }

    bool Validation::validateTransactionOutputs(const Transaction& tx,
                                                TransactionValidationState& state) const {
        uint64_t totalOutput = 0;

        for (const auto& output : tx.getOutputs()) {
            // Check amount
            if (output.amount == 0) {
                state.setError(ValidationResult::INVALID_TRANSACTION,
                              "Zero amount output");
                return false;
            }

            if (output.amount > consensus->getMaxMoney()) {
                state.setError(ValidationResult::INVALID_TRANSACTION,
                              "Output amount exceeds maximum");
                return false;
            }

            // Check for dust
            if (isDust(output)) {
                state.setError(ValidationResult::NON_STANDARD_TRANSACTION,
                              "Dust output");
                return false;
            }

            // Check address format
            if (!Transaction::isValidAddress(output.address)) {
                state.setError(ValidationResult::INVALID_TRANSACTION,
                              "Invalid address format");
                return false;
            }

            totalOutput += output.amount;
        }

        // Check total output
        if (totalOutput > consensus->getMaxMoney()) {
            state.setError(ValidationResult::INVALID_TRANSACTION,
                          "Total output exceeds maximum");
            return false;
        }

        return true;
    }

    bool Validation::validateScript(const ScriptContext& context,
                                   TransactionValidationState& state) const {
        // Check cache
        std::string cacheKey = SHA256::hash(
            std::string(context.signature.begin(), context.signature.end()) +
            std::string(context.publicKey.begin(), context.publicKey.end()) +
            context.txHash + std::to_string(context.inputIndex));

        auto cacheIt = scriptCache.find(cacheKey);
        if (cacheIt != scriptCache.end()) {
            if (onScriptValidated) {
                onScriptValidated(cacheKey, cacheIt->second);
            }
            return cacheIt->second;
        }

        // Create message for signature
        std::string message = context.txHash + std::to_string(context.inputIndex) +
                             std::to_string(context.amount);

        // Verify signature
        bool valid = validateSignature(context.signature, context.publicKey, 
                                      message, state);

        scriptCache[cacheKey] = valid;

        if (onScriptValidated) {
            onScriptValidated(cacheKey, valid);
        }

        return valid;
    }

    bool Validation::validateScript(const std::vector<uint8_t>& script,
                                   const std::vector<uint8_t>& signature,
                                   const std::vector<uint8_t>& publicKey,
                                   const std::string& txHash,
                                   uint32_t inputIndex,
                                   uint64_t amount) const {
        ScriptContext context;
        context.script = script;
        context.signature = signature;
        context.publicKey = publicKey;
        context.txHash = txHash;
        context.inputIndex = inputIndex;
        context.amount = amount;

        TransactionValidationState state;
        return validateScript(context, state);
    }

    bool Validation::validatePayToPubKey(const std::vector<uint8_t>& script,
                                         const std::vector<uint8_t>& signature,
                                         const std::vector<uint8_t>& publicKey,
                                         const std::string& message) const {
        Secp256k1 secp256k1;
        return secp256k1.verify(message, signature, publicKey);
    }

    bool Validation::validatePayToPubKeyHash(const std::vector<uint8_t>& script,
                                             const std::vector<uint8_t>& signature,
                                             const std::vector<uint8_t>& publicKey,
                                             const std::string& message) const {
        // Check public key hash
        std::string pubKeyStr(publicKey.begin(), publicKey.end());
        std::string hash160 = RIPEMD160::hash(SHA256::hash(pubKeyStr));

        // Compare with script hash
        if (script.size() > 3) {
            // Extract hash from script (simplified)
            std::vector<uint8_t> scriptHash(script.begin() + 3, script.end() - 1);
            if (std::equal(scriptHash.begin(), scriptHash.end(), hash160.begin())) {
                Secp256k1 secp256k1;
                return secp256k1.verify(message, signature, publicKey);
            }
        }

        return false;
    }

    bool Validation::validateMultiSig(const std::vector<uint8_t>& script,
                                      const std::vector<std::vector<uint8_t>>& signatures,
                                      const std::vector<std::vector<uint8_t>>& publicKeys,
                                      const std::string& message) const {
        if (signatures.empty() || publicKeys.empty()) {
            return false;
        }

        Secp256k1 secp256k1;
        size_t validSigs = 0;
        size_t keyIndex = 0;

        for (const auto& sig : signatures) {
            while (keyIndex < publicKeys.size()) {
                if (secp256k1.verify(message, sig, publicKeys[keyIndex])) {
                    validSigs++;
                    keyIndex++;
                    break;
                }
                keyIndex++;
            }
        }

        // Check if we have enough valid signatures
        uint32_t required = 1; // Default
        if (script.size() > 0) {
            required = static_cast<uint32_t>(script[0] - 0x50); // OP_1 = 0x51
        }

        return validSigs >= required;
    }

    bool Validation::validateSignature(const std::vector<uint8_t>& signature,
                                       const std::vector<uint8_t>& publicKey,
                                       const std::string& message,
                                       TransactionValidationState& state) const {
        if (signature.empty() || publicKey.empty()) {
            state.setError(ValidationResult::INVALID_SIGNATURE,
                          "Empty signature or public key");
            return false;
        }

        Secp256k1 secp256k1;
        if (!secp256k1.verify(message, signature, publicKey)) {
            state.setError(ValidationResult::INVALID_SIGNATURE,
                          "Signature verification failed");
            return false;
        }

        return true;
    }

    bool Validation::validateLockTime(const Transaction& tx,
                                      uint32_t currentHeight,
                                      uint32_t currentTime,
                                      TransactionValidationState& state) const {
        uint32_t lockTime = tx.getLockTime();

        if (lockTime == 0) {
            return true;
        }

        if (lockTime < 500000000) {
            // Block height based
            if (currentHeight < lockTime) {
                state.setError(ValidationResult::INVALID_TRANSACTION,
                              "Transaction is timelocked (height)");
                return false;
            }
        } else {
            // Time based
            if (currentTime < lockTime) {
                state.setError(ValidationResult::INVALID_TRANSACTION,
                              "Transaction is timelocked (time)");
                return false;
            }
        }

        return true;
    }

    bool Validation::validateSequence(const Transaction& tx,
                                      uint32_t currentHeight,
                                      uint32_t currentTime,
                                      TransactionValidationState& state) const {
        for (const auto& input : tx.getInputs()) {
            if (input.sequence < 0xFFFFFFFF) {
                // Check if relative lock time is satisfied
                uint32_t relativeLock = input.sequence & 0xFFFF;
                if (relativeLock > 0) {
                    // TODO: Implement relative lock time validation
                }
            }
        }
        return true;
    }

    bool Validation::validateFee(const Transaction& tx,
                                 uint64_t minFee,
                                 TransactionValidationState& state) const {
        if (state.fee < minFee) {
            state.setError(ValidationResult::INSUFFICIENT_FEE,
                          "Insufficient fee: " + std::to_string(state.fee) + 
                          " < " + std::to_string(minFee));
            return false;
        }
        return true;
    }

    bool Validation::validateCoinbase(const Transaction& tx,
                                      uint64_t expectedReward,
                                      TransactionValidationState& state) const {
        if (tx.getType() != TransactionType::COINBASE) {
            state.setError(ValidationResult::INVALID_COINBASE,
                          "Not a coinbase transaction");
            return false;
        }

        if (tx.getInputs().size() != 1) {
            state.setError(ValidationResult::INVALID_COINBASE,
                          "Coinbase must have exactly one input");
            return false;
        }

        const auto& input = tx.getInputs()[0];
        if (input.previousTxHash != std::string(64, '0')) {
            state.setError(ValidationResult::INVALID_COINBASE,
                          "Invalid coinbase input");
            return false;
        }

        uint64_t totalOutput = tx.getTotalOutput();
        if (totalOutput > expectedReward + 10000) { // Allow small variance
            state.setError(ValidationResult::INVALID_COINBASE,
                          "Coinbase reward too high: " + 
                          std::to_string(totalOutput) + " > " +
                          std::to_string(expectedReward));
            return false;
        }

        state.fee = 0; // Coinbase has no fee
        return true;
    }

    bool Validation::validateStake(const Transaction& tx,
                                   uint64_t stakeAmount,
                                   uint32_t stakeAge,
                                   TransactionValidationState& state) const {
        if (tx.getType() != TransactionType::STAKE) {
            state.setError(ValidationResult::INVALID_TRANSACTION,
                          "Not a stake transaction");
            return false;
        }

        if (stakeAmount < 1000 * 100000000ULL) {
            state.setError(ValidationResult::INVALID_TRANSACTION,
                          "Stake amount too low");
            return false;
        }

        if (stakeAge < 8 * 60 * 60) {
            state.setError(ValidationResult::INVALID_TRANSACTION,
                          "Stake age too low");
            return false;
        }

        return true;
    }

    bool Validation::validateUTXO(const UTXOContext& utxo,
                                  const Transaction& spendingTx,
                                  TransactionValidationState& state) const {
        if (!utxo.isMature()) {
            state.setError(ValidationResult::INVALID_TRANSACTION,
                          "UTXO not mature");
            return false;
        }

        // Check if UTXO is already spent (would be handled by caller)

        return true;
    }

    bool Validation::validateUTXOSet(const std::map<std::string, UTXOContext>& utxos,
                                     const std::vector<Transaction>& transactions,
                                     TransactionValidationState& state) const {
        std::map<std::string, bool> spentUTXOs;

        for (const auto& tx : transactions) {
            for (const auto& input : tx.getInputs()) {
                std::string utxoKey = input.previousTxHash + ":" + 
                                     std::to_string(input.outputIndex);

                if (spentUTXOs[utxoKey]) {
                    state.setError(ValidationResult::DOUBLE_SPEND,
                                  "Double spend detected: " + utxoKey);
                    return false;
                }

                if (utxos.find(utxoKey) == utxos.end()) {
                    state.setError(ValidationResult::INVALID_TRANSACTION,
                                  "UTXO not found: " + utxoKey);
                    return false;
                }

                spentUTXOs[utxoKey] = true;
            }
        }

        return true;
    }

    bool Validation::validateChain(const std::vector<Block>& chain,
                                   BlockValidationState& state) const {
        if (chain.empty()) {
            return true;
        }

        std::map<std::string, UTXOContext> utxos;

        for (size_t i = 1; i < chain.size(); i++) {
            const auto& block = chain[i];
            const auto& previousBlock = chain[i - 1];

            std::vector<Transaction> mempool;
            if (!validateBlock(block, previousBlock, mempool, utxos, state)) {
                return false;
            }

            // Update UTXO set (simplified)
            for (const auto& tx : block.getTransactions()) {
                for (const auto& output : tx.getOutputs()) {
                    UTXOContext utxo;
                    utxo.txHash = tx.getHash();
                    utxo.address = output.address;
                    utxo.amount = output.amount;
                    utxo.blockHeight = block.getHeight();
                    utxo.isCoinbase = (tx.getType() == TransactionType::COINBASE);
                    utxo.confirmations = chain.size() - block.getHeight();
                    utxos[tx.getHash() + ":" + std::to_string(utxo.outputIndex)] = utxo;
                }
            }
        }

        return true;
    }

    bool Validation::validateChainWork(const std::vector<Block>& chain,
                                       const ChainWork& expectedWork,
                                       BlockValidationState& state) const {
        auto actualWork = consensus->calculateChainWork(chain);
        if (!consensus->isChainBetter(actualWork, expectedWork)) {
            state.setError(ValidationResult::CHAIN_REORGANIZATION,
                          "Chain work insufficient");
            return false;
        }
        return true;
    }

    uint64_t Validation::calculateMinFee(const Transaction& tx) const {
        return tx.getVirtualSize() * 10; // 10 satoshi per byte
    }

    bool Validation::isDoubleSpend(const Transaction& tx,
                                   const std::vector<Transaction>& mempool,
                                   const std::map<std::string, UTXOContext>& utxos) const {
        std::map<std::string, bool> spentUTXOs;

        // Check against mempool
        for (const auto& mempoolTx : mempool) {
            for (const auto& input : mempoolTx.getInputs()) {
                std::string utxoKey = input.previousTxHash + ":" + 
                                     std::to_string(input.outputIndex);
                spentUTXOs[utxoKey] = true;
            }
        }

        // Check against new transaction
        for (const auto& input : tx.getInputs()) {
            std::string utxoKey = input.previousTxHash + ":" + 
                                 std::to_string(input.outputIndex);
            if (spentUTXOs[utxoKey]) {
                return true;
            }
        }

        return false;
    }

    bool Validation::findDoubleSpends(const std::vector<Transaction>& transactions,
                                      std::vector<std::string>& doubleSpends) const {
        std::map<std::string, std::string> spentUTXOs;
        bool found = false;

        for (const auto& tx : transactions) {
            for (const auto& input : tx.getInputs()) {
                std::string utxoKey = input.previousTxHash + ":" + 
                                     std::to_string(input.outputIndex);

                auto it = spentUTXOs.find(utxoKey);
                if (it != spentUTXOs.end()) {
                    doubleSpends.push_back("UTXO " + utxoKey + " spent by " +
                                          it->second + " and " + tx.getHash());
                    found = true;
                } else {
                    spentUTXOs[utxoKey] = tx.getHash();
                }
            }
        }

        return found;
    }

    bool Validation::isOrphanBlock(const Block& block,
                                   const std::vector<Block>& chain) const {
        for (const auto& b : chain) {
            if (b.getHash() == block.getPreviousHash()) {
                return false;
            }
        }
        return true;
    }

    std::vector<Block> Validation::getOrphanBlocks(const std::vector<Block>& blocks,
                                                   const std::vector<Block>& chain) const {
        std::vector<Block> orphans;
        for (const auto& block : blocks) {
            if (isOrphanBlock(block, chain)) {
                orphans.push_back(block);
            }
        }
        return orphans;
    }

    void Validation::updateValidationStats(uint64_t startTime, bool success) const {
        totalValidations++;
        if (!success) {
            failedValidations++;
        }

        if (startTime > 0) {
            auto endTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::high_resolution_clock::now().time_since_epoch()).count();
            uint64_t validationTime = endTime - startTime;
            averageValidationTime = (averageValidationTime * (totalValidations - 1) + 
                                    validationTime) / totalValidations;
        }
    }

    void Validation::clearCache() {
        blockCache.clear();
        txCache.clear();
        scriptCache.clear();
    }

    void Validation::clearBlockCache() {
        blockCache.clear();
    }

    void Validation::clearTransactionCache() {
        txCache.clear();
    }

    void Validation::clearScriptCache() {
        scriptCache.clear();
    }

    double Validation::getSuccessRate() const {
        if (totalValidations == 0) return 0.0;
        return static_cast<double>(totalValidations - failedValidations) / 
               totalValidations * 100.0;
    }

    std::map<std::string, uint64_t> Validation::getErrorStatistics() const {
        std::map<std::string, uint64_t> errors;

        for (const auto& [hash, state] : blockCache) {
            if (!state.isValid()) {
                errors[state.errorMessage]++;
            }
        }

        for (const auto& [hash, state] : txCache) {
            if (!state.isValid()) {
                errors[state.errorMessage]++;
            }
        }

        return errors;
    }

    void Validation::setOnBlockValidated(std::function<void(const BlockValidationState&)> callback) {
        onBlockValidated = callback;
    }

    void Validation::setOnTransactionValidated(std::function<void(const TransactionValidationState&)> callback) {
        onTransactionValidated = callback;
    }

    void Validation::setOnScriptValidated(std::function<void(const std::string&, bool)> callback) {
        onScriptValidated = callback;
    }

    std::string Validation::resultToString(ValidationResult result) const {
        switch (result) {
            case ValidationResult::VALID:
                return "VALID";
            case ValidationResult::INVALID_BLOCK_VERSION:
                return "INVALID_BLOCK_VERSION";
            case ValidationResult::INVALID_PREVIOUS_HASH:
                return "INVALID_PREVIOUS_HASH";
            case ValidationResult::INVALID_TIMESTAMP:
                return "INVALID_TIMESTAMP";
            case ValidationResult::INVALID_DIFFICULTY:
                return "INVALID_DIFFICULTY";
            case ValidationResult::INVALID_MERKLE_ROOT:
                return "INVALID_MERKLE_ROOT";
            case ValidationResult::INVALID_PROOF_OF_WORK:
                return "INVALID_PROOF_OF_WORK";
            case ValidationResult::INVALID_PROOF_OF_STAKE:
                return "INVALID_PROOF_OF_STAKE";
            case ValidationResult::INVALID_TRANSACTION:
                return "INVALID_TRANSACTION";
            case ValidationResult::INVALID_COINBASE:
                return "INVALID_COINBASE";
            case ValidationResult::INVALID_SIGNATURE:
                return "INVALID_SIGNATURE";
            case ValidationResult::INVALID_SCRIPT:
                return "INVALID_SCRIPT";
            case ValidationResult::INSUFFICIENT_FEE:
                return "INSUFFICIENT_FEE";
            case ValidationResult::DOUBLE_SPEND:
                return "DOUBLE_SPEND";
            case ValidationResult::NON_STANDARD_TRANSACTION:
                return "NON_STANDARD_TRANSACTION";
            case ValidationResult::EXCEEDS_MAX_BLOCK_SIZE:
                return "EXCEEDS_MAX_BLOCK_SIZE";
            case ValidationResult::EXCEEDS_MAX_BLOCK_SIGOPS:
                return "EXCEEDS_MAX_BLOCK_SIGOPS";
            case ValidationResult::EXCEEDS_MAX_BLOCK_GAS:
                return "EXCEEDS_MAX_BLOCK_GAS";
            case ValidationResult::ORPHAN_BLOCK:
                return "ORPHAN_BLOCK";
            case ValidationResult::DUPLICATE_BLOCK:
                return "DUPLICATE_BLOCK";
            case ValidationResult::DUPLICATE_TRANSACTION:
                return "DUPLICATE_TRANSACTION";
            case ValidationResult::CHAIN_REORGANIZATION:
                return "CHAIN_REORGANIZATION";
            case ValidationResult::CONSENSUS_ERROR:
                return "CONSENSUS_ERROR";
            case ValidationResult::INTERNAL_ERROR:
                return "INTERNAL_ERROR";
            default:
                return "UNKNOWN_ERROR";
        }
    }

    void Validation::printStatistics() const {
        std::cout << "\n=== Validation Statistics ===\n";
        std::cout << "Total Validations: " << totalValidations << "\n";
        std::cout << "Failed Validations: " << failedValidations << "\n";
        std::cout << "Success Rate: " << getSuccessRate() << "%\n";
        std::cout << "Average Time: " << averageValidationTime << " ms\n";
        std::cout << "Block Cache: " << blockCache.size() << " entries\n";
        std::cout << "Tx Cache: " << txCache.size() << " entries\n";
        std::cout << "Script Cache: " << scriptCache.size() << " entries\n";
    }

    // ============== ValidationResultWrapper Implementation ==============

    ValidationResultWrapper::ValidationResultWrapper(ValidationResult r, const std::string& msg)
        : result(r), message(msg) {}

    bool ValidationResultWrapper::operator==(ValidationResult r) const {
        return result == r;
    }

    bool ValidationResultWrapper::operator!=(ValidationResult r) const {
        return result != r;
    }

    ValidationResultWrapper::operator bool() const {
        return result == ValidationResult::VALID;
    }

    ValidationResultWrapper ValidationResultWrapper::valid() {
        return ValidationResultWrapper(ValidationResult::VALID);
    }

    ValidationResultWrapper ValidationResultWrapper::error(ValidationResult r, const std::string& msg) {
        return ValidationResultWrapper(r, msg);
    }

    // ============== ValidationContext Implementation ==============

    ValidationContext::ValidationContext() : currentHeight(0), currentTime(0) {}

    void ValidationContext::addBlock(const Block& block) {
        blocks.push_back(block);
    }

    void ValidationContext::addTransaction(const Transaction& tx) {
        transactions.push_back(tx);
    }

    void ValidationContext::addUTXO(const UTXOContext& utxo) {
        utxos[utxo.txHash + ":" + std::to_string(utxo.outputIndex)] = utxo;
    }

    void ValidationContext::setCurrentHeight(uint32_t height) {
        currentHeight = height;
    }

    void ValidationContext::setCurrentTime(uint32_t time) {
        currentTime = time;
    }

    bool ValidationContext::validateAll(std::vector<ValidationResultWrapper>& results) const {
        bool allValid = true;
        results.clear();

        // Validate blocks
        std::vector<ValidationResultWrapper> blockResults;
        if (!validateBlocks(blockResults)) {
            allValid = false;
            results.insert(results.end(), blockResults.begin(), blockResults.end());
        }

        // Validate transactions
        std::vector<ValidationResultWrapper> txResults;
        if (!validateTransactions(txResults)) {
            allValid = false;
            results.insert(results.end(), txResults.begin(), txResults.end());
        }

        return allValid;
    }

    bool ValidationContext::validateBlocks(std::vector<ValidationResultWrapper>& results) const {
        bool allValid = true;
        Validation validation;

        for (const auto& block : blocks) {
            BlockValidationState state;
            if (!validation.validateBlock(block, {}, {}, utxos, state)) {
                allValid = false;
                results.push_back(ValidationResultWrapper::error(
                    state.result, state.errorMessage));
            }
        }

        return allValid;
    }

    bool ValidationContext::validateTransactions(std::vector<ValidationResultWrapper>& results) const {
        bool allValid = true;
        Validation validation;

        for (const auto& tx : transactions) {
            TransactionValidationState state;
            std::vector<UTXOContext> txUtxos;

            for (const auto& input : tx.getInputs()) {
                auto utxoIt = utxos.find(input.previousTxHash + ":" + 
                                        std::to_string(input.outputIndex));
                if (utxoIt != utxos.end()) {
                    txUtxos.push_back(utxoIt->second);
                }
            }

            if (!validation.validateTransaction(tx, txUtxos, currentHeight, 
                                               currentTime, state)) {
                allValid = false;
                results.push_back(ValidationResultWrapper::error(
                    state.result, state.errorMessage));
            }
        }

        return allValid;
    }

    void ValidationContext::clear() {
        blocks.clear();
        transactions.clear();
        utxos.clear();
        currentHeight = 0;
        currentTime = 0;
    }

    // ============== Static Helper Methods ==============

    bool Validation::isStandardOutput(const TxOutput& output) {
        if (output.amount < getDustThreshold(output)) {
            return false;
        }

        // Check script pattern
        std::vector<uint8_t> script(output.scriptPubKey.begin(), 
                                    output.scriptPubKey.end());

        if (script.empty()) return false;

        // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        if (script.size() == 25 && script[0] == 0x76 && script[1] == 0xa9 &&
            script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac) {
            return true;
        }

        // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
        if (script.size() == 23 && script[0] == 0xa9 && 
            script[1] == 0x14 && script[22] == 0x87) {
            return true;
        }

        return false;
    }

    bool Validation::isStandardInput(const TxInput& input) {
        // Check scriptSig is push-only
        std::vector<uint8_t> script(input.scriptSig.begin(), input.scriptSig.end());
        return Script::isPushOnly(script);
    }

    bool Validation::isDust(const TxOutput& output) {
        return output.amount < getDustThreshold(output);
    }

    uint64_t Validation::getDustThreshold(const TxOutput& output) {
        // Dust threshold = 3 * (input size + output size) * minRelayFee
        return 3 * (41 + output.getSize()) * 1000; // 1000 sat/byte min relay fee
    }

    bool Validation::isStandardScript(const std::vector<uint8_t>& script) {
        // Check for non-standard opcodes
        for (auto byte : script) {
            OpCode op = static_cast<OpCode>(byte);
            if (op > OpCode::OP_16 && op < OpCode::OP_NOP) {
                return false;
            }
        }
        return true;
    }

    bool Validation::isWitnessProgram(const std::vector<uint8_t>& script) {
        return script.size() >= 4 && script.size() <= 42 && 
               script[0] >= 0x00 && script[0] <= 0x10;
    }

    uint32_t Validation::getWitnessVersion(const std::vector<uint8_t>& script) {
        if (isWitnessProgram(script)) {
            return static_cast<uint32_t>(script[0]);
        }
        return 0;
    }

} // namespace powercoin