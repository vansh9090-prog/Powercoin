#include "transaction.h"
#include "../crypto/sha256.h"
#include "../crypto/ripemd160.h"
#include "../crypto/secp256k1.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>

namespace powercoin {

    // ============== TxInput Implementation ==============

    TxInput::TxInput() 
        : outputIndex(0), sequence(0xFFFFFFFF) {}

    std::string TxInput::serialize() const {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        ss << previousTxHash;
        ss << std::setw(8) << outputIndex;
        ss << std::setw(8) << sequence;
        
        // Write scriptSig length and data
        ss << std::setw(8) << scriptSig.length();
        ss << scriptSig;
        
        // Write signature and public key
        ss << std::setw(8) << signature.size();
        for (auto byte : signature) {
            ss << std::setw(2) << (int)byte;
        }
        
        ss << std::setw(8) << publicKey.size();
        for (auto byte : publicKey) {
            ss << std::setw(2) << (int)byte;
        }
        
        return ss.str();
    }

    bool TxInput::deserialize(const std::string& data) {
        size_t pos = 0;
        
        previousTxHash = data.substr(pos, 64); pos += 64;
        outputIndex = std::stoul(data.substr(pos, 8), nullptr, 16); pos += 8;
        sequence = std::stoul(data.substr(pos, 8), nullptr, 16); pos += 8;
        
        // Read scriptSig
        uint32_t scriptLen = std::stoul(data.substr(pos, 8), nullptr, 16); pos += 8;
        scriptSig = data.substr(pos, scriptLen); pos += scriptLen;
        
        // Read signature
        uint32_t sigLen = std::stoul(data.substr(pos, 8), nullptr, 16); pos += 8;
        signature.clear();
        for (uint32_t i = 0; i < sigLen; i++) {
            signature.push_back(std::stoul(data.substr(pos + i*2, 2), nullptr, 16));
        }
        pos += sigLen * 2;
        
        // Read public key
        uint32_t keyLen = std::stoul(data.substr(pos, 8), nullptr, 16); pos += 8;
        publicKey.clear();
        for (uint32_t i = 0; i < keyLen; i++) {
            publicKey.push_back(std::stoul(data.substr(pos + i*2, 2), nullptr, 16));
        }
        
        return true;
    }

    size_t TxInput::getSize() const {
        return previousTxHash.length() + 
               sizeof(outputIndex) + 
               sizeof(sequence) + 
               scriptSig.length() + 
               signature.size() + 
               publicKey.size() + 
               24; // Overhead
    }

    // ============== TxOutput Implementation ==============

    TxOutput::TxOutput() : amount(0), lockTime(0) {}

    std::string TxOutput::serialize() const {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        ss << std::setw(16) << amount;
        ss << scriptPubKey;
        ss << address;
        ss << std::setw(8) << lockTime;
        return ss.str();
    }

    bool TxOutput::deserialize(const std::string& data) {
        size_t pos = 0;
        
        amount = std::stoull(data.substr(pos, 16), nullptr, 16); pos += 16;
        
        // ScriptPubKey is variable length, in production would have length prefix
        scriptPubKey = data.substr(pos, 40); pos += 40;
        address = data.substr(pos, 34); pos += 34;
        lockTime = std::stoul(data.substr(pos, 8), nullptr, 16);
        
        return true;
    }

    size_t TxOutput::getSize() const {
        return sizeof(amount) + scriptPubKey.length() + address.length() + sizeof(lockTime);
    }

    bool TxOutput::isSpendable() const {
        // Check if output is not locked
        return lockTime == 0;
    }

    // ============== UTXO Implementation ==============

    UTXO::UTXO() 
        : outputIndex(0), amount(0), blockHeight(0), 
          isCoinbase(false), confirmations(0) {}

    std::string UTXO::toString() const {
        std::stringstream ss;
        ss << "UTXO: " << txHash << ":" << outputIndex << "\n";
        ss << "  Address: " << address << "\n";
        ss << "  Amount: " << amount / 100000000.0 << " PWR\n";
        ss << "  Block: " << blockHeight << "\n";
        ss << "  Confirmations: " << confirmations << "\n";
        return ss.str();
    }

    bool UTXO::isMature() const {
        // Coinbase outputs need 100 confirmations
        if (isCoinbase) {
            return confirmations >= 100;
        }
        return true;
    }

    // ============== Transaction Implementation ==============

    Transaction::Transaction() 
        : type(TransactionType::TRANSFER), 
          version(CURRENT_VERSION),
          lockTime(0),
          timestamp(std::time(nullptr)),
          fee(0),
          hashValidated(false) {}

    Transaction::Transaction(TransactionType t) 
        : type(t),
          version(CURRENT_VERSION),
          lockTime(0),
          timestamp(std::time(nullptr)),
          fee(0),
          hashValidated(false) {}

    Transaction::Transaction(const Transaction& other)
        : txHash(other.txHash),
          type(other.type),
          version(other.version),
          lockTime(other.lockTime),
          timestamp(other.timestamp),
          inputs(other.inputs),
          outputs(other.outputs),
          fee(other.fee),
          hashValidated(other.hashValidated),
          cachedHash(other.cachedHash) {}

    Transaction& Transaction::operator=(const Transaction& other) {
        if (this != &other) {
            txHash = other.txHash;
            type = other.type;
            version = other.version;
            lockTime = other.lockTime;
            timestamp = other.timestamp;
            inputs = other.inputs;
            outputs = other.outputs;
            fee = other.fee;
            hashValidated = other.hashValidated;
            cachedHash = other.cachedHash;
        }
        return *this;
    }

    Transaction::Transaction(Transaction&& other) noexcept
        : txHash(std::move(other.txHash)),
          type(other.type),
          version(other.version),
          lockTime(other.lockTime),
          timestamp(other.timestamp),
          inputs(std::move(other.inputs)),
          outputs(std::move(other.outputs)),
          fee(other.fee),
          hashValidated(other.hashValidated),
          cachedHash(std::move(other.cachedHash)) {
        other.type = TransactionType::TRANSFER;
        other.version = 0;
        other.lockTime = 0;
        other.timestamp = 0;
        other.fee = 0;
        other.hashValidated = false;
    }

    Transaction& Transaction::operator=(Transaction&& other) noexcept {
        if (this != &other) {
            txHash = std::move(other.txHash);
            type = other.type;
            version = other.version;
            lockTime = other.lockTime;
            timestamp = other.timestamp;
            inputs = std::move(other.inputs);
            outputs = std::move(other.outputs);
            fee = other.fee;
            hashValidated = other.hashValidated;
            cachedHash = std::move(other.cachedHash);
            
            other.type = TransactionType::TRANSFER;
            other.version = 0;
            other.lockTime = 0;
            other.timestamp = 0;
            other.fee = 0;
            other.hashValidated = false;
        }
        return *this;
    }

    bool Transaction::operator==(const Transaction& other) const {
        return txHash == other.txHash;
    }

    bool Transaction::operator!=(const Transaction& other) const {
        return !(*this == other);
    }

    void Transaction::addInput(const TxInput& input) {
        inputs.push_back(input);
        hashValidated = false;
    }

    void Transaction::addInput(const std::string& prevTxHash, uint32_t index) {
        TxInput input;
        input.previousTxHash = prevTxHash;
        input.outputIndex = index;
        input.sequence = 0xFFFFFFFF;
        inputs.push_back(input);
        hashValidated = false;
    }

    void Transaction::addInput(const std::string& prevTxHash, uint32_t index,
                               const std::vector<uint8_t>& signature,
                               const std::vector<uint8_t>& pubKey) {
        TxInput input;
        input.previousTxHash = prevTxHash;
        input.outputIndex = index;
        input.sequence = 0xFFFFFFFF;
        input.signature = signature;
        input.publicKey = pubKey;
        inputs.push_back(input);
        hashValidated = false;
    }

    bool Transaction::removeInput(uint32_t index) {
        if (index < inputs.size()) {
            inputs.erase(inputs.begin() + index);
            hashValidated = false;
            return true;
        }
        return false;
    }

    void Transaction::clearInputs() {
        inputs.clear();
        hashValidated = false;
    }

    void Transaction::addOutput(const TxOutput& output) {
        outputs.push_back(output);
        hashValidated = false;
    }

    void Transaction::addOutput(const std::string& address, uint64_t amount) {
        TxOutput output;
        output.address = address;
        output.amount = amount;
        output.scriptPubKey = "P2PKH:" + address;
        outputs.push_back(output);
        hashValidated = false;
    }

    void Transaction::addOutput(const std::string& address, uint64_t amount,
                                const std::string& script) {
        TxOutput output;
        output.address = address;
        output.amount = amount;
        output.scriptPubKey = script;
        outputs.push_back(output);
        hashValidated = false;
    }

    bool Transaction::removeOutput(uint32_t index) {
        if (index < outputs.size()) {
            outputs.erase(outputs.begin() + index);
            hashValidated = false;
            return true;
        }
        return false;
    }

    void Transaction::clearOutputs() {
        outputs.clear();
        hashValidated = false;
    }

    bool Transaction::signInput(uint32_t inputIndex, const std::vector<uint8_t>& privateKey) {
        if (inputIndex >= inputs.size()) {
            return false;
        }

        // Create signature hash
        std::string message = txHash + std::to_string(inputIndex);
        
        // Sign with private key
        Secp256k1 secp256k1;
        auto signature = secp256k1.sign(message, privateKey);
        
        if (!signature.empty()) {
            inputs[inputIndex].signature = signature;
            return true;
        }
        
        return false;
    }

    bool Transaction::verifyInput(uint32_t inputIndex, const std::vector<uint8_t>& publicKey) const {
        if (inputIndex >= inputs.size()) {
            return false;
        }

        const auto& input = inputs[inputIndex];
        if (input.signature.empty()) {
            return false;
        }

        // Verify signature
        Secp256k1 secp256k1;
        std::string message = txHash + std::to_string(inputIndex);
        
        return secp256k1.verify(message, input.signature, publicKey);
    }

    bool Transaction::verifySignature(const std::string& message,
                                      const std::vector<uint8_t>& signature,
                                      const std::vector<uint8_t>& publicKey) const {
        Secp256k1 secp256k1;
        return secp256k1.verify(message, signature, publicKey);
    }

    void Transaction::calculateHash() {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        ss << static_cast<int>(type);
        ss << std::setw(8) << version;
        ss << std::setw(8) << lockTime;
        ss << std::setw(8) << timestamp;
        
        for (const auto& input : inputs) {
            ss << input.serialize();
        }
        
        for (const auto& output : outputs) {
            ss << output.serialize();
        }
        
        txHash = SHA256::doubleHash(ss.str());
        cachedHash = txHash;
        hashValidated = true;
    }

    bool Transaction::validateHash() const {
        if (!hashValidated) {
            const_cast<Transaction*>(this)->calculateHash();
        }
        return SHA256::doubleHash(serialize()) == txHash;
    }

    std::string Transaction::getWitnessHash() const {
        // Witness hash excludes witness data
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        ss << static_cast<int>(type);
        ss << std::setw(8) << version;
        ss << std::setw(8) << lockTime;
        ss << std::setw(8) << timestamp;
        
        for (const auto& input : inputs) {
            ss << input.previousTxHash;
            ss << std::setw(8) << input.outputIndex;
            ss << std::setw(8) << input.sequence;
        }
        
        for (const auto& output : outputs) {
            ss << output.serialize();
        }
        
        return SHA256::doubleHash(ss.str());
    }

    uint64_t Transaction::calculateFee() const {
        return getTotalInput() - getTotalOutput();
    }

    uint64_t Transaction::calculateMinFee() const {
        // Minimum fee based on transaction size
        uint64_t baseFee = getVirtualSize() * 10; // 10 satoshi per byte
        return std::max(baseFee, MIN_FEE);
    }

    bool Transaction::hasEnoughFee() const {
        fee = calculateFee();
        return fee >= calculateMinFee();
    }

    uint32_t Transaction::getSize() const {
        uint32_t size = sizeof(type) + sizeof(version) + 
                        sizeof(lockTime) + sizeof(timestamp);
        
        for (const auto& input : inputs) {
            size += input.getSize();
        }
        
        for (const auto& output : outputs) {
            size += output.getSize();
        }
        
        return size;
    }

    uint32_t Transaction::getBaseSize() const {
        // Size without witness data
        uint32_t size = sizeof(type) + sizeof(version) + 
                        sizeof(lockTime) + sizeof(timestamp);
        
        for (const auto& input : inputs) {
            size += input.previousTxHash.length() + 
                    sizeof(input.outputIndex) + 
                    sizeof(input.sequence);
        }
        
        for (const auto& output : outputs) {
            size += output.getSize();
        }
        
        return size;
    }

    uint32_t Transaction::getWitnessSize() const {
        uint32_t size = 0;
        for (const auto& input : inputs) {
            size += input.signature.size() + input.publicKey.size();
        }
        return size;
    }

    uint64_t Transaction::getVirtualSize() const {
        // Weighted size: (base * 3 + total) / 4
        return (getBaseSize() * 3 + getSize()) / 4;
    }

    uint64_t Transaction::getTotalInput() const {
        uint64_t total = 0;
        // In production, would fetch from UTXO set
        for (const auto& input : inputs) {
            // Placeholder - actual value from UTXO
            total += 100000000; // 1 PWR
        }
        return total;
    }

    uint64_t Transaction::getTotalOutput() const {
        uint64_t total = 0;
        for (const auto& output : outputs) {
            total += output.amount;
        }
        return total;
    }

    bool Transaction::validate() const {
        // Check basic structure
        if (inputs.empty() || outputs.empty()) {
            return false;
        }

        // Check amounts
        if (!validateInputs() || !validateOutputs()) {
            return false;
        }

        // Check fee
        if (!hasEnoughFee()) {
            return false;
        }

        // Check hash
        if (!validateHash()) {
            return false;
        }

        return true;
    }

    bool Transaction::validateInputs() const {
        for (const auto& input : inputs) {
            // Check input format
            if (input.previousTxHash.length() != 64) {
                return false;
            }
            
            // Verify signature for non-coinbase
            if (!isCoinbase() && input.signature.empty()) {
                return false;
            }
        }
        return true;
    }

    bool Transaction::validateOutputs() const {
        uint64_t totalOutput = 0;
        
        for (const auto& output : outputs) {
            // Check amount
            if (output.amount == 0 || output.amount > MAX_MONEY) {
                return false;
            }
            
            // Check address format
            if (!isValidAddress(output.address)) {
                return false;
            }
            
            totalOutput += output.amount;
        }
        
        // Check total output doesn't exceed maximum
        if (totalOutput > MAX_MONEY) {
            return false;
        }
        
        return true;
    }

    bool Transaction::validateLockTime(uint32_t currentHeight, uint32_t currentTime) const {
        if (lockTime == 0) {
            return true;
        }
        
        if (lockTime < 500000000) {
            // Block height based
            return currentHeight >= lockTime;
        } else {
            // Time based
            return currentTime >= lockTime;
        }
    }

    std::string Transaction::serialize() const {
        std::stringstream ss;
        ss << txHash << "\n";
        ss << static_cast<int>(type) << "\n";
        ss << version << "\n";
        ss << lockTime << "\n";
        ss << timestamp << "\n";
        ss << fee << "\n";
        ss << inputs.size() << "\n";
        
        for (const auto& input : inputs) {
            ss << input.serialize() << "\n";
        }
        
        ss << outputs.size() << "\n";
        for (const auto& output : outputs) {
            ss << output.serialize() << "\n";
        }
        
        return ss.str();
    }

    bool Transaction::deserialize(const std::string& data) {
        std::stringstream ss(data);
        std::string line;
        
        std::getline(ss, txHash);
        
        std::getline(ss, line);
        type = static_cast<TransactionType>(std::stoi(line));
        
        std::getline(ss, line);
        version = std::stoul(line);
        
        std::getline(ss, line);
        lockTime = std::stoul(line);
        
        std::getline(ss, line);
        timestamp = std::stoul(line);
        
        std::getline(ss, line);
        fee = std::stoull(line);
        
        std::getline(ss, line);
        size_t inputCount = std::stoul(line);
        
        inputs.clear();
        for (size_t i = 0; i < inputCount; i++) {
            std::getline(ss, line);
            TxInput input;
            if (input.deserialize(line)) {
                inputs.push_back(input);
            }
        }
        
        std::getline(ss, line);
        size_t outputCount = std::stoul(line);
        
        outputs.clear();
        for (size_t i = 0; i < outputCount; i++) {
            std::getline(ss, line);
            TxOutput output;
            if (output.deserialize(line)) {
                outputs.push_back(output);
            }
        }
        
        return true;
    }

    std::vector<uint8_t> Transaction::serializeBinary() const {
        std::vector<uint8_t> data;
        // TODO: Implement binary serialization
        return data;
    }

    bool Transaction::deserializeBinary(const std::vector<uint8_t>& data) {
        // TODO: Implement binary deserialization
        return false;
    }

    TransactionStats Transaction::getStats() const {
        TransactionStats stats;
        stats.hash = txHash;
        stats.type = type;
        stats.version = version;
        stats.size = getSize();
        stats.virtualSize = getVirtualSize();
        stats.inputCount = inputs.size();
        stats.outputCount = outputs.size();
        stats.totalInput = getTotalInput();
        stats.totalOutput = getTotalOutput();
        stats.fee = calculateFee();
        stats.feeRate = getFeeRate();
        stats.lockTime = lockTime;
        stats.timestamp = timestamp;
        stats.blockHeight = 0;
        stats.confirmations = 0;
        return stats;
    }

    double Transaction::getFeeRate() const {
        return static_cast<double>(fee) / getVirtualSize();
    }

    std::string Transaction::toString() const {
        std::stringstream ss;
        ss << "Transaction: " << txHash.substr(0, 16) << "...\n";
        ss << "  Type: " << static_cast<int>(type) << "\n";
        ss << "  Version: " << version << "\n";
        ss << "  Inputs: " << inputs.size() << "\n";
        ss << "  Outputs: " << outputs.size() << "\n";
        ss << "  Fee: " << fee / 100000000.0 << " PWR\n";
        ss << "  Size: " << getSize() << " bytes\n";
        return ss.str();
    }

    void Transaction::print() const {
        std::cout << toString();
    }

    Transaction Transaction::createCoinbase(const std::string& address, uint64_t amount) {
        Transaction tx(TransactionType::COINBASE);
        
        // Coinbase input (special)
        TxInput input;
        input.previousTxHash = std::string(64, '0');
        input.outputIndex = 0xFFFFFFFF;
        tx.addInput(input);
        
        // Output to miner
        tx.addOutput(address, amount);
        
        tx.calculateHash();
        return tx;
    }

    Transaction Transaction::createTransfer(const std::string& from,
                                           const std::string& to,
                                           uint64_t amount,
                                           uint64_t fee) {
        Transaction tx;
        
        // Add input from UTXO (simplified)
        tx.addInput("dummy_tx_hash", 0);
        
        // Add output to recipient
        tx.addOutput(to, amount);
        
        // Add change output
        tx.addOutput(from, amount - fee);
        
        tx.calculateHash();
        return tx;
    }

    Transaction Transaction::createPrivateTransfer(const std::string& from,
                                                  const std::string& stealthAddress,
                                                  uint64_t amount) {
        Transaction tx(TransactionType::PRIVATE);
        // TODO: Implement private transaction creation
        return tx;
    }

    bool Transaction::isValidAddress(const std::string& address) {
        // Basic P2PKH address validation
        if (address.empty() || address.length() < 26 || address.length() > 35) {
            return false;
        }
        
        // Check prefix
        if (address.substr(0, 3) != "PWR" && address[0] != '1') {
            return false;
        }
        
        // TODO: Add checksum validation
        
        return true;
    }

    bool Transaction::isValidAmount(uint64_t amount) {
        return amount > 0 && amount <= MAX_MONEY;
    }

    // ============== TransactionBuilder Implementation ==============

    TransactionBuilder::TransactionBuilder() 
        : fee(Transaction::MIN_FEE), type(TransactionType::TRANSFER), lockTime(0) {}

    TransactionBuilder& TransactionBuilder::addUTXO(const std::string& txHash, uint32_t index) {
        utxos.push_back({txHash, index});
        return *this;
    }

    TransactionBuilder& TransactionBuilder::addOutput(const std::string& address, uint64_t amount) {
        outputs[address] += amount;
        return *this;
    }

    TransactionBuilder& TransactionBuilder::setFee(uint64_t feeRate) {
        fee = feeRate;
        return *this;
    }

    TransactionBuilder& TransactionBuilder::setType(TransactionType t) {
        type = t;
        return *this;
    }

    TransactionBuilder& TransactionBuilder::setLockTime(uint32_t lt) {
        lockTime = lt;
        return *this;
    }

    Transaction TransactionBuilder::build(const std::vector<uint8_t>& privateKey) {
        Transaction tx(type);
        tx.setLockTime(lockTime);
        
        // Add UTXOs as inputs
        for (const auto& utxo : utxos) {
            tx.addInput(utxo.first, utxo.second);
        }
        
        // Add outputs
        for (const auto& [address, amount] : outputs) {
            tx.addOutput(address, amount);
        }
        
        tx.calculateHash();
        
        // Sign inputs
        for (size_t i = 0; i < tx.getInputs().size(); i++) {
            tx.signInput(i, privateKey);
        }
        
        return tx;
    }

    Transaction TransactionBuilder::buildWithChange(const std::vector<uint8_t>& privateKey,
                                                   const std::string& changeAddress) {
        // Calculate total input (simplified)
        uint64_t totalInput = utxos.size() * 100000000; // 1 PWR per UTXO
        
        // Calculate total output
        uint64_t totalOutput = 0;
        for (const auto& [address, amount] : outputs) {
            totalOutput += amount;
        }
        
        // Add change if needed
        if (totalInput > totalOutput + fee) {
            outputs[changeAddress] = totalInput - totalOutput - fee;
        }
        
        return build(privateKey);
    }

} // namespace powercoin