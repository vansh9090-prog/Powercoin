#include "block.h"
#include "../crypto/sha256.h"
#include "../crypto/ripemd160.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>

namespace powercoin {

    // Genesis block constants
    const std::string Block::GENESIS_HASH = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";
    const std::string Block::GENESIS_PREVIOUS_HASH = std::string(64, '0');

    BlockHeader::BlockHeader() 
        : version(1), timestamp(0), bits(0x1d00ffff), nonce(0) {}

    std::string BlockHeader::serialize() const {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        ss << std::setw(8) << version;
        ss << previousBlockHash;
        ss << merkleRoot;
        ss << std::setw(8) << timestamp;
        ss << std::setw(8) << bits;
        ss << std::setw(8) << nonce;
        return ss.str();
    }

    bool BlockHeader::deserialize(const std::string& data) {
        if (data.length() < 8 + 64 + 64 + 8 + 8 + 8) {
            return false;
        }
        
        size_t pos = 0;
        version = std::stoul(data.substr(pos, 8), nullptr, 16); pos += 8;
        previousBlockHash = data.substr(pos, 64); pos += 64;
        merkleRoot = data.substr(pos, 64); pos += 64;
        timestamp = std::stoul(data.substr(pos, 8), nullptr, 16); pos += 8;
        bits = std::stoul(data.substr(pos, 8), nullptr, 16); pos += 8;
        nonce = std::stoul(data.substr(pos, 8), nullptr, 16);
        
        return true;
    }

    std::string BlockHeader::calculateHash() const {
        return SHA256::doubleHash(serialize());
    }

    uint64_t BlockHeader::getWork() const {
        // Work is 2^256 / (target + 1)
        // Simplified calculation
        uint64_t target = bits & 0x007fffff;
        int32_t exponent = ((bits >> 24) & 0xff) - 3;
        return (uint64_t)std::pow(2.0, 256 - 8 * exponent) / (target + 1);
    }

    Block::Block() 
        : height(0), cachedWork(0), merkleRootValidated(false) {
        header.version = 1;
    }

    Block::Block(uint32_t h) 
        : height(h), cachedWork(0), merkleRootValidated(false) {
        header.version = 1;
        header.timestamp = std::time(nullptr);
    }

    Block::Block(const Block& other)
        : header(other.header),
          transactions(other.transactions),
          height(other.height),
          blockHash(other.blockHash),
          cachedWork(other.cachedWork),
          merkleRootValidated(other.merkleRootValidated),
          cachedMerkleRoot(other.cachedMerkleRoot) {}

    Block& Block::operator=(const Block& other) {
        if (this != &other) {
            header = other.header;
            transactions = other.transactions;
            height = other.height;
            blockHash = other.blockHash;
            cachedWork = other.cachedWork;
            merkleRootValidated = other.merkleRootValidated;
            cachedMerkleRoot = other.cachedMerkleRoot;
        }
        return *this;
    }

    Block::Block(Block&& other) noexcept
        : header(std::move(other.header)),
          transactions(std::move(other.transactions)),
          height(other.height),
          blockHash(std::move(other.blockHash)),
          cachedWork(other.cachedWork),
          merkleRootValidated(other.merkleRootValidated),
          cachedMerkleRoot(std::move(other.cachedMerkleRoot)) {
        other.height = 0;
        other.cachedWork = 0;
        other.merkleRootValidated = false;
    }

    Block& Block::operator=(Block&& other) noexcept {
        if (this != &other) {
            header = std::move(other.header);
            transactions = std::move(other.transactions);
            height = other.height;
            blockHash = std::move(other.blockHash);
            cachedWork = other.cachedWork;
            merkleRootValidated = other.merkleRootValidated;
            cachedMerkleRoot = std::move(other.cachedMerkleRoot);
            
            other.height = 0;
            other.cachedWork = 0;
            other.merkleRootValidated = false;
        }
        return *this;
    }

    bool Block::operator==(const Block& other) const {
        return blockHash == other.blockHash;
    }

    bool Block::operator!=(const Block& other) const {
        return !(*this == other);
    }

    void Block::addTransaction(const Transaction& tx) {
        transactions.push_back(tx);
        merkleRootValidated = false;
    }

    void Block::addTransaction(Transaction&& tx) {
        transactions.push_back(std::move(tx));
        merkleRootValidated = false;
    }

    bool Block::removeTransaction(const std::string& txHash) {
        auto it = std::find_if(transactions.begin(), transactions.end(),
            [&txHash](const Transaction& tx) {
                return tx.getHash() == txHash;
            });
        
        if (it != transactions.end()) {
            transactions.erase(it);
            merkleRootValidated = false;
            return true;
        }
        return false;
    }

    void Block::clearTransactions() {
        transactions.clear();
        merkleRootValidated = false;
    }

    bool Block::hasTransaction(const std::string& txHash) const {
        return std::any_of(transactions.begin(), transactions.end(),
            [&txHash](const Transaction& tx) {
                return tx.getHash() == txHash;
            });
    }

    const Transaction* Block::getTransaction(const std::string& txHash) const {
        auto it = std::find_if(transactions.begin(), transactions.end(),
            [&txHash](const Transaction& tx) {
                return tx.getHash() == txHash;
            });
        
        return (it != transactions.end()) ? &(*it) : nullptr;
    }

    void Block::calculateMerkleRoot() {
        if (transactions.empty()) {
            header.merkleRoot = SHA256::doubleHash("empty");
            cachedMerkleRoot = header.merkleRoot;
            merkleRootValidated = true;
            return;
        }

        std::vector<std::string> hashes;
        for (const auto& tx : transactions) {
            hashes.push_back(tx.getHash());
        }

        while (hashes.size() > 1) {
            if (hashes.size() % 2 == 1) {
                hashes.push_back(hashes.back());
            }

            std::vector<std::string> newHashes;
            for (size_t i = 0; i < hashes.size(); i += 2) {
                newHashes.push_back(SHA256::doubleHash(hashes[i] + hashes[i + 1]));
            }
            hashes = std::move(newHashes);
        }

        header.merkleRoot = hashes[0];
        cachedMerkleRoot = header.merkleRoot;
        merkleRootValidated = true;
    }

    bool Block::validateMerkleRoot() const {
        if (!merkleRootValidated) {
            Block* nonConstThis = const_cast<Block*>(this);
            nonConstThis->calculateMerkleRoot();
        }
        return header.merkleRoot == cachedMerkleRoot;
    }

    std::string Block::buildMerkleTree() const {
        if (transactions.empty()) {
            return "empty";
        }

        std::vector<std::string> tree;
        for (const auto& tx : transactions) {
            tree.push_back(tx.getHash());
        }

        size_t level = 0;
        while (tree.size() > 1) {
            std::vector<std::string> newLevel;
            for (size_t i = 0; i < tree.size(); i += 2) {
                if (i + 1 < tree.size()) {
                    newLevel.push_back(SHA256::doubleHash(tree[i] + tree[i + 1]));
                } else {
                    newLevel.push_back(SHA256::doubleHash(tree[i] + tree[i]));
                }
            }
            tree = std::move(newLevel);
            level++;
        }

        return tree.empty() ? "" : tree[0];
    }

    void Block::calculateHash() {
        blockHash = header.calculateHash();
    }

    bool Block::validateHash() const {
        return header.calculateHash() == blockHash;
    }

    bool Block::mine(uint32_t targetBits) {
        header.bits = targetBits;
        calculateMerkleRoot();
        
        std::string target(header.bits >> 24, '0');
        
        while (header.nonce < UINT32_MAX) {
            calculateHash();
            if (blockHash.substr(0, header.bits >> 24) == target) {
                return true;
            }
            header.nonce++;
        }
        
        return false;
    }

    bool Block::mineWithNonce(uint32_t startNonce, uint32_t targetBits) {
        header.bits = targetBits;
        header.nonce = startNonce;
        calculateMerkleRoot();
        
        std::string target(header.bits >> 24, '0');
        
        for (uint32_t i = 0; i < 1000000; i++) {
            calculateHash();
            if (blockHash.substr(0, header.bits >> 24) == target) {
                return true;
            }
            header.nonce++;
        }
        
        return false;
    }

    uint64_t Block::getWork() const {
        if (cachedWork == 0) {
            const_cast<Block*>(this)->cachedWork = header.getWork();
        }
        return cachedWork;
    }

    bool Block::validate(const Block& previousBlock) const {
        // Check previous hash
        if (header.previousBlockHash != previousBlock.getHash()) {
            return false;
        }

        // Check timestamp
        if (header.timestamp <= previousBlock.getTimestamp()) {
            return false;
        }

        // Check block hash meets difficulty
        if (!validateHash()) {
            return false;
        }

        // Check merkle root
        if (!validateMerkleRoot()) {
            return false;
        }

        // Validate all transactions
        if (!validateTransactions()) {
            return false;
        }

        return true;
    }

    bool Block::validateTimestamp() const {
        uint32_t now = std::time(nullptr);
        return header.timestamp <= now + 7200 && // 2 hours in future
               header.timestamp >= 1231006505;    // Not before Bitcoin genesis
    }

    bool Block::validateTransactions() const {
        if (transactions.empty()) {
            return false;
        }

        // First transaction must be coinbase
        if (transactions[0].getType() != TransactionType::COINBASE) {
            return false;
        }

        // Validate each transaction
        for (const auto& tx : transactions) {
            if (!tx.validate()) {
                return false;
            }
        }

        return true;
    }

    bool Block::validateSize() const {
        return getSize() <= 1000000; // 1MB max
    }

    std::string Block::serialize() const {
        std::stringstream ss;
        ss << height << "\n";
        ss << blockHash << "\n";
        ss << header.serialize() << "\n";
        ss << transactions.size() << "\n";
        
        for (const auto& tx : transactions) {
            ss << tx.serialize() << "\n";
        }
        
        return ss.str();
    }

    bool Block::deserialize(const std::string& data) {
        std::stringstream ss(data);
        std::string line;
        
        std::getline(ss, line);
        height = std::stoul(line);
        
        std::getline(ss, blockHash);
        
        std::getline(ss, line);
        if (!header.deserialize(line)) {
            return false;
        }
        
        std::getline(ss, line);
        size_t txCount = std::stoul(line);
        
        transactions.clear();
        for (size_t i = 0; i < txCount; i++) {
            std::getline(ss, line);
            Transaction tx;
            if (tx.deserialize(line)) {
                transactions.push_back(tx);
            }
        }
        
        return true;
    }

    std::vector<uint8_t> Block::serializeBinary() const {
        std::vector<uint8_t> data;
        // TODO: Implement binary serialization
        return data;
    }

    bool Block::deserializeBinary(const std::vector<uint8_t>& data) {
        // TODO: Implement binary deserialization
        return false;
    }

    uint32_t Block::getSize() const {
        uint32_t size = sizeof(header) + sizeof(height) + blockHash.length();
        for (const auto& tx : transactions) {
            size += tx.getSize();
        }
        return size;
    }

    uint32_t Block::getBaseSize() const {
        return sizeof(header) + sizeof(height);
    }

    uint32_t Block::getTotalSize() const {
        return getSize();
    }

    BlockStats Block::getStats() const {
        BlockStats stats;
        stats.height = height;
        stats.version = header.version;
        stats.hash = blockHash;
        stats.previousHash = header.previousBlockHash;
        stats.merkleRoot = header.merkleRoot;
        stats.timestamp = header.timestamp;
        stats.bits = header.bits;
        stats.nonce = header.nonce;
        stats.txCount = transactions.size();
        stats.totalOutput = getTotalOutput();
        stats.totalFees = getTotalFees();
        stats.size = getSize();
        stats.work = getWork();
        stats.difficulty = getDifficulty();
        return stats;
    }

    uint64_t Block::getTotalOutput() const {
        uint64_t total = 0;
        for (const auto& tx : transactions) {
            total += tx.getTotalOutput();
        }
        return total;
    }

    uint64_t Block::getTotalFees() const {
        uint64_t total = 0;
        for (const auto& tx : transactions) {
            total += tx.getFee();
        }
        return total;
    }

    double Block::getDifficulty() const {
        uint64_t target = header.bits & 0x007fffff;
        int32_t exponent = ((header.bits >> 24) & 0xff) - 3;
        return (double)target * std::pow(2.0, 8 * exponent) / std::pow(2.0, 32);
    }

    std::string Block::toString() const {
        std::stringstream ss;
        ss << "Block #" << height << "\n";
        ss << "  Hash: " << blockHash << "\n";
        ss << "  Previous: " << header.previousBlockHash << "\n";
        ss << "  Merkle Root: " << header.merkleRoot << "\n";
        ss << "  Timestamp: " << header.timestamp << "\n";
        ss << "  Bits: " << header.bits << "\n";
        ss << "  Nonce: " << header.nonce << "\n";
        ss << "  Transactions: " << transactions.size() << "\n";
        ss << "  Size: " << getSize() << " bytes\n";
        return ss.str();
    }

    void Block::print() const {
        std::cout << toString();
    }

    Block Block::createGenesis() {
        Block genesis(0);
        genesis.setPreviousHash(GENESIS_PREVIOUS_HASH);
        genesis.setTimestamp(GENESIS_TIMESTAMP);
        genesis.setBits(GENESIS_BITS);
        genesis.setNonce(GENESIS_NONCE);
        
        // Create genesis coinbase transaction
        Transaction coinbase;
        coinbase.setType(TransactionType::COINBASE);
        coinbase.addOutput("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 50 * 100000000); // 50 BTC
        coinbase.calculateHash();
        genesis.addTransaction(coinbase);
        
        genesis.calculateMerkleRoot();
        genesis.calculateHash();
        
        return genesis;
    }

    bool Block::isValidTimestamp(uint32_t timestamp) {
        uint32_t now = std::time(nullptr);
        return timestamp <= now + 7200 && timestamp >= 1231006505;
    }

    uint32_t Block::getMaxTimestamp() {
        return std::time(nullptr) + 7200;
    }

    uint32_t Block::getMinTimestamp() {
        return 1231006505;
    }

} // namespace powercoin