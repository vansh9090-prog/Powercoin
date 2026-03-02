#include "utxo.h"
#include "../crypto/sha256.h"
#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <random>

namespace powercoin {

    // ============== UTXOEntry Implementation ==============

    UTXOEntry::UTXOEntry()
        : outputIndex(0), amount(0), blockHeight(0), confirmations(0),
          status(UTXOStatus::UNSPENT), createdAt(0), spentAt(0),
          isCoinbase(false) {}

    std::string UTXOEntry::toString() const {
        std::stringstream ss;
        ss << "UTXO: " << txHash.substr(0, 16) << ":" << outputIndex << "\n";
        ss << "  Address: " << address << "\n";
        ss << "  Amount: " << amount / 100000000.0 << " PWR\n";
        ss << "  Height: " << blockHeight << "\n";
        ss << "  Confirmations: " << confirmations << "\n";
        ss << "  Status: " << static_cast<int>(status) << "\n";
        ss << "  Coinbase: " << (isCoinbase ? "yes" : "no") << "\n";
        return ss.str();
    }

    bool UTXOEntry::isSpendable() const {
        return status == UTXOStatus::UNSPENT && !isCoinbase;
    }

    bool UTXOEntry::isMature(uint32_t currentHeight) const {
        if (!isCoinbase) return true;
        return (currentHeight - blockHeight) >= 100;
    }

    std::string UTXOEntry::getKey() const {
        return txHash + ":" + std::to_string(outputIndex);
    }

    // ============== UTXOSetStats Implementation ==============

    UTXOSetStats::UTXOSetStats()
        : totalUTXOs(0), totalAmount(0), spendableUTXOs(0), spendableAmount(0),
          immatureUTXOs(0), immatureAmount(0), lockedUTXOs(0), lockedAmount(0),
          coinbaseUTXOs(0), coinbaseAmount(0), averageConfirmations(0),
          addressCount(0) {}

    std::string UTXOSetStats::toString() const {
        std::stringstream ss;
        ss << "UTXO Set Statistics:\n";
        ss << "  Total UTXOs: " << totalUTXOs << "\n";
        ss << "  Total Amount: " << totalAmount / 100000000.0 << " PWR\n";
        ss << "  Spendable: " << spendableUTXOs << " (" << spendableAmount / 100000000.0 << " PWR)\n";
        ss << "  Immature: " << immatureUTXOs << " (" << immatureAmount / 100000000.0 << " PWR)\n";
        ss << "  Locked: " << lockedUTXOs << " (" << lockedAmount / 100000000.0 << " PWR)\n";
        ss << "  Coinbase: " << coinbaseUTXOs << " (" << coinbaseAmount / 100000000.0 << " PWR)\n";
        ss << "  Avg Confirmations: " << averageConfirmations << "\n";
        ss << "  Addresses: " << addressCount << "\n";
        return ss.str();
    }

    // ============== UTXOFilters Implementation ==============

    UTXOFilters::UTXOFilters()
        : minAmount(0), maxAmount(UINT64_MAX), minConfirmations(0), maxConfirmations(UINT32_MAX),
          includeSpent(false), includeLocked(false), includeImmature(false),
          onlyCoinbase(false), onlySpendable(false) {}

    bool UTXOFilters::matches(const UTXOEntry& utxo) const {
        if (!address.empty() && utxo.address != address) return false;
        if (utxo.amount < minAmount || utxo.amount > maxAmount) return false;
        if (utxo.confirmations < minConfirmations || utxo.confirmations > maxConfirmations) return false;
        
        if (!includeSpent && utxo.status == UTXOStatus::SPENT) return false;
        if (!includeLocked && utxo.status == UTXOStatus::LOCKED) return false;
        if (!includeImmature && utxo.status == UTXOStatus::IMMATURE) return false;
        
        if (onlyCoinbase && !utxo.isCoinbase) return false;
        if (onlySpendable && !utxo.isSpendable()) return false;
        
        if (!statusFilter.empty() && statusFilter.find(utxo.status) == statusFilter.end()) return false;
        
        return true;
    }

    // ============== CoinSelectionResult Implementation ==============

    CoinSelectionResult::CoinSelectionResult()
        : totalSelected(0), totalRequired(0), change(0), success(false) {}

    std::string CoinSelectionResult::toString() const {
        std::stringstream ss;
        ss << "Coin Selection Result: " << (success ? "SUCCESS" : "FAILED") << "\n";
        if (!success) {
            ss << "  Error: " << error << "\n";
        } else {
            ss << "  Selected: " << selected.size() << " UTXOs\n";
            ss << "  Total Selected: " << totalSelected / 100000000.0 << " PWR\n";
            ss << "  Required: " << totalRequired / 100000000.0 << " PWR\n";
            ss << "  Change: " << change / 100000000.0 << " PWR\n";
        }
        return ss.str();
    }

    // ============== UTXOPoolEntry Implementation ==============

    UTXOPoolEntry::UTXOPoolEntry() : mempoolTime(0), inMempool(false) {}

    // ============== UTXOSet Implementation ==============

    struct UTXOSet::Impl {
        std::map<std::string, UTXOEntry> utxos;
        std::map<std::string, std::chrono::steady_clock::time_point> frozenUntil;
        std::map<std::string, UTXOPoolEntry> mempool;
        std::unique_ptr<UTXOCache> cache;
        std::unique_ptr<UTXOIndex> index;
        
        uint64_t totalBalance;
        uint32_t currentHeight;
        
        std::function<void(const UTXOEntry&)> onUTXOAdded;
        std::function<void(const UTXOEntry&, const std::string&)> onUTXOSpent;
        std::function<void(const UTXOEntry&)> onUTXORemoved;
        std::function<void(uint64_t, uint64_t)> onBalanceChanged;

        Impl() : totalBalance(0), currentHeight(0) {
            cache = std::make_unique<UTXOCache>();
            index = std::make_unique<UTXOIndex>();
        }
    };

    UTXOSet::UTXOSet() {
        impl = std::make_unique<Impl>();
    }

    UTXOSet::~UTXOSet() = default;

    bool UTXOSet::initialize() {
        std::lock_guard<std::mutex> lock(mutex);
        impl->utxos.clear();
        impl->index->clear();
        impl->totalBalance = 0;
        return true;
    }

    bool UTXOSet::addUTXO(const Transaction& tx, uint32_t outputIndex, uint32_t blockHeight) {
        std::lock_guard<std::mutex> lock(mutex);

        if (outputIndex >= tx.getOutputs().size()) {
            return false;
        }

        const auto& output = tx.getOutputs()[outputIndex];

        UTXOEntry utxo;
        utxo.txHash = tx.getHash();
        utxo.outputIndex = outputIndex;
        utxo.address = output.address;
        utxo.amount = output.amount;
        utxo.blockHeight = blockHeight;
        utxo.confirmations = (impl->currentHeight > blockHeight) ? 
                              impl->currentHeight - blockHeight + 1 : 0;
        utxo.status = UTXOStatus::UNSPENT;
        utxo.createdAt = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        utxo.isCoinbase = (tx.getType() == TransactionType::COINBASE);
        utxo.script = output.scriptPubKey;

        if (utxo.isCoinbase && utxo.confirmations < 100) {
            utxo.status = UTXOStatus::IMMATURE;
        }

        std::string key = utxo.getKey();
        impl->utxos[key] = utxo;
        impl->index->addUTXO(utxo);
        impl->totalBalance += utxo.amount;

        if (impl->cache) {
            impl->cache->put(utxo);
        }

        if (impl->onUTXOAdded) {
            impl->onUTXOAdded(utxo);
        }

        if (impl->onBalanceChanged) {
            impl->onBalanceChanged(impl->totalBalance, getSpendableBalance("", impl->currentHeight));
        }

        return true;
    }

    bool UTXOSet::addUTXO(const UTXOEntry& utxo) {
        std::lock_guard<std::mutex> lock(mutex);

        std::string key = utxo.getKey();
        impl->utxos[key] = utxo;
        impl->index->addUTXO(utxo);
        impl->totalBalance += utxo.amount;

        if (impl->cache) {
            impl->cache->put(utxo);
        }

        if (impl->onUTXOAdded) {
            impl->onUTXOAdded(utxo);
        }

        return true;
    }

    bool UTXOSet::spendUTXO(const std::string& txHash, uint32_t outputIndex,
                            const std::string& spentByTx, uint32_t blockHeight) {
        std::lock_guard<std::mutex> lock(mutex);

        std::string key = txHash + ":" + std::to_string(outputIndex);
        auto it = impl->utxos.find(key);
        if (it == impl->utxos.end()) {
            return false;
        }

        UTXOEntry oldUtxo = it->second;
        
        it->second.status = UTXOStatus::SPENT;
        it->second.spentAt = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        it->second.spentByTx = spentByTx;

        impl->totalBalance -= oldUtxo.amount;
        impl->index->removeUTXO(oldUtxo);

        if (impl->cache) {
            impl->cache->remove(key);
        }

        if (impl->onUTXOSpent) {
            impl->onUTXOSpent(oldUtxo, spentByTx);
        }

        if (impl->onBalanceChanged) {
            impl->onBalanceChanged(impl->totalBalance, getSpendableBalance("", blockHeight));
        }

        return true;
    }

    bool UTXOSet::removeUTXO(const std::string& txHash, uint32_t outputIndex) {
        std::lock_guard<std::mutex> lock(mutex);

        std::string key = txHash + ":" + std::to_string(outputIndex);
        auto it = impl->utxos.find(key);
        if (it == impl->utxos.end()) {
            return false;
        }

        if (it->second.status != UTXOStatus::SPENT) {
            impl->totalBalance -= it->second.amount;
        }

        impl->index->removeUTXO(it->second);

        if (impl->cache) {
            impl->cache->remove(key);
        }

        if (impl->onUTXORemoved) {
            impl->onUTXORemoved(it->second);
        }

        impl->utxos.erase(it);
        return true;
    }

    UTXOEntry UTXOSet::getUTXO(const std::string& txHash, uint32_t outputIndex) const {
        std::lock_guard<std::mutex> lock(mutex);

        std::string key = txHash + ":" + std::to_string(outputIndex);

        // Check cache first
        if (impl->cache && impl->cache->contains(key)) {
            return impl->cache->get(key);
        }

        auto it = impl->utxos.find(key);
        if (it != impl->utxos.end()) {
            if (impl->cache) {
                impl->cache->put(it->second);
            }
            return it->second;
        }
        return UTXOEntry();
    }

    bool UTXOSet::hasUTXO(const std::string& txHash, uint32_t outputIndex) const {
        std::lock_guard<std::mutex> lock(mutex);
        std::string key = txHash + ":" + std::to_string(outputIndex);
        return impl->utxos.find(key) != impl->utxos.end();
    }

    std::vector<UTXOEntry> UTXOSet::getUTXOsForAddress(const std::string& address,
                                                        const UTXOFilters& filters) const {
        std::lock_guard<std::mutex> lock(mutex);
        
        UTXOFilters addrFilters = filters;
        addrFilters.address = address;
        
        return getUTXOs(addrFilters);
    }

    std::vector<UTXOEntry> UTXOSet::getUTXOs(const UTXOFilters& filters) const {
        std::lock_guard<std::mutex> lock(mutex);

        std::vector<UTXOEntry> result;

        if (!filters.address.empty()) {
            // Use index for address lookups
            result = impl->index->getByAddress(filters.address, filters);
        } else {
            // Scan all UTXOs
            for (const auto& [_, utxo] : impl->utxos) {
                if (filters.matches(utxo)) {
                    // Check frozen status
                    auto frozenIt = impl->frozenUntil.find(utxo.getKey());
                    if (frozenIt != impl->frozenUntil.end()) {
                        if (std::chrono::steady_clock::now() < frozenIt->second) {
                            continue; // Still frozen
                        }
                    }
                    result.push_back(utxo);
                }
            }
        }

        return result;
    }

    uint64_t UTXOSet::getBalance(const std::string& address, uint32_t minConfirmations) const {
        std::lock_guard<std::mutex> lock(mutex);

        uint64_t balance = 0;
        UTXOFilters filters;
        filters.minConfirmations = minConfirmations;
        filters.includeSpent = false;
        filters.includeLocked = false;

        auto utxos = getUTXOsForAddress(address, filters);
        for (const auto& utxo : utxos) {
            balance += utxo.amount;
        }

        return balance;
    }

    uint64_t UTXOSet::getTotalBalance(uint32_t minConfirmations) const {
        std::lock_guard<std::mutex> lock(mutex);

        uint64_t balance = 0;
        UTXOFilters filters;
        filters.minConfirmations = minConfirmations;
        filters.includeSpent = false;
        filters.includeLocked = false;

        auto utxos = getUTXOs(filters);
        for (const auto& utxo : utxos) {
            balance += utxo.amount;
        }

        return balance;
    }

    uint64_t UTXOSet::getSpendableBalance(const std::string& address, uint32_t currentHeight) const {
        std::lock_guard<std::mutex> lock(mutex);

        uint64_t balance = 0;
        UTXOFilters filters;
        filters.includeSpent = false;
        filters.includeLocked = false;
        filters.onlySpendable = true;

        auto utxos = getUTXOsForAddress(address, filters);
        for (const auto& utxo : utxos) {
            if (utxo.isMature(currentHeight)) {
                balance += utxo.amount;
            }
        }

        return balance;
    }

    UTXOSetStats UTXOSet::getStats() const {
        std::lock_guard<std::mutex> lock(mutex);

        UTXOSetStats stats;
        stats.totalUTXOs = impl->utxos.size();
        stats.totalAmount = impl->totalBalance;
        stats.addressCount = impl->index->size();

        uint64_t totalConfirmations = 0;

        for (const auto& [_, utxo] : impl->utxos) {
            if (utxo.status == UTXOStatus::UNSPENT) {
                stats.spendableUTXOs++;
                stats.spendableAmount += utxo.amount;
                totalConfirmations += utxo.confirmations;
            } else if (utxo.status == UTXOStatus::IMMATURE) {
                stats.immatureUTXOs++;
                stats.immatureAmount += utxo.amount;
            } else if (utxo.status == UTXOStatus::LOCKED) {
                stats.lockedUTXOs++;
                stats.lockedAmount += utxo.amount;
            }

            if (utxo.isCoinbase) {
                stats.coinbaseUTXOs++;
                stats.coinbaseAmount += utxo.amount;
            }
        }

        if (stats.spendableUTXOs > 0) {
            stats.averageConfirmations = totalConfirmations / stats.spendableUTXOs;
        }

        return stats;
    }

    CoinSelectionResult UTXOSet::selectCoins(uint64_t targetAmount,
                                              const std::string& address,
                                              CoinSelectionStrategy strategy,
                                              uint32_t currentHeight,
                                              uint32_t minConfirmations) const {
        CoinSelector selector(this);
        selector.withTarget(targetAmount)
                .withAddress(address)
                .withCurrentHeight(currentHeight)
                .withMinConfirmations(minConfirmations);
        
        return selector.select(strategy);
    }

    CoinSelectionResult UTXOSet::selectCoinsWithFee(uint64_t targetAmount,
                                                     uint64_t feeEstimate,
                                                     const std::string& address,
                                                     CoinSelectionStrategy strategy) const {
        return selectCoins(targetAmount + feeEstimate, address, strategy, impl->currentHeight, 1);
    }

    void UTXOSet::updateConfirmations(uint32_t currentHeight) {
        std::lock_guard<std::mutex> lock(mutex);

        impl->currentHeight = currentHeight;

        for (auto& [key, utxo] : impl->utxos) {
            if (utxo.blockHeight > 0) {
                utxo.confirmations = currentHeight - utxo.blockHeight + 1;
                
                // Update immature status
                if (utxo.isCoinbase && utxo.status == UTXOStatus::IMMATURE && utxo.confirmations >= 100) {
                    utxo.status = UTXOStatus::UNSPENT;
                }
            }
        }
    }

    bool UTXOSet::lockUTXO(const std::string& txHash, uint32_t outputIndex, bool lock) {
        std::lock_guard<std::mutex> lock(mutex);

        std::string key = txHash + ":" + std::to_string(outputIndex);
        auto it = impl->utxos.find(key);
        if (it == impl->utxos.end()) {
            return false;
        }

        UTXOEntry oldUtxo = it->second;
        
        if (lock) {
            it->second.status = UTXOStatus::LOCKED;
        } else {
            it->second.status = UTXOStatus::UNSPENT;
        }

        impl->index->removeUTXO(oldUtxo);
        impl->index->addUTXO(it->second);

        if (impl->cache) {
            impl->cache->remove(key);
        }

        return true;
    }

    bool UTXOSet::isLocked(const std::string& txHash, uint32_t outputIndex) const {
        std::lock_guard<std::mutex> lock(mutex);

        std::string key = txHash + ":" + std::to_string(outputIndex);
        auto it = impl->utxos.find(key);
        if (it == impl->utxos.end()) {
            return false;
        }

        return it->second.status == UTXOStatus::LOCKED;
    }

    std::vector<UTXOEntry> UTXOSet::getLockedUTXOs() const {
        std::lock_guard<std::mutex> lock(mutex);

        std::vector<UTXOEntry> locked;
        for (const auto& [_, utxo] : impl->utxos) {
            if (utxo.status == UTXOStatus::LOCKED) {
                locked.push_back(utxo);
            }
        }
        return locked;
    }

    bool UTXOSet::freezeUTXO(const std::string& txHash, uint32_t outputIndex,
                             std::chrono::seconds duration) {
        std::lock_guard<std::mutex> lock(mutex);

        std::string key = txHash + ":" + std::to_string(outputIndex);
        if (impl->utxos.find(key) == impl->utxos.end()) {
            return false;
        }

        impl->frozenUntil[key] = std::chrono::steady_clock::now() + duration;
        return true;
    }

    bool UTXOSet::unfreezeUTXO(const std::string& txHash, uint32_t outputIndex) {
        std::lock_guard<std::mutex> lock(mutex);

        std::string key = txHash + ":" + std::to_string(outputIndex);
        return impl->frozenUntil.erase(key) > 0;
    }

    void UTXOSet::addToMempool(const Transaction& tx) {
        std::lock_guard<std::mutex> lock(mutex);

        for (size_t i = 0; i < tx.getOutputs().size(); i++) {
            const auto& output = tx.getOutputs()[i];
            
            UTXOPoolEntry entry;
            entry.utxo.txHash = tx.getHash();
            entry.utxo.outputIndex = i;
            entry.utxo.address = output.address;
            entry.utxo.amount = output.amount;
            entry.utxo.status = UTXOStatus::UNSPENT;
            entry.inMempool = true;
            entry.mempoolTime = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();

            std::string key = tx.getHash() + ":" + std::to_string(i);
            impl->mempool[key] = entry;
        }
    }

    void UTXOSet::removeFromMempool(const std::string& txHash) {
        std::lock_guard<std::mutex> lock(mutex);

        for (auto it = impl->mempool.begin(); it != impl->mempool.end();) {
            if (it->second.utxo.txHash == txHash) {
                it = impl->mempool.erase(it);
            } else {
                ++it;
            }
        }
    }

    bool UTXOSet::isInMempool(const std::string& txHash, uint32_t outputIndex) const {
        std::lock_guard<std::mutex> lock(mutex);

        std::string key = txHash + ":" + std::to_string(outputIndex);
        return impl->mempool.find(key) != impl->mempool.end();
    }

    std::vector<UTXOPoolEntry> UTXOSet::getMempoolUTXOs() const {
        std::lock_guard<std::mutex> lock(mutex);

        std::vector<UTXOPoolEntry> result;
        for (const auto& [_, entry] : impl->mempool) {
            result.push_back(entry);
        }
        return result;
    }

    void UTXOSet::clearMempool() {
        std::lock_guard<std::mutex> lock(mutex);
        impl->mempool.clear();
    }

    size_t UTXOSet::prune(size_t olderThan) {
        std::lock_guard<std::mutex> lock(mutex);

        size_t pruned = 0;
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        for (auto it = impl->utxos.begin(); it != impl->utxos.end();) {
            if (it->second.status == UTXOStatus::SPENT &&
                (now - it->second.spentAt) > static_cast<int64_t>(olderThan * 600)) { // ~10 min per block
                impl->index->removeUTXO(it->second);
                if (impl->cache) {
                    impl->cache->remove(it->first);
                }
                it = impl->utxos.erase(it);
                pruned++;
            } else {
                ++it;
            }
        }

        return pruned;
    }

    size_t UTXOSet::size() const {
        std::lock_guard<std::mutex> lock(mutex);
        return impl->utxos.size();
    }

    size_t UTXOSet::memoryUsage() const {
        std::lock_guard<std::mutex> lock(mutex);
        // Rough estimate
        return impl->utxos.size() * (sizeof(UTXOEntry) + 100);
    }

    bool UTXOSet::save(const std::string& path) const {
        std::lock_guard<std::mutex> lock(mutex);

        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        // Write number of UTXOs
        uint32_t count = impl->utxos.size();
        file.write(reinterpret_cast<const char*>(&count), sizeof(count));

        // Write each UTXO
        for (const auto& [key, utxo] : impl->utxos) {
            // Write key
            uint32_t keyLen = key.size();
            file.write(reinterpret_cast<const char*>(&keyLen), sizeof(keyLen));
            file.write(key.c_str(), keyLen);

            // Write UTXO data
            uint32_t txHashLen = utxo.txHash.size();
            file.write(reinterpret_cast<const char*>(&txHashLen), sizeof(txHashLen));
            file.write(utxo.txHash.c_str(), txHashLen);
            
            file.write(reinterpret_cast<const char*>(&utxo.outputIndex), sizeof(utxo.outputIndex));
            
            uint32_t addressLen = utxo.address.size();
            file.write(reinterpret_cast<const char*>(&addressLen), sizeof(addressLen));
            file.write(utxo.address.c_str(), addressLen);
            
            file.write(reinterpret_cast<const char*>(&utxo.amount), sizeof(utxo.amount));
            file.write(reinterpret_cast<const char*>(&utxo.blockHeight), sizeof(utxo.blockHeight));
            file.write(reinterpret_cast<const char*>(&utxo.confirmations), sizeof(utxo.confirmations));
            file.write(reinterpret_cast<const char*>(&utxo.status), sizeof(utxo.status));
            file.write(reinterpret_cast<const char*>(&utxo.createdAt), sizeof(utxo.createdAt));
            file.write(reinterpret_cast<const char*>(&utxo.spentAt), sizeof(utxo.spentAt));
            
            uint32_t spentByTxLen = utxo.spentByTx.size();
            file.write(reinterpret_cast<const char*>(&spentByTxLen), sizeof(spentByTxLen));
            file.write(utxo.spentByTx.c_str(), spentByTxLen);
            
            uint32_t scriptLen = utxo.script.size();
            file.write(reinterpret_cast<const char*>(&scriptLen), sizeof(scriptLen));
            file.write(utxo.script.c_str(), scriptLen);
            
            file.write(reinterpret_cast<const char*>(&utxo.isCoinbase), sizeof(utxo.isCoinbase));
        }

        file.close();
        return true;
    }

    bool UTXOSet::load(const std::string& path) {
        std::lock_guard<std::mutex> lock(mutex);

        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        // Read number of UTXOs
        uint32_t count;
        file.read(reinterpret_cast<char*>(&count), sizeof(count));

        impl->utxos.clear();
        impl->totalBalance = 0;

        for (uint32_t i = 0; i < count; i++) {
            // Read key
            uint32_t keyLen;
            file.read(reinterpret_cast<char*>(&keyLen), sizeof(keyLen));
            std::string key(keyLen, '\0');
            file.read(&key[0], keyLen);

            UTXOEntry utxo;

            // Read UTXO data
            uint32_t txHashLen;
            file.read(reinterpret_cast<char*>(&txHashLen), sizeof(txHashLen));
            utxo.txHash.resize(txHashLen);
            file.read(&utxo.txHash[0], txHashLen);
            
            file.read(reinterpret_cast<char*>(&utxo.outputIndex), sizeof(utxo.outputIndex));
            
            uint32_t addressLen;
            file.read(reinterpret_cast<char*>(&addressLen), sizeof(addressLen));
            utxo.address.resize(addressLen);
            file.read(&utxo.address[0], addressLen);
            
            file.read(reinterpret_cast<char*>(&utxo.amount), sizeof(utxo.amount));
            file.read(reinterpret_cast<char*>(&utxo.blockHeight), sizeof(utxo.blockHeight));
            file.read(reinterpret_cast<char*>(&utxo.confirmations), sizeof(utxo.confirmations));
            file.read(reinterpret_cast<char*>(&utxo.status), sizeof(utxo.status));
            file.read(reinterpret_cast<char*>(&utxo.createdAt), sizeof(utxo.createdAt));
            file.read(reinterpret_cast<char*>(&utxo.spentAt), sizeof(utxo.spentAt));
            
            uint32_t spentByTxLen;
            file.read(reinterpret_cast<char*>(&spentByTxLen), sizeof(spentByTxLen));
            utxo.spentByTx.resize(spentByTxLen);
            file.read(&utxo.spentByTx[0], spentByTxLen);
            
            uint32_t scriptLen;
            file.read(reinterpret_cast<char*>(&scriptLen), sizeof(scriptLen));
            utxo.script.resize(scriptLen);
            file.read(&utxo.script[0], scriptLen);
            
            file.read(reinterpret_cast<char*>(&utxo.isCoinbase), sizeof(utxo.isCoinbase));

            impl->utxos[key] = utxo;
            impl->index->addUTXO(utxo);
            if (utxo.status != UTXOStatus::SPENT) {
                impl->totalBalance += utxo.amount;
            }
        }

        file.close();
        return true;
    }

    void UTXOSet::clear() {
        std::lock_guard<std::mutex> lock(mutex);
        impl->utxos.clear();
        impl->index->clear();
        impl->mempool.clear();
        impl->frozenUntil.clear();
        impl->totalBalance = 0;
        if (impl->cache) {
            impl->cache->clear();
        }
    }

    void UTXOSet::setOnUTXOAdded(std::function<void(const UTXOEntry&)> callback) {
        impl->onUTXOAdded = callback;
    }

    void UTXOSet::setOnUTXOSpent(std::function<void(const UTXOEntry&, const std::string&)> callback) {
        impl->onUTXOSpent = callback;
    }

    void UTXOSet::setOnUTXORemoved(std::function<void(const UTXOEntry&)> callback) {
        impl->onUTXORemoved = callback;
    }

    void UTXOSet::setOnBalanceChanged(std::function<void(uint64_t, uint64_t)> callback) {
        impl->onBalanceChanged = callback;
    }

    // ============== UTXOCache Implementation ==============

    UTXOCache::UTXOCache(size_t maxSize) : maxSize(maxSize) {}

    UTXOCache::~UTXOCache() = default;

    bool UTXOCache::put(const UTXOEntry& utxo) {
        std::lock_guard<std::mutex> lock(mutex);

        if (cache.size() >= maxSize) {
            prune();
        }

        Entry entry;
        entry.utxo = utxo;
        entry.accessTime = std::chrono::steady_clock::now();

        cache[utxo.getKey()] = entry;
        return true;
    }

    UTXOEntry UTXOCache::get(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = cache.find(key);
        if (it != cache.end()) {
            it->second.accessTime = std::chrono::steady_clock::now();
            return it->second.utxo;
        }
        return UTXOEntry();
    }

    bool UTXOCache::remove(const std::string& key) {
        std::lock_guard<std::mutex> lock(mutex);
        return cache.erase(key) > 0;
    }

    void UTXOCache::clear() {
        std::lock_guard<std::mutex> lock(mutex);
        cache.clear();
    }

    bool UTXOCache::contains(const std::string& key) const {
        std::lock_guard<std::mutex> lock(mutex);
        return cache.find(key) != cache.end();
    }

    size_t UTXOCache::size() const {
        std::lock_guard<std::mutex> lock(mutex);
        return cache.size();
    }

    void UTXOCache::prune() {
        // Remove oldest 20% of entries
        if (cache.size() < maxSize) return;

        std::vector<std::pair<std::string, std::chrono::steady_clock::time_point>> entries;
        for (const auto& [key, entry] : cache) {
            entries.emplace_back(key, entry.accessTime);
        }

        std::sort(entries.begin(), entries.end(),
            [](const auto& a, const auto& b) {
                return a.second < b.second;
            });

        size_t toRemove = cache.size() - maxSize + (maxSize / 5);
        for (size_t i = 0; i < toRemove && i < entries.size(); i++) {
            cache.erase(entries[i].first);
        }
    }

    // ============== UTXOIndex Implementation ==============

    void UTXOIndex::addUTXO(const UTXOEntry& utxo) {
        std::lock_guard<std::mutex> lock(mutex);

        addressIndex[utxo.address].insert(utxo.getKey());
        amountIndex[utxo.amount].insert(utxo.getKey());
        heightIndex[utxo.blockHeight].insert(utxo.getKey());
    }

    void UTXOIndex::removeUTXO(const UTXOEntry& utxo) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = addressIndex.find(utxo.address);
        if (it != addressIndex.end()) {
            it->second.erase(utxo.getKey());
            if (it->second.empty()) {
                addressIndex.erase(it);
            }
        }

        auto amtIt = amountIndex.find(utxo.amount);
        if (amtIt != amountIndex.end()) {
            amtIt->second.erase(utxo.getKey());
            if (amtIt->second.empty()) {
                amountIndex.erase(amtIt);
            }
        }

        auto hgtIt = heightIndex.find(utxo.blockHeight);
        if (hgtIt != heightIndex.end()) {
            hgtIt->second.erase(utxo.getKey());
            if (hgtIt->second.empty()) {
                heightIndex.erase(hgtIt);
            }
        }
    }

    void UTXOIndex::updateUTXO(const UTXOEntry& oldUtxo, const UTXOEntry& newUtxo) {
        removeUTXO(oldUtxo);
        addUTXO(newUtxo);
    }

    std::vector<UTXOEntry> UTXOIndex::getByAddress(const std::string& address,
                                                    const UTXOFilters& filters) const {
        std::lock_guard<std::mutex> lock(mutex);

        std::vector<UTXOEntry> result;
        auto it = addressIndex.find(address);
        if (it == addressIndex.end()) {
            return result;
        }

        // In a real implementation, we would need access to the UTXO set
        // This is just returning keys, not actual UTXO entries
        return result;
    }

    std::vector<UTXOEntry> UTXOIndex::getByAmountRange(uint64_t minAmount, uint64_t maxAmount) const {
        std::lock_guard<std::mutex> lock(mutex);

        std::vector<UTXOEntry> result;
        // Would need UTXO set access
        return result;
    }

    std::vector<UTXOEntry> UTXOIndex::getByHeight(uint32_t minHeight, uint32_t maxHeight) const {
        std::lock_guard<std::mutex> lock(mutex);

        std::vector<UTXOEntry> result;
        // Would need UTXO set access
        return result;
    }

    size_t UTXOIndex::size() const {
        std::lock_guard<std::mutex> lock(mutex);
        return addressIndex.size();
    }

    void UTXOIndex::clear() {
        std::lock_guard<std::mutex> lock(mutex);
        addressIndex.clear();
        amountIndex.clear();
        heightIndex.clear();
    }

    // ============== CoinSelector Implementation ==============

    CoinSelector::CoinSelector(const UTXOSet* set)
        : utxoSet(set), target(0), fee(0), currentHeight(0), minConfirmations(1) {}

    CoinSelector& CoinSelector::withTarget(uint64_t amount) {
        target = amount;
        return *this;
    }

    CoinSelector& CoinSelector::withFee(uint64_t feeAmount) {
        fee = feeAmount;
        return *this;
    }

    CoinSelector& CoinSelector::withAddress(const std::string& addr) {
        address = addr;
        return *this;
    }

    CoinSelector& CoinSelector::withCurrentHeight(uint32_t height) {
        currentHeight = height;
        return *this;
    }

    CoinSelector& CoinSelector::withMinConfirmations(uint32_t confs) {
        minConfirmations = confs;
        return *this;
    }

    CoinSelectionResult CoinSelector::select(CoinSelectionStrategy strategy) const {
        // Get available UTXOs
        UTXOFilters filters;
        filters.minConfirmations = minConfirmations;
        filters.includeSpent = false;
        filters.includeLocked = false;
        filters.onlySpendable = true;

        auto utxos = (address.empty()) ? 
            utxoSet->getUTXOs(filters) : 
            utxoSet->getUTXOsForAddress(address, filters);

        // Filter by maturity
        std::vector<UTXOEntry> mature;
        for (const auto& utxo : utxos) {
            if (utxo.isMature(currentHeight)) {
                mature.push_back(utxo);
            }
        }

        // Apply selection strategy
        switch (strategy) {
            case CoinSelectionStrategy::FIRST_FIT:
                return selectFirstFit(mature);
            case CoinSelectionStrategy::BEST_FIT:
                return selectBestFit(mature);
            case CoinSelectionStrategy::LARGEST_FIRST:
                return selectLargestFirst(mature);
            case CoinSelectionStrategy::SMALLEST_FIRST:
                return selectSmallestFirst(mature);
            case CoinSelectionStrategy::RANDOM:
                return selectRandom(mature);
            case CoinSelectionStrategy::OPTIMAL:
                return selectOptimal(mature);
            default:
                return selectFirstFit(mature);
        }
    }

    CoinSelectionResult CoinSelector::selectFirstFit(const std::vector<UTXOEntry>& utxos) const {
        CoinSelectionResult result;
        result.totalRequired = target + fee;

        uint64_t selectedAmount = 0;
        for (const auto& utxo : utxos) {
            result.selected.push_back(utxo);
            selectedAmount += utxo.amount;
            result.totalSelected = selectedAmount;

            if (selectedAmount >= result.totalRequired) {
                result.success = true;
                result.change = selectedAmount - result.totalRequired;
                break;
            }
        }

        if (!result.success) {
            result.error = "Insufficient funds";
        }

        return result;
    }

    CoinSelectionResult CoinSelector::selectBestFit(const std::vector<UTXOEntry>& utxos) const {
        CoinSelectionResult result;
        result.totalRequired = target + fee;

        uint64_t bestWaste = UINT64_MAX;
        std::vector<UTXOEntry> bestSelection;

        // Simple best-fit algorithm (NP-hard, so we use heuristic)
        // For small numbers of UTXOs, we could do exact knapsack
        size_t n = utxos.size();
        size_t maxCheck = std::min(n, size_t(20)); // Limit for performance

        for (size_t i = 0; i < maxCheck; i++) {
            std::vector<UTXOEntry> selection;
            uint64_t amount = 0;
            
            for (size_t j = i; j < n && amount < result.totalRequired; j++) {
                selection.push_back(utxos[j]);
                amount += utxos[j].amount;
            }

            if (amount >= result.totalRequired) {
                uint64_t waste = amount - result.totalRequired;
                if (waste < bestWaste) {
                    bestWaste = waste;
                    bestSelection = selection;
                }
            }
        }

        if (!bestSelection.empty()) {
            result.success = true;
            result.selected = bestSelection;
            result.totalSelected = result.totalRequired + bestWaste;
            result.change = bestWaste;
        } else {
            result.error = "Insufficient funds";
        }

        return result;
    }

    CoinSelectionResult CoinSelector::selectLargestFirst(const std::vector<UTXOEntry>& utxos) const {
        auto sorted = utxos;
        std::sort(sorted.begin(), sorted.end(),
            [](const UTXOEntry& a, const UTXOEntry& b) {
                return a.amount > b.amount;
            });

        return selectFirstFit(sorted);
    }

    CoinSelectionResult CoinSelector::selectSmallestFirst(const std::vector<UTXOEntry>& utxos) const {
        auto sorted = utxos;
        std::sort(sorted.begin(), sorted.end(),
            [](const UTXOEntry& a, const UTXOEntry& b) {
                return a.amount < b.amount;
            });

        return selectFirstFit(sorted);
    }

    CoinSelectionResult CoinSelector::selectRandom(const std::vector<UTXOEntry>& utxos) const {
        auto shuffled = utxos;
        std::random_device rd;
        std::mt19937 g(rd());
        std::shuffle(shuffled.begin(), shuffled.end(), g);

        return selectFirstFit(shuffled);
    }

    CoinSelectionResult CoinSelector::selectOptimal(const std::vector<UTXOEntry>& utxos) const {
        // Try best-fit first, fall back to largest-first
        auto result = selectBestFit(utxos);
        if (!result.success) {
            result = selectLargestFirst(utxos);
        }
        return result;
    }

} // namespace powercoin