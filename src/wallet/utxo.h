#ifndef POWERCOIN_UTXO_H
#define POWERCOIN_UTXO_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <functional>
#include <mutex>
#include <chrono>
#include "../blockchain/transaction.h"

namespace powercoin {

    /**
     * UTXO status flags
     */
    enum class UTXOStatus : uint8_t {
        UNSPENT = 0,
        SPENT = 1,
        LOCKED = 2,
        FROZEN = 3,
        COINBASE = 4,
        IMMATURE = 5
    };

    /**
     * UTXO entry structure
     */
    struct UTXOEntry {
        std::string txHash;
        uint32_t outputIndex;
        std::string address;
        uint64_t amount;
        uint32_t blockHeight;
        uint32_t confirmations;
        UTXOStatus status;
        uint64_t createdAt;
        uint64_t spentAt;
        std::string spentByTx;
        std::string script;
        bool isCoinbase;
        
        UTXOEntry();
        std::string toString() const;
        bool isSpendable() const;
        bool isMature(uint32_t currentHeight) const;
        std::string getKey() const;
    };

    /**
     * UTXO set statistics
     */
    struct UTXOSetStats {
        uint64_t totalUTXOs;
        uint64_t totalAmount;
        uint64_t spendableUTXOs;
        uint64_t spendableAmount;
        uint64_t immatureUTXOs;
        uint64_t immatureAmount;
        uint64_t lockedUTXOs;
        uint64_t lockedAmount;
        uint64_t coinbaseUTXOs;
        uint64_t coinbaseAmount;
        uint32_t averageConfirmations;
        size_t addressCount;
        
        UTXOSetStats();
        std::string toString() const;
    };

    /**
     * UTXO filter criteria
     */
    struct UTXOFilters {
        std::string address;
        uint64_t minAmount;
        uint64_t maxAmount;
        uint32_t minConfirmations;
        uint32_t maxConfirmations;
        bool includeSpent;
        bool includeLocked;
        bool includeImmature;
        bool onlyCoinbase;
        bool onlySpendable;
        std::set<UTXOStatus> statusFilter;
        
        UTXOFilters();
        bool matches(const UTXOEntry& utxo) const;
    };

    /**
     * Coin selection strategy
     */
    enum class CoinSelectionStrategy {
        FIRST_FIT,          // First sufficient UTXO
        BEST_FIT,           // Best fit (minimize waste)
        LARGEST_FIRST,      // Use largest UTXOs first
        SMALLEST_FIRST,     // Use smallest UTXOs first
        RANDOM,             // Random selection
        OPTIMAL             // Optimal for privacy
    };

    /**
     * Coin selection result
     */
    struct CoinSelectionResult {
        std::vector<UTXOEntry> selected;
        uint64_t totalSelected;
        uint64_t totalRequired;
        uint64_t change;
        bool success;
        std::string error;
        
        CoinSelectionResult();
        std::string toString() const;
    };

    /**
     * UTXO pool for mempool tracking
     */
    struct UTXOPoolEntry {
        UTXOEntry utxo;
        uint32_t mempoolTime;
        bool inMempool;
        
        UTXOPoolEntry();
    };

    /**
     * Main UTXO set class
     * Manages unspent transaction outputs
     */
    class UTXOSet {
    private:
        struct Impl;
        std::unique_ptr<Impl> impl;

    public:
        /**
         * Constructor
         */
        UTXOSet();

        /**
         * Destructor
         */
        ~UTXOSet();

        // Disable copy
        UTXOSet(const UTXOSet&) = delete;
        UTXOSet& operator=(const UTXOSet&) = delete;

        /**
         * Initialize UTXO set
         * @return true if successful
         */
        bool initialize();

        /**
         * Add UTXO from transaction output
         * @param tx Transaction
         * @param outputIndex Output index
         * @param blockHeight Block height
         * @return true if added
         */
        bool addUTXO(const Transaction& tx, uint32_t outputIndex, uint32_t blockHeight);

        /**
         * Add UTXO from entry
         * @param utxo UTXO entry
         * @return true if added
         */
        bool addUTXO(const UTXOEntry& utxo);

        /**
         * Remove UTXO (mark as spent)
         * @param txHash Transaction hash
         * @param outputIndex Output index
         * @param spentByTx Spending transaction hash
         * @param blockHeight Spending block height
         * @return true if removed
         */
        bool spendUTXO(const std::string& txHash, uint32_t outputIndex,
                       const std::string& spentByTx, uint32_t blockHeight);

        /**
         * Remove UTXO permanently
         * @param txHash Transaction hash
         * @param outputIndex Output index
         * @return true if removed
         */
        bool removeUTXO(const std::string& txHash, uint32_t outputIndex);

        /**
         * Get UTXO by key
         * @param txHash Transaction hash
         * @param outputIndex Output index
         * @return UTXO entry
         */
        UTXOEntry getUTXO(const std::string& txHash, uint32_t outputIndex) const;

        /**
         * Check if UTXO exists
         * @param txHash Transaction hash
         * @param outputIndex Output index
         * @return true if exists
         */
        bool hasUTXO(const std::string& txHash, uint32_t outputIndex) const;

        /**
         * Get all UTXOs for address
         * @param address Bitcoin address
         * @param filters Optional filters
         * @return Vector of UTXOs
         */
        std::vector<UTXOEntry> getUTXOsForAddress(const std::string& address,
                                                   const UTXOFilters& filters = UTXOFilters()) const;

        /**
         * Get all UTXOs
         * @param filters Optional filters
         * @return Vector of UTXOs
         */
        std::vector<UTXOEntry> getUTXOs(const UTXOFilters& filters = UTXOFilters()) const;

        /**
         * Get balance for address
         * @param address Bitcoin address
         * @param minConfirmations Minimum confirmations
         * @return Balance in satoshis
         */
        uint64_t getBalance(const std::string& address, uint32_t minConfirmations = 1) const;

        /**
         * Get total balance
         * @param minConfirmations Minimum confirmations
         * @return Total balance
         */
        uint64_t getTotalBalance(uint32_t minConfirmations = 1) const;

        /**
         * Get spendable balance for address
         * @param address Bitcoin address
         * @param currentHeight Current block height
         * @return Spendable balance
         */
        uint64_t getSpendableBalance(const std::string& address, uint32_t currentHeight) const;

        /**
         * Get UTXO set statistics
         * @return UTXO set stats
         */
        UTXOSetStats getStats() const;

        /**
         * Select coins for transaction
         * @param targetAmount Target amount in satoshis
         * @param address Source address (empty for all)
         * @param strategy Selection strategy
         * @param currentHeight Current block height
         * @param minConfirmations Minimum confirmations
         * @return Coin selection result
         */
        CoinSelectionResult selectCoins(uint64_t targetAmount,
                                        const std::string& address = "",
                                        CoinSelectionStrategy strategy = CoinSelectionStrategy::FIRST_FIT,
                                        uint32_t currentHeight = 0,
                                        uint32_t minConfirmations = 1) const;

        /**
         * Select coins with fee consideration
         * @param targetAmount Target amount
         * @param feeEstimate Estimated fee
         * @param address Source address
         * @param strategy Selection strategy
         * @return Coin selection result
         */
        CoinSelectionResult selectCoinsWithFee(uint64_t targetAmount,
                                               uint64_t feeEstimate,
                                               const std::string& address = "",
                                               CoinSelectionStrategy strategy = CoinSelectionStrategy::OPTIMAL) const;

        /**
         * Update confirmations for all UTXOs
         * @param currentHeight Current block height
         */
        void updateConfirmations(uint32_t currentHeight);

        /**
         * Lock UTXO (prevent spending)
         * @param txHash Transaction hash
         * @param outputIndex Output index
         * @param lock true to lock, false to unlock
         * @return true if successful
         */
        bool lockUTXO(const std::string& txHash, uint32_t outputIndex, bool lock = true);

        /**
         * Check if UTXO is locked
         * @param txHash Transaction hash
         * @param outputIndex Output index
         * @return true if locked
         */
        bool isLocked(const std::string& txHash, uint32_t outputIndex) const;

        /**
         * Get locked UTXOs
         * @return Vector of locked UTXOs
         */
        std::vector<UTXOEntry> getLockedUTXOs() const;

        /**
         * Freeze UTXO (temporary lock)
         * @param txHash Transaction hash
         * @param outputIndex Output index
         * @param duration Freeze duration in seconds
         * @return true if frozen
         */
        bool freezeUTXO(const std::string& txHash, uint32_t outputIndex, 
                        std::chrono::seconds duration);

        /**
         * Unfreeze UTXO
         * @param txHash Transaction hash
         * @param outputIndex Output index
         * @return true if unfrozen
         */
        bool unfreezeUTXO(const std::string& txHash, uint32_t outputIndex);

        /**
         * Add to mempool pool
         * @param tx Transaction in mempool
         */
        void addToMempool(const Transaction& tx);

        /**
         * Remove from mempool pool
         * @param txHash Transaction hash
         */
        void removeFromMempool(const std::string& txHash);

        /**
         * Check if UTXO is in mempool
         * @param txHash Transaction hash
         * @param outputIndex Output index
         * @return true if in mempool
         */
        bool isInMempool(const std::string& txHash, uint32_t outputIndex) const;

        /**
         * Get mempool UTXOs
         * @return Vector of mempool UTXOs
         */
        std::vector<UTXOPoolEntry> getMempoolUTXOs() const;

        /**
         * Clear mempool
         */
        void clearMempool();

        /**
         * Prune old UTXOs (spent and old)
         * @param olderThan Prune older than this many blocks
         * @return Number pruned
         */
        size_t prune(size_t olderThan = 1000);

        /**
         * Get UTXO count
         * @return Number of UTXOs
         */
        size_t size() const;

        /**
         * Get memory usage
         * @return Memory usage in bytes
         */
        size_t memoryUsage() const;

        /**
         * Save UTXO set to file
         * @param path File path
         * @return true if successful
         */
        bool save(const std::string& path) const;

        /**
         * Load UTXO set from file
         * @param path File path
         * @return true if successful
         */
        bool load(const std::string& path);

        /**
         * Clear UTXO set
         */
        void clear();

        // Callbacks
        void setOnUTXOAdded(std::function<void(const UTXOEntry&)> callback);
        void setOnUTXOSpent(std::function<void(const UTXOEntry&, const std::string&)> callback);
        void setOnUTXORemoved(std::function<void(const UTXOEntry&)> callback);
        void setOnBalanceChanged(std::function<void(uint64_t, uint64_t)> callback);

    private:
        mutable std::mutex mutex;
    };

    /**
     * UTXO cache for performance
     */
    class UTXOCache {
    private:
        struct Entry {
            UTXOEntry utxo;
            std::chrono::steady_clock::time_point accessTime;
        };

        std::map<std::string, Entry> cache;
        size_t maxSize;
        mutable std::mutex mutex;

    public:
        explicit UTXOCache(size_t maxSize = 10000);
        ~UTXOCache();

        bool put(const UTXOEntry& utxo);
        UTXOEntry get(const std::string& key);
        bool remove(const std::string& key);
        void clear();
        bool contains(const std::string& key) const;
        size_t size() const;
        void prune();
    };

    /**
     * UTXO indexer for fast lookups
     */
    class UTXOIndex {
    private:
        std::map<std::string, std::set<std::string>> addressIndex;
        std::map<uint64_t, std::set<std::string>> amountIndex;
        std::map<uint32_t, std::set<std::string>> heightIndex;
        mutable std::mutex mutex;

    public:
        UTXOIndex() = default;
        ~UTXOIndex() = default;

        void addUTXO(const UTXOEntry& utxo);
        void removeUTXO(const UTXOEntry& utxo);
        void updateUTXO(const UTXOEntry& oldUtxo, const UTXOEntry& newUtxo);
        
        std::vector<UTXOEntry> getByAddress(const std::string& address,
                                            const UTXOFilters& filters = UTXOFilters()) const;
        std::vector<UTXOEntry> getByAmountRange(uint64_t minAmount, uint64_t maxAmount) const;
        std::vector<UTXOEntry> getByHeight(uint32_t minHeight, uint32_t maxHeight) const;
        
        size_t size() const;
        void clear();
    };

    /**
     * UTXO coin selector with multiple strategies
     */
    class CoinSelector {
    private:
        const UTXOSet* utxoSet;
        uint64_t target;
        uint64_t fee;
        std::string address;
        uint32_t currentHeight;
        uint32_t minConfirmations;

        // Selection algorithms
        CoinSelectionResult selectFirstFit(const std::vector<UTXOEntry>& utxos) const;
        CoinSelectionResult selectBestFit(const std::vector<UTXOEntry>& utxos) const;
        CoinSelectionResult selectLargestFirst(const std::vector<UTXOEntry>& utxos) const;
        CoinSelectionResult selectSmallestFirst(const std::vector<UTXOEntry>& utxos) const;
        CoinSelectionResult selectRandom(const std::vector<UTXOEntry>& utxos) const;
        CoinSelectionResult selectOptimal(const std::vector<UTXOEntry>& utxos) const;

    public:
        CoinSelector(const UTXOSet* set);

        CoinSelector& withTarget(uint64_t amount);
        CoinSelector& withFee(uint64_t feeAmount);
        CoinSelector& withAddress(const std::string& addr);
        CoinSelector& withCurrentHeight(uint32_t height);
        CoinSelector& withMinConfirmations(uint32_t confs);

        CoinSelectionResult select(CoinSelectionStrategy strategy = CoinSelectionStrategy::OPTIMAL) const;
    };

} // namespace powercoin

#endif // POWERCOIN_UTXO_H