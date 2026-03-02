#ifndef POWERCOIN_WALLET_H
#define POWERCOIN_WALLET_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <functional>
#include <mutex>
#include <chrono>
#include "../crypto/keys.h"
#include "../crypto/aes.h"
#include "../blockchain/transaction.h"
#include "../blockchain/block.h"

namespace powercoin {

    /**
     * Wallet types
     */
    enum class WalletType {
        HD_WALLET,           // Hierarchical Deterministic (BIP32)
        SINGLE_KEY,          // Single key pair
        MULTI_SIG,           // Multi-signature wallet
        WATCH_ONLY,          // Watch-only wallet (no private keys)
        COLD_STORAGE,        // Cold storage (offline)
        HARDWARE             // Hardware wallet
    };

    /**
     * Address type
     */
    enum class AddressType {
        P2PKH,               // Pay to Public Key Hash (legacy)
        P2SH,                // Pay to Script Hash
        P2WPKH,              // Pay to Witness Public Key Hash (native segwit)
        P2WSH,               // Pay to Witness Script Hash
        P2TR,                // Pay to Taproot
        P2PK                  // Pay to Public Key (rare)
    };

    /**
     * Wallet status
     */
    enum class WalletStatus {
        UNINITIALIZED,
        LOCKED,
        UNLOCKED,
        READY,
        ERROR,
        SYNCING
    };

    /**
     * UTXO (Unspent Transaction Output) for wallet
     */
    struct WalletUTXO {
        std::string txHash;
        uint32_t outputIndex;
        std::string address;
        uint64_t amount;
        uint32_t blockHeight;
        uint32_t confirmations;
        bool isCoinbase;
        bool isSpent;
        bool isLocked;
        std::string script;

        WalletUTXO();
        std::string toString() const;
        bool isMature() const;
    };

    /**
     * Wallet transaction
     */
    struct WalletTransaction {
        std::string txHash;
        int64_t timestamp;
        uint64_t amount;
        int64_t fee;
        uint32_t blockHeight;
        uint32_t confirmations;
        std::string fromAddress;
        std::string toAddress;
        std::vector<std::string> inputs;
        std::vector<std::string> outputs;
        bool isIncoming;
        bool isOutgoing;
        bool isPending;
        bool isConfirmed;

        WalletTransaction();
        std::string toString() const;
    };

    /**
     * Wallet account
     */
    struct WalletAccount {
        uint32_t index;
        std::string name;
        std::string purpose;
        std::string xpub;
        std::vector<std::string> addresses;
        uint64_t balance;
        uint32_t nextAddressIndex;
        uint32_t nextChangeIndex;

        WalletAccount();
        std::string toString() const;
    };

    /**
     * Wallet configuration
     */
    struct WalletConfig {
        WalletType type;
        AddressType defaultAddressType;
        std::string walletPath;
        std::string dbPath;
        uint32_t minConfirmations;
        uint32_t coinbaseMaturity;
        uint64_t minRelayFee;
        bool autoRescan;
        bool pruneHistory;
        bool enableLogging;
        std::string encryptionMethod;
        uint32_t keyDerivationIterations;

        WalletConfig();
    };

    /**
     * Wallet balance
     */
    struct WalletBalance {
        uint64_t total;
        uint64_t confirmed;
        uint64_t unconfirmed;
        uint64_t immature;
        uint64_t locked;
        uint64_t spendable;
        uint64_t watchOnly;

        WalletBalance();
        std::string toString() const;
    };

    /**
     * Wallet statistics
     */
    struct WalletStats {
        uint32_t accountCount;
        uint32_t addressCount;
        uint32_t transactionCount;
        uint32_t utxoCount;
        WalletBalance balance;
        uint64_t totalReceived;
        uint64_t totalSent;
        uint64_t totalFees;
        uint32_t lastBlockHeight;
        std::chrono::system_clock::time_point lastSyncTime;
        WalletStatus status;

        WalletStats();
        std::string toString() const;
    };

    /**
     * Main wallet class
     * Manages cryptocurrency wallets
     */
    class Wallet {
    private:
        struct Impl;
        std::unique_ptr<Impl> impl;

    public:
        /**
         * Constructor
         * @param config Wallet configuration
         */
        explicit Wallet(const WalletConfig& config = WalletConfig());

        /**
         * Destructor
         */
        ~Wallet();

        // Disable copy
        Wallet(const Wallet&) = delete;
        Wallet& operator=(const Wallet&) = delete;

        /**
         * Initialize wallet
         * @param seed Seed phrase or entropy
         * @param passphrase Optional passphrase
         * @return true if successful
         */
        bool initialize(const std::string& seed, const std::string& passphrase = "");

        /**
         * Initialize wallet with random seed
         * @param passphrase Optional passphrase
         * @return Generated seed phrase
         */
        std::string initializeNew(const std::string& passphrase = "");

        /**
         * Load wallet from file
         * @param path Wallet file path
         * @param password Wallet password
         * @return true if successful
         */
        bool load(const std::string& path, const std::string& password);

        /**
         * Save wallet to file
         * @param path Wallet file path
         * @param password Wallet password
         * @return true if successful
         */
        bool save(const std::string& path, const std::string& password);

        /**
         * Unlock wallet for operations
         * @param password Wallet password
         * @param timeout Unlock timeout in seconds (0 = forever)
         * @return true if successful
         */
        bool unlock(const std::string& password, uint32_t timeout = 300);

        /**
         * Lock wallet
         */
        void lock();

        /**
         * Check if wallet is locked
         * @return true if locked
         */
        bool isLocked() const;

        /**
         * Check if wallet is initialized
         * @return true if initialized
         */
        bool isInitialized() const;

        /**
         * Get wallet status
         * @return Current status
         */
        WalletStatus getStatus() const;

        /**
         * Get wallet configuration
         * @return Wallet config
         */
        const WalletConfig& getConfig() const { return config; }

        /**
         * Get wallet statistics
         * @return Wallet stats
         */
        WalletStats getStats() const;

        /**
         * Create new account
         * @param name Account name
         * @param purpose Purpose (BIP43)
         * @return Account index
         */
        uint32_t createAccount(const std::string& name, const std::string& purpose = "");

        /**
         * Get account by index
         * @param index Account index
         * @return Account info
         */
        std::unique_ptr<WalletAccount> getAccount(uint32_t index) const;

        /**
         * Get all accounts
         * @return Vector of account info
         */
        std::vector<WalletAccount> getAccounts() const;

        /**
         * Generate new address for account
         * @param accountIndex Account index
         * @param type Address type
         * @return New address
         */
        std::string getNewAddress(uint32_t accountIndex = 0, 
                                   AddressType type = AddressType::P2PKH);

        /**
         * Get change address for account
         * @param accountIndex Account index
         * @return Change address
         */
        std::string getChangeAddress(uint32_t accountIndex = 0);

        /**
         * Get all addresses for account
         * @param accountIndex Account index
         * @return Vector of addresses
         */
        std::vector<std::string> getAddresses(uint32_t accountIndex = 0) const;

        /**
         * Check if address belongs to wallet
         * @param address Address to check
         * @return true if address belongs to wallet
         */
        bool hasAddress(const std::string& address) const;

        /**
         * Get account index for address
         * @param address Wallet address
         * @return Account index, -1 if not found
         */
        int getAccountForAddress(const std::string& address) const;

        /**
         * Get private key for address
         * @param address Wallet address
         * @return Private key (empty if not found or locked)
         */
        std::vector<uint8_t> getPrivateKey(const std::string& address);

        /**
         * Get public key for address
         * @param address Wallet address
         * @return Public key
         */
        std::vector<uint8_t> getPublicKey(const std::string& address) const;

        /**
         * Get wallet balance
         * @param accountIndex Account index (-1 for all)
         * @return Wallet balance
         */
        WalletBalance getBalance(int accountIndex = -1) const;

        /**
         * Get UTXOs for account
         * @param accountIndex Account index (-1 for all)
         * @param minConfirmations Minimum confirmations
         * @return Vector of UTXOs
         */
        std::vector<WalletUTXO> getUTXOs(int accountIndex = -1, 
                                         uint32_t minConfirmations = 1) const;

        /**
         * Get transaction history
         * @param accountIndex Account index (-1 for all)
         * @param count Maximum number of transactions
         * @param offset Offset for pagination
         * @return Vector of wallet transactions
         */
        std::vector<WalletTransaction> getTransactions(int accountIndex = -1,
                                                       uint32_t count = 100,
                                                       uint32_t offset = 0) const;

        /**
         * Get transaction by hash
         * @param txHash Transaction hash
         * @return Wallet transaction info
         */
        std::unique_ptr<WalletTransaction> getTransaction(const std::string& txHash) const;

        /**
         * Create new transaction
         * @param toAddress Recipient address
         * @param amount Amount to send (in satoshis)
         * @param accountIndex Account index to send from
         * @param fee Optional fee (0 = auto-calculate)
         * @param changeAddress Optional change address
         * @return Created transaction
         */
        Transaction createTransaction(const std::string& toAddress,
                                      uint64_t amount,
                                      uint32_t accountIndex = 0,
                                      uint64_t fee = 0,
                                      const std::string& changeAddress = "");

        /**
         * Create multi-output transaction
         * @param outputs Map of address to amount
         * @param accountIndex Account index to send from
         * @param fee Optional fee
         * @return Created transaction
         */
        Transaction createTransaction(const std::map<std::string, uint64_t>& outputs,
                                      uint32_t accountIndex = 0,
                                      uint64_t fee = 0);

        /**
         * Sign transaction
         * @param tx Transaction to sign
         * @return true if signed successfully
         */
        bool signTransaction(Transaction& tx);

        /**
         * Send transaction
         * @param tx Transaction to send
         * @return true if sent successfully
         */
        bool sendTransaction(const Transaction& tx);

        /**
         * Broadcast transaction
         * @param tx Transaction to broadcast
         * @return true if broadcasted
         */
        bool broadcastTransaction(const Transaction& tx);

        /**
         * Rescan blockchain for wallet transactions
         * @param startHeight Starting height
         * @param progressCallback Progress callback
         * @return true if successful
         */
        bool rescan(uint32_t startHeight = 0,
                    std::function<void(uint32_t, uint32_t)> progressCallback = nullptr);

        /**
         * Import address for watch-only
         * @param address Address to watch
         * @param accountIndex Account to import to
         * @return true if imported
         */
        bool importAddress(const std::string& address, uint32_t accountIndex = 0);

        /**
         * Import private key
         * @param wif Private key in WIF format
         * @param accountIndex Account to import to
         * @param rescan Whether to rescan blockchain
         * @return true if imported
         */
        bool importPrivateKey(const std::string& wif, uint32_t accountIndex = 0, bool rescan = true);

        /**
         * Import HD seed
         * @param seed Seed phrase
         * @param passphrase Optional passphrase
         * @param accountIndex Account index
         * @return true if imported
         */
        bool importSeed(const std::string& seed, const std::string& passphrase = "",
                        uint32_t accountIndex = 0);

        /**
         * Export wallet seed
         * @param passphrase Passphrase for decryption
         * @return Seed phrase (empty if locked or not HD)
         */
        std::string exportSeed(const std::string& passphrase = "");

        /**
         * Export account extended public key
         * @param accountIndex Account index
         * @return Extended public key (xpub)
         */
        std::string exportAccountXPub(uint32_t accountIndex = 0) const;

        /**
         * Lock UTXO for spending
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
        bool isUTXOLocked(const std::string& txHash, uint32_t outputIndex) const;

        /**
         * Get locked UTXOs
         * @return Vector of locked UTXOs
         */
        std::vector<WalletUTXO> getLockedUTXOs() const;

        /**
         * Abandon transaction (remove from history)
         * @param txHash Transaction hash
         * @return true if abandoned
         */
        bool abandonTransaction(const std::string& txHash);

        /**
         * Estimate fee for transaction
         * @param txSize Transaction size in bytes
         * @param targetConfirmation Target confirmations
         * @return Estimated fee in satoshis
         */
        uint64_t estimateFee(uint32_t txSize, uint32_t targetConfirmation = 6) const;

        /**
         * Get minimum relay fee
         * @return Minimum relay fee
         */
        uint64_t getMinRelayFee() const { return config.minRelayFee; }

        /**
         * Set minimum relay fee
         * @param fee New minimum fee
         */
        void setMinRelayFee(uint64_t fee) { config.minRelayFee = fee; }

        /**
         * Update wallet with new block
         * @param block New block
         * @return true if updated
         */
        bool updateWithBlock(const Block& block);

        /**
         * Update wallet with new transaction
         * @param tx New transaction
         * @param blockHeight Current block height
         * @return true if updated
         */
        bool updateWithTransaction(const Transaction& tx, uint32_t blockHeight);

        /**
         * Remove transaction from wallet
         * @param txHash Transaction hash
         * @return true if removed
         */
        bool removeTransaction(const std::string& txHash);

        /**
         * Clear wallet data
         */
        void clear();

        // Callbacks
        void setOnBalanceChanged(std::function<void(const WalletBalance&)> callback);
        void setOnTransactionAdded(std::function<void(const WalletTransaction&)> callback);
        void setOnTransactionRemoved(std::function<void(const std::string&)> callback);
        void setOnAddressAdded(std::function<void(const std::string&, uint32_t)> callback);
        void setOnSyncProgress(std::function<void(uint32_t, uint32_t)> callback);
        void setOnError(std::function<void(const std::string&)> callback);

    private:
        WalletConfig config;
        mutable std::mutex mutex;
    };

    /**
     * Wallet manager for multiple wallets
     */
    class WalletManager {
    private:
        std::map<std::string, std::unique_ptr<Wallet>> wallets;
        std::string defaultWallet;
        mutable std::mutex mutex;

    public:
        WalletManager() = default;
        ~WalletManager() = default;

        /**
         * Create new wallet
         * @param name Wallet name
         * @param config Wallet configuration
         * @param seed Seed phrase
         * @return true if created
         */
        bool createWallet(const std::string& name, const WalletConfig& config,
                         const std::string& seed);

        /**
         * Load wallet from file
         * @param name Wallet name
         * @param path Wallet file path
         * @param password Wallet password
         * @return true if loaded
         */
        bool loadWallet(const std::string& name, const std::string& path,
                       const std::string& password);

        /**
         * Unload wallet
         * @param name Wallet name
         * @return true if unloaded
         */
        bool unloadWallet(const std::string& name);

        /**
         * Get wallet by name
         * @param name Wallet name
         * @return Wallet pointer or nullptr
         */
        Wallet* getWallet(const std::string& name);

        /**
         * Get default wallet
         * @return Default wallet pointer
         */
        Wallet* getDefaultWallet();

        /**
         * Set default wallet
         * @param name Wallet name
         */
        void setDefaultWallet(const std::string& name);

        /**
         * Get all wallet names
         * @return Vector of wallet names
         */
        std::vector<std::string> getWalletNames() const;

        /**
         * Get wallet count
         * @return Number of wallets
         */
        size_t getWalletCount() const { return wallets.size(); }

        /**
         * Save all wallets
         * @param password Master password
         * @return true if all saved
         */
        bool saveAll(const std::string& password);
    };

    /**
     * Wallet address validator
     */
    class AddressValidator {
    public:
        static bool isValid(const std::string& address);
        static bool isP2PKH(const std::string& address);
        static bool isP2SH(const std::string& address);
        static bool isP2WPKH(const std::string& address);
        static bool isP2WSH(const std::string& address);
        static bool isP2TR(const std::string& address);
        static AddressType detectType(const std::string& address);
        static std::string toLegacy(const std::string& address);
        static std::string toBech32(const std::string& address);
        static std::vector<uint8_t> extractHash160(const std::string& address);
    };

} // namespace powercoin

#endif // POWERCOIN_WALLET_H