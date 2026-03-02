#ifndef POWERCOIN_KEYSTORE_H
#define POWERCOIN_KEYSTORE_H

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

namespace powercoin {

    /**
     * Key type enumeration
     */
    enum class KeyType {
        PRIVATE_KEY,
        PUBLIC_KEY,
        EXTENDED_PRIVATE,
        EXTENDED_PUBLIC,
        SEED_PHRASE,
        MASTER_KEY,
        SCRIPT
    };

    /**
     * Key purpose (BIP43)
     */
    enum class KeyPurpose {
        PAYMENT,           // External addresses (receive)
        CHANGE,            // Internal addresses (change)
        STAKING,           // Staking keys
        VOTING,            // Governance voting keys
        MULTISIG,          // Multi-signature keys
        COLD_STORAGE,      // Cold storage keys
        HARDWARE           // Hardware wallet keys
    };

    /**
     * Key metadata
     */
    struct KeyMetadata {
        std::string id;
        KeyType type;
        KeyPurpose purpose;
        std::string label;
        std::string description;
        uint64_t createdAt;
        uint64_t lastUsed;
        uint32_t useCount;
        std::vector<std::string> tags;
        bool isLocked;
        bool isBackedUp;
        bool isImported;
        uint32_t accountIndex;
        uint32_t addressIndex;
        std::string path;           // Derivation path (e.g., "m/44'/0'/0'/0/0")
        
        KeyMetadata();
        std::string toString() const;
    };

    /**
     * Key entry in keystore
     */
    struct KeyEntry {
        KeyMetadata metadata;
        std::vector<uint8_t> keyData;
        std::vector<uint8_t> chainCode;
        std::vector<uint8_t> encryptedData;
        bool isEncrypted;
        
        KeyEntry();
        bool isEmpty() const { return keyData.empty() && encryptedData.empty(); }
        size_t size() const { return keyData.size() + encryptedData.size(); }
    };

    /**
     * Keystore configuration
     */
    struct KeystoreConfig {
        std::string storagePath;
        std::string encryptionMethod;
        uint32_t keyDerivationIterations;
        bool autoLock;
        uint32_t autoLockTimeout;
        bool encryptByDefault;
        bool cacheKeys;
        size_t maxCacheSize;
        bool enableLogging;
        
        KeystoreConfig();
    };

    /**
     * Keystore statistics
     */
    struct KeystoreStats {
        uint32_t totalKeys;
        uint32_t privateKeys;
        uint32_t publicKeys;
        uint32_t extendedKeys;
        uint32_t seeds;
        uint32_t encryptedKeys;
        uint32_t lockedKeys;
        uint32_t backedUp;
        uint64_t totalSize;
        uint64_t cacheHits;
        uint64_t cacheMisses;
        std::chrono::milliseconds averageAccessTime;
        
        KeystoreStats();
        std::string toString() const;
    };

    /**
     * Key search criteria
     */
    struct KeySearchCriteria {
        KeyType type;
        KeyPurpose purpose;
        std::string label;
        std::string tag;
        uint32_t accountIndex;
        std::string path;
        bool onlyLocked;
        bool onlyUnlocked;
        bool onlyBackedUp;
        
        KeySearchCriteria();
        bool matches(const KeyMetadata& metadata) const;
    };

    /**
     * Main keystore class
     * Secure storage for cryptographic keys
     */
    class Keystore {
    private:
        struct Impl;
        std::unique_ptr<Impl> impl;

    public:
        /**
         * Constructor
         * @param config Keystore configuration
         */
        explicit Keystore(const KeystoreConfig& config = KeystoreConfig());

        /**
         * Destructor
         */
        ~Keystore();

        // Disable copy
        Keystore(const Keystore&) = delete;
        Keystore& operator=(const Keystore&) = delete;

        /**
         * Initialize keystore
         * @param password Master password for encryption
         * @return true if successful
         */
        bool initialize(const std::string& password);

        /**
         * Load keystore from file
         * @param path File path
         * @param password Master password
         * @return true if successful
         */
        bool load(const std::string& path, const std::string& password);

        /**
         * Save keystore to file
         * @param path File path
         * @param password Master password
         * @return true if successful
         */
        bool save(const std::string& path, const std::string& password);

        /**
         * Unlock keystore for operations
         * @param password Master password
         * @param timeout Unlock timeout in seconds
         * @return true if successful
         */
        bool unlock(const std::string& password, uint32_t timeout = 300);

        /**
         * Lock keystore
         */
        void lock();

        /**
         * Check if keystore is locked
         * @return true if locked
         */
        bool isLocked() const;

        /**
         * Check if keystore is initialized
         * @return true if initialized
         */
        bool isInitialized() const;

        /**
         * Get keystore statistics
         * @return Keystore stats
         */
        KeystoreStats getStats() const;

        /**
         * Add private key to keystore
         * @param privateKey Private key bytes
         * @param metadata Key metadata
         * @param password Optional encryption password (uses master if empty)
         * @return Key ID
         */
        std::string addPrivateKey(const std::vector<uint8_t>& privateKey,
                                   const KeyMetadata& metadata,
                                   const std::string& password = "");

        /**
         * Add private key in WIF format
         * @param wif Private key in WIF format
         * @param metadata Key metadata
         * @param password Optional encryption password
         * @return Key ID
         */
        std::string addPrivateKeyWIF(const std::string& wif,
                                      const KeyMetadata& metadata,
                                      const std::string& password = "");

        /**
         * Add public key to keystore
         * @param publicKey Public key bytes
         * @param metadata Key metadata
         * @return Key ID
         */
        std::string addPublicKey(const std::vector<uint8_t>& publicKey,
                                  const KeyMetadata& metadata);

        /**
         * Add extended private key (xprv)
         * @param xprv Extended private key
         * @param metadata Key metadata
         * @param password Optional encryption password
         * @return Key ID
         */
        std::string addExtendedPrivate(const std::string& xprv,
                                        const KeyMetadata& metadata,
                                        const std::string& password = "");

        /**
         * Add extended public key (xpub)
         * @param xpub Extended public key
         * @param metadata Key metadata
         * @return Key ID
         */
        std::string addExtendedPublic(const std::string& xpub,
                                       const KeyMetadata& metadata);

        /**
         * Add seed phrase
         * @param seed Seed phrase (BIP39)
         * @param metadata Key metadata
         * @param password Optional encryption password
         * @return Key ID
         */
        std::string addSeed(const std::string& seed,
                             const KeyMetadata& metadata,
                             const std::string& password = "");

        /**
         * Add script
         * @param script Script bytes
         * @param metadata Key metadata
         * @return Key ID
         */
        std::string addScript(const std::vector<uint8_t>& script,
                               const KeyMetadata& metadata);

        /**
         * Get key by ID
         * @param id Key ID
         * @param password Password for decryption (if needed)
         * @return Key entry (empty if not found)
         */
        KeyEntry getKey(const std::string& id, const std::string& password = "");

        /**
         * Get private key by ID
         * @param id Key ID
         * @param password Password for decryption
         * @return Private key bytes (empty if not found)
         */
        std::vector<uint8_t> getPrivateKey(const std::string& id,
                                            const std::string& password = "");

        /**
         * Get public key by ID
         * @param id Key ID
         * @return Public key bytes (empty if not found)
         */
        std::vector<uint8_t> getPublicKey(const std::string& id) const;

        /**
         * Get key metadata
         * @param id Key ID
         * @return Key metadata
         */
        KeyMetadata getMetadata(const std::string& id) const;

        /**
         * Update key metadata
         * @param id Key ID
         * @param metadata New metadata
         * @return true if updated
         */
        bool updateMetadata(const std::string& id, const KeyMetadata& metadata);

        /**
         * Remove key from keystore
         * @param id Key ID
         * @return true if removed
         */
        bool removeKey(const std::string& id);

        /**
         * Check if key exists
         * @param id Key ID
         * @return true if exists
         */
        bool hasKey(const std::string& id) const;

        /**
         * Find keys by criteria
         * @param criteria Search criteria
         * @return Vector of key IDs
         */
        std::vector<std::string> findKeys(const KeySearchCriteria& criteria) const;

        /**
         * Get all key IDs
         * @return Vector of key IDs
         */
        std::vector<std::string> getAllKeyIds() const;

        /**
         * Get keys by type
         * @param type Key type
         * @return Vector of key IDs
         */
        std::vector<std::string> getKeysByType(KeyType type) const;

        /**
         * Get keys by purpose
         * @param purpose Key purpose
         * @return Vector of key IDs
         */
        std::vector<std::string> getKeysByPurpose(KeyPurpose purpose) const;

        /**
         * Get keys by account
         * @param accountIndex Account index
         * @return Vector of key IDs
         */
        std::vector<std::string> getKeysByAccount(uint32_t accountIndex) const;

        /**
         * Get keys by tag
         * @param tag Tag
         * @return Vector of key IDs
         */
        std::vector<std::string> getKeysByTag(const std::string& tag) const;

        /**
         * Export key in WIF format
         * @param id Key ID
         * @param password Password for decryption
         * @return WIF string (empty if not found)
         */
        std::string exportWIF(const std::string& id, const std::string& password = "");

        /**
         * Export key in DER format
         * @param id Key ID
         * @param password Password for decryption
         * @return DER bytes
         */
        std::vector<uint8_t> exportDER(const std::string& id,
                                        const std::string& password = "");

        /**
         * Import key from DER
         * @param der DER bytes
         * @param metadata Key metadata
         * @param password Optional encryption password
         * @return Key ID
         */
        std::string importDER(const std::vector<uint8_t>& der,
                               const KeyMetadata& metadata,
                               const std::string& password = "");

        /**
         * Lock specific key
         * @param id Key ID
         * @return true if locked
         */
        bool lockKey(const std::string& id);

        /**
         * Unlock specific key
         * @param id Key ID
         * @param password Key password
         * @param timeout Unlock timeout
         * @return true if unlocked
         */
        bool unlockKey(const std::string& id, const std::string& password,
                       uint32_t timeout = 300);

        /**
         * Check if key is locked
         * @param id Key ID
         * @return true if locked
         */
        bool isKeyLocked(const std::string& id) const;

        /**
         * Mark key as backed up
         * @param id Key ID
         * @return true if updated
         */
        bool markBackedUp(const std::string& id);

        /**
         * Change master password
         * @param oldPassword Current password
         * @param newPassword New password
         * @return true if changed
         */
        bool changePassword(const std::string& oldPassword,
                            const std::string& newPassword);

        /**
         * Change key password
         * @param id Key ID
         * @param oldPassword Current password
         * @param newPassword New password
         * @return true if changed
         */
        bool changeKeyPassword(const std::string& id,
                               const std::string& oldPassword,
                               const std::string& newPassword);

        /**
         * Clear cache
         */
        void clearCache();

        /**
         * Backup keystore
         * @param backupPath Backup file path
         * @param password Encryption password
         * @return true if successful
         */
        bool backup(const std::string& backupPath, const std::string& password);

        /**
         * Restore keystore from backup
         * @param backupPath Backup file path
         * @param password Encryption password
         * @return true if successful
         */
        bool restore(const std::string& backupPath, const std::string& password);

        /**
         * Get key count
         * @return Number of keys
         */
        size_t getKeyCount() const;

        /**
         * Get encrypted key count
         * @return Number of encrypted keys
         */
        size_t getEncryptedKeyCount() const;

        // Callbacks
        void setOnKeyAdded(std::function<void(const std::string&, const KeyMetadata&)> callback);
        void setOnKeyRemoved(std::function<void(const std::string&)> callback);
        void setOnKeyUpdated(std::function<void(const std::string&, const KeyMetadata&)> callback);
        void setOnLockStateChanged(std::function<void(bool)> callback);
        void setOnError(std::function<void(const std::string&)> callback);
    };

    /**
     * Key generator for creating keys
     */
    class KeyGenerator {
    public:
        /**
         * Generate random private key
         * @return 32-byte private key
         */
        static std::vector<uint8_t> generatePrivateKey();

        /**
         * Generate key pair from seed
         * @param seed Seed bytes
         * @return Key pair
         */
        static Keys generateFromSeed(const std::vector<uint8_t>& seed);

        /**
         * Generate HD key from seed
         * @param seed Seed bytes
         * @param path Derivation path
         * @return Derived key
         */
        static Keys deriveHDKey(const std::vector<uint8_t>& seed,
                                const std::string& path);

        /**
         * Generate multisig script
         * @param required Required signatures
         * @param publicKeys Public keys
         * @return Script bytes
         */
        static std::vector<uint8_t> generateMultisigScript(
            uint32_t required,
            const std::vector<std::vector<uint8_t>>& publicKeys);

        /**
         * Generate key ID
         * @param keyData Key data
         * @param metadata Key metadata
         * @return Unique key ID
         */
        static std::string generateKeyId(const std::vector<uint8_t>& keyData,
                                          const KeyMetadata& metadata);
    };

    /**
     * Key cache for performance
     */
    class KeyCache {
    private:
        struct Entry {
            KeyEntry key;
            std::chrono::steady_clock::time_point accessTime;
            uint32_t accessCount;
        };

        std::map<std::string, Entry> cache;
        size_t maxSize;
        mutable std::mutex mutex;

    public:
        explicit KeyCache(size_t maxSize = 1000);
        ~KeyCache();

        bool put(const std::string& id, const KeyEntry& key);
        KeyEntry get(const std::string& id);
        bool remove(const std::string& id);
        void clear();
        bool contains(const std::string& id) const;
        size_t size() const;
        void prune();
    };

} // namespace powercoin

#endif // POWERCOIN_KEYSTORE_H