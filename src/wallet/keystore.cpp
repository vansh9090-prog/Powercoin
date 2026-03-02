#include "keystore.h"
#include "../crypto/sha256.h"
#include "../crypto/ripemd160.h"
#include "../crypto/aes.h"
#include "../crypto/random.h"
#include "../crypto/base58.h"
#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <cmath>

namespace powercoin {

    // ============== KeyMetadata Implementation ==============

    KeyMetadata::KeyMetadata()
        : type(KeyType::PUBLIC_KEY),
          purpose(KeyPurpose::PAYMENT),
          createdAt(0),
          lastUsed(0),
          useCount(0),
          isLocked(false),
          isBackedUp(false),
          isImported(false),
          accountIndex(0),
          addressIndex(0) {}

    std::string KeyMetadata::toString() const {
        std::stringstream ss;
        ss << "Key: " << id << "\n";
        ss << "  Type: " << static_cast<int>(type) << "\n";
        ss << "  Purpose: " << static_cast<int>(purpose) << "\n";
        ss << "  Label: " << label << "\n";
        ss << "  Path: " << path << "\n";
        ss << "  Account: " << accountIndex << "\n";
        ss << "  Address Index: " << addressIndex << "\n";
        ss << "  Created: " << createdAt << "\n";
        ss << "  Last Used: " << lastUsed << "\n";
        ss << "  Uses: " << useCount << "\n";
        ss << "  Status: " << (isLocked ? "Locked" : "Unlocked") << "\n";
        ss << "  Backed Up: " << (isBackedUp ? "Yes" : "No") << "\n";
        return ss.str();
    }

    // ============== KeyEntry Implementation ==============

    KeyEntry::KeyEntry() : isEncrypted(false) {}

    // ============== KeystoreConfig Implementation ==============

    KeystoreConfig::KeystoreConfig()
        : storagePath("keystore.dat"),
          encryptionMethod("aes-256-cbc"),
          keyDerivationIterations(100000),
          autoLock(true),
          autoLockTimeout(300),
          encryptByDefault(true),
          cacheKeys(true),
          maxCacheSize(1000),
          enableLogging(true) {}

    // ============== KeystoreStats Implementation ==============

    KeystoreStats::KeystoreStats()
        : totalKeys(0),
          privateKeys(0),
          publicKeys(0),
          extendedKeys(0),
          seeds(0),
          encryptedKeys(0),
          lockedKeys(0),
          backedUp(0),
          totalSize(0),
          cacheHits(0),
          cacheMisses(0),
          averageAccessTime(0) {}

    std::string KeystoreStats::toString() const {
        std::stringstream ss;
        ss << "Keystore Statistics:\n";
        ss << "  Total Keys: " << totalKeys << "\n";
        ss << "  Private Keys: " << privateKeys << "\n";
        ss << "  Public Keys: " << publicKeys << "\n";
        ss << "  Extended Keys: " << extendedKeys << "\n";
        ss << "  Seeds: " << seeds << "\n";
        ss << "  Encrypted: " << encryptedKeys << "\n";
        ss << "  Locked: " << lockedKeys << "\n";
        ss << "  Backed Up: " << backedUp << "\n";
        ss << "  Total Size: " << (totalSize / 1024) << " KB\n";
        ss << "  Cache Hits: " << cacheHits << "\n";
        ss << "  Cache Misses: " << cacheMisses << "\n";
        ss << "  Avg Access: " << averageAccessTime.count() << " ms\n";
        return ss.str();
    }

    // ============== KeySearchCriteria Implementation ==============

    KeySearchCriteria::KeySearchCriteria()
        : type(KeyType::PRIVATE_KEY),
          purpose(KeyPurpose::PAYMENT),
          accountIndex(0),
          onlyLocked(false),
          onlyUnlocked(false),
          onlyBackedUp(false) {}

    bool KeySearchCriteria::matches(const KeyMetadata& metadata) const {
        if (type != metadata.type) return false;
        if (purpose != metadata.purpose) return false;
        if (!label.empty() && metadata.label != label) return false;
        if (!tag.empty()) {
            if (std::find(metadata.tags.begin(), metadata.tags.end(), tag) == metadata.tags.end()) {
                return false;
            }
        }
        if (accountIndex != metadata.accountIndex) return false;
        if (!path.empty() && metadata.path != path) return false;
        if (onlyLocked && !metadata.isLocked) return false;
        if (onlyUnlocked && metadata.isLocked) return false;
        if (onlyBackedUp && !metadata.isBackedUp) return false;
        return true;
    }

    // ============== Keystore Implementation ==============

    struct Keystore::Impl {
        KeystoreConfig config;
        std::map<std::string, KeyEntry> keys;
        std::map<std::string, std::chrono::steady_clock::time_point> unlockTimes;
        std::vector<uint8_t> masterKey;
        std::vector<uint8_t> masterSalt;
        bool initialized;
        bool locked;
        KeystoreStats stats;
        std::unique_ptr<KeyCache> cache;
        
        std::chrono::steady_clock::time_point startTime;
        
        std::function<void(const std::string&, const KeyMetadata&)> onKeyAdded;
        std::function<void(const std::string&)> onKeyRemoved;
        std::function<void(const std::string&, const KeyMetadata&)> onKeyUpdated;
        std::function<void(bool)> onLockStateChanged;
        std::function<void(const std::string&)> onError;

        Impl() : initialized(false), locked(true) {
            startTime = std::chrono::steady_clock::now();
        }
    };

    Keystore::Keystore(const KeystoreConfig& config) {
        impl = std::make_unique<Impl>();
        impl->config = config;
        if (config.cacheKeys) {
            impl->cache = std::make_unique<KeyCache>(config.maxCacheSize);
        }
    }

    Keystore::~Keystore() = default;

    bool Keystore::initialize(const std::string& password) {
        std::lock_guard<std::mutex> lock(mutex);

        // Generate master salt
        impl->masterSalt = Random::getSalt(16);

        // Derive master key using PBKDF2
        impl->masterKey = SHA256::pbkdf2(
            reinterpret_cast<const uint8_t*>(password.c_str()), password.length(),
            impl->masterSalt.data(), impl->masterSalt.size(),
            impl->config.keyDerivationIterations, 32
        );

        impl->initialized = true;
        impl->locked = false;

        if (impl->onLockStateChanged) {
            impl->onLockStateChanged(false);
        }

        return true;
    }

    bool Keystore::load(const std::string& path, const std::string& password) {
        std::lock_guard<std::mutex> lock(mutex);

        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        // Read salt
        std::vector<uint8_t> salt(16);
        file.read(reinterpret_cast<char*>(salt.data()), salt.size());

        // Read encrypted data
        std::vector<uint8_t> encrypted(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>()
        );
        file.close();

        // Derive master key
        impl->masterKey = SHA256::pbkdf2(
            reinterpret_cast<const uint8_t*>(password.c_str()), password.length(),
            salt.data(), salt.size(),
            impl->config.keyDerivationIterations, 32
        );

        // Decrypt keystore
        AES aes(AESMode::CBC, AESKeyLength::AES_256, AESPadding::PKCS7);
        std::vector<uint8_t> iv(encrypted.begin(), encrypted.begin() + 16);
        std::vector<uint8_t> ciphertext(encrypted.begin() + 16, encrypted.end());

        aes.setKey(impl->masterKey);
        auto decrypted = aes.decrypt(ciphertext, iv);

        // Deserialize keys
        // TODO: Implement deserialization

        impl->initialized = true;
        impl->locked = false;

        return true;
    }

    bool Keystore::save(const std::string& path, const std::string& password) {
        std::lock_guard<std::mutex> lock(mutex);

        // Serialize keys
        std::vector<uint8_t> data;
        // TODO: Implement serialization

        // Encrypt
        AES aes(AESMode::CBC, AESKeyLength::AES_256, AESPadding::PKCS7);
        auto iv = aes.generateIV();

        std::vector<uint8_t> salt(16);
        Random::getBytes(salt.data(), salt.size());

        auto key = SHA256::pbkdf2(
            reinterpret_cast<const uint8_t*>(password.c_str()), password.length(),
            salt.data(), salt.size(),
            impl->config.keyDerivationIterations, 32
        );

        aes.setKey(key);
        auto encrypted = aes.encrypt(data, iv);

        // Write to file
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        file.write(reinterpret_cast<const char*>(salt.data()), salt.size());
        file.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        file.close();

        return true;
    }

    bool Keystore::unlock(const std::string& password, uint32_t timeout) {
        std::lock_guard<std::mutex> lock(mutex);

        // Verify password by decrypting a test key
        // In production, use proper verification

        impl->locked = false;
        if (timeout > 0) {
            auto unlockTime = std::chrono::steady_clock::now() + 
                             std::chrono::seconds(timeout);
            // Store in unlockTimes for master key
        }

        if (impl->onLockStateChanged) {
            impl->onLockStateChanged(false);
        }

        return true;
    }

    void Keystore::lock() {
        std::lock_guard<std::mutex> lock(mutex);

        impl->locked = true;
        impl->masterKey.clear();

        // Clear cache
        if (impl->cache) {
            impl->cache->clear();
        }

        if (impl->onLockStateChanged) {
            impl->onLockStateChanged(true);
        }
    }

    bool Keystore::isLocked() const {
        return impl->locked;
    }

    bool Keystore::isInitialized() const {
        return impl->initialized;
    }

    KeystoreStats Keystore::getStats() const {
        std::lock_guard<std::mutex> lock(mutex);

        impl->stats.totalKeys = impl->keys.size();

        // Reset counters
        impl->stats.privateKeys = 0;
        impl->stats.publicKeys = 0;
        impl->stats.extendedKeys = 0;
        impl->stats.seeds = 0;
        impl->stats.encryptedKeys = 0;
        impl->stats.lockedKeys = 0;
        impl->stats.totalSize = 0;

        for (const auto& [id, entry] : impl->keys) {
            if (entry.metadata.type == KeyType::PRIVATE_KEY) {
                impl->stats.privateKeys++;
            } else if (entry.metadata.type == KeyType::PUBLIC_KEY) {
                impl->stats.publicKeys++;
            } else if (entry.metadata.type == KeyType::EXTENDED_PRIVATE ||
                       entry.metadata.type == KeyType::EXTENDED_PUBLIC) {
                impl->stats.extendedKeys++;
            } else if (entry.metadata.type == KeyType::SEED_PHRASE) {
                impl->stats.seeds++;
            }

            if (entry.isEncrypted) {
                impl->stats.encryptedKeys++;
            }
            if (entry.metadata.isLocked) {
                impl->stats.lockedKeys++;
            }
            if (entry.metadata.isBackedUp) {
                impl->stats.backedUp++;
            }

            impl->stats.totalSize += entry.size();
        }

        return impl->stats;
    }

    std::string Keystore::addPrivateKey(const std::vector<uint8_t>& privateKey,
                                         const KeyMetadata& metadata,
                                         const std::string& password) {
        std::lock_guard<std::mutex> lock(mutex);

        KeyEntry entry;
        entry.metadata = metadata;
        entry.metadata.id = KeyGenerator::generateKeyId(privateKey, metadata);
        entry.metadata.createdAt = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();

        if (password.empty() && impl->config.encryptByDefault) {
            // Encrypt with master key
            AES aes(AESMode::CBC, AESKeyLength::AES_256, AESPadding::PKCS7);
            auto iv = aes.generateIV();
            aes.setKey(impl->masterKey);
            entry.encryptedData = aes.encrypt(privateKey, iv);
            entry.isEncrypted = true;
        } else if (!password.empty()) {
            // Encrypt with provided password
            auto key = SHA256::pbkdf2(
                reinterpret_cast<const uint8_t*>(password.c_str()), password.length(),
                impl->masterSalt.data(), impl->masterSalt.size(),
                impl->config.keyDerivationIterations, 32
            );

            AES aes(AESMode::CBC, AESKeyLength::AES_256, AESPadding::PKCS7);
            auto iv = aes.generateIV();
            aes.setKey(key);
            entry.encryptedData = aes.encrypt(privateKey, iv);
            entry.isEncrypted = true;
        } else {
            entry.keyData = privateKey;
            entry.isEncrypted = false;
        }

        impl->keys[entry.metadata.id] = entry;

        if (impl->onKeyAdded) {
            impl->onKeyAdded(entry.metadata.id, entry.metadata);
        }

        return entry.metadata.id;
    }

    std::string Keystore::addPrivateKeyWIF(const std::string& wif,
                                            const KeyMetadata& metadata,
                                            const std::string& password) {
        bool compressed;
        auto privateKey = Base58::decodePrivateKey(wif, compressed);
        return addPrivateKey(privateKey, metadata, password);
    }

    std::string Keystore::addPublicKey(const std::vector<uint8_t>& publicKey,
                                         const KeyMetadata& metadata) {
        std::lock_guard<std::mutex> lock(mutex);

        KeyEntry entry;
        entry.metadata = metadata;
        entry.metadata.id = KeyGenerator::generateKeyId(publicKey, metadata);
        entry.metadata.createdAt = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        entry.keyData = publicKey;
        entry.isEncrypted = false;

        impl->keys[entry.metadata.id] = entry;

        if (impl->onKeyAdded) {
            impl->onKeyAdded(entry.metadata.id, entry.metadata);
        }

        return entry.metadata.id;
    }

    std::string Keystore::addExtendedPrivate(const std::string& xprv,
                                               const KeyMetadata& metadata,
                                               const std::string& password) {
        auto decoded = Base58::decodeCheck(xprv);
        return addPrivateKey(decoded, metadata, password);
    }

    std::string Keystore::addExtendedPublic(const std::string& xpub,
                                              const KeyMetadata& metadata) {
        auto decoded = Base58::decodeCheck(xpub);
        return addPublicKey(decoded, metadata);
    }

    std::string Keystore::addSeed(const std::string& seed,
                                    const KeyMetadata& metadata,
                                    const std::string& password) {
        std::vector<uint8_t> seedData(seed.begin(), seed.end());
        return addPrivateKey(seedData, metadata, password);
    }

    std::string Keystore::addScript(const std::vector<uint8_t>& script,
                                      const KeyMetadata& metadata) {
        std::lock_guard<std::mutex> lock(mutex);

        KeyEntry entry;
        entry.metadata = metadata;
        entry.metadata.id = KeyGenerator::generateKeyId(script, metadata);
        entry.metadata.createdAt = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        entry.keyData = script;
        entry.isEncrypted = false;

        impl->keys[entry.metadata.id] = entry;

        if (impl->onKeyAdded) {
            impl->onKeyAdded(entry.metadata.id, entry.metadata);
        }

        return entry.metadata.id;
    }

    KeyEntry Keystore::getKey(const std::string& id, const std::string& password) {
        std::lock_guard<std::mutex> lock(mutex);

        auto accessStart = std::chrono::steady_clock::now();

        // Check cache first
        if (impl->cache && impl->cache->contains(id)) {
            impl->stats.cacheHits++;
            auto cached = impl->cache->get(id);
            
            auto accessTime = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - accessStart);
            impl->stats.averageAccessTime = (impl->stats.averageAccessTime + accessTime) / 2;
            
            return cached;
        }

        impl->stats.cacheMisses++;

        auto it = impl->keys.find(id);
        if (it == impl->keys.end()) {
            return KeyEntry();
        }

        KeyEntry entry = it->second;

        // Decrypt if necessary
        if (entry.isEncrypted && !entry.encryptedData.empty()) {
            std::vector<uint8_t> decryptionKey;

            if (!password.empty()) {
                // Use provided password
                decryptionKey = SHA256::pbkdf2(
                    reinterpret_cast<const uint8_t*>(password.c_str()), password.length(),
                    impl->masterSalt.data(), impl->masterSalt.size(),
                    impl->config.keyDerivationIterations, 32
                );
            } else {
                // Use master key
                decryptionKey = impl->masterKey;
            }

            AES aes(AESMode::CBC, AESKeyLength::AES_256, AESPadding::PKCS7);
            std::vector<uint8_t> iv(entry.encryptedData.begin(), 
                                     entry.encryptedData.begin() + 16);
            std::vector<uint8_t> ciphertext(entry.encryptedData.begin() + 16,
                                            entry.encryptedData.end());

            aes.setKey(decryptionKey);
            entry.keyData = aes.decrypt(ciphertext, iv);
        }

        // Update cache
        if (impl->cache) {
            impl->cache->put(id, entry);
        }

        // Update metadata
        auto& mutableEntry = impl->keys[id];
        mutableEntry.metadata.lastUsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        mutableEntry.metadata.useCount++;

        auto accessTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - accessStart);
        impl->stats.averageAccessTime = (impl->stats.averageAccessTime + accessTime) / 2;

        return entry;
    }

    std::vector<uint8_t> Keystore::getPrivateKey(const std::string& id,
                                                  const std::string& password) {
        auto entry = getKey(id, password);
        return entry.keyData;
    }

    std::vector<uint8_t> Keystore::getPublicKey(const std::string& id) const {
        auto it = impl->keys.find(id);
        if (it != impl->keys.end()) {
            return it->second.keyData;
        }
        return {};
    }

    KeyMetadata Keystore::getMetadata(const std::string& id) const {
        auto it = impl->keys.find(id);
        if (it != impl->keys.end()) {
            return it->second.metadata;
        }
        return KeyMetadata();
    }

    bool Keystore::updateMetadata(const std::string& id, const KeyMetadata& metadata) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = impl->keys.find(id);
        if (it == impl->keys.end()) {
            return false;
        }

        it->second.metadata = metadata;

        if (impl->cache) {
            impl->cache->remove(id);
        }

        if (impl->onKeyUpdated) {
            impl->onKeyUpdated(id, metadata);
        }

        return true;
    }

    bool Keystore::removeKey(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = impl->keys.find(id);
        if (it == impl->keys.end()) {
            return false;
        }

        impl->keys.erase(it);

        if (impl->cache) {
            impl->cache->remove(id);
        }

        if (impl->onKeyRemoved) {
            impl->onKeyRemoved(id);
        }

        return true;
    }

    bool Keystore::hasKey(const std::string& id) const {
        return impl->keys.find(id) != impl->keys.end();
    }

    std::vector<std::string> Keystore::findKeys(const KeySearchCriteria& criteria) const {
        std::vector<std::string> results;

        for (const auto& [id, entry] : impl->keys) {
            if (criteria.matches(entry.metadata)) {
                results.push_back(id);
            }
        }

        return results;
    }

    std::vector<std::string> Keystore::getAllKeyIds() const {
        std::vector<std::string> ids;
        for (const auto& [id, _] : impl->keys) {
            ids.push_back(id);
        }
        return ids;
    }

    std::vector<std::string> Keystore::getKeysByType(KeyType type) const {
        KeySearchCriteria criteria;
        criteria.type = type;
        return findKeys(criteria);
    }

    std::vector<std::string> Keystore::getKeysByPurpose(KeyPurpose purpose) const {
        KeySearchCriteria criteria;
        criteria.purpose = purpose;
        return findKeys(criteria);
    }

    std::vector<std::string> Keystore::getKeysByAccount(uint32_t accountIndex) const {
        KeySearchCriteria criteria;
        criteria.accountIndex = accountIndex;
        return findKeys(criteria);
    }

    std::vector<std::string> Keystore::getKeysByTag(const std::string& tag) const {
        KeySearchCriteria criteria;
        criteria.tag = tag;
        return findKeys(criteria);
    }

    std::string Keystore::exportWIF(const std::string& id, const std::string& password) {
        auto privateKey = getPrivateKey(id, password);
        if (privateKey.empty()) {
            return "";
        }

        bool compressed = true; // Default
        return Base58::encodePrivateKey(privateKey, compressed);
    }

    std::vector<uint8_t> Keystore::exportDER(const std::string& id,
                                               const std::string& password) {
        // TODO: Implement DER encoding
        return getPrivateKey(id, password);
    }

    std::string Keystore::importDER(const std::vector<uint8_t>& der,
                                      const KeyMetadata& metadata,
                                      const std::string& password) {
        // TODO: Implement DER decoding
        return addPrivateKey(der, metadata, password);
    }

    bool Keystore::lockKey(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = impl->keys.find(id);
        if (it == impl->keys.end()) {
            return false;
        }

        it->second.metadata.isLocked = true;

        if (impl->cache) {
            impl->cache->remove(id);
        }

        return true;
    }

    bool Keystore::unlockKey(const std::string& id, const std::string& password,
                              uint32_t timeout) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = impl->keys.find(id);
        if (it == impl->keys.end()) {
            return false;
        }

        // Verify password by attempting decryption
        auto entry = getKey(id, password);
        if (entry.isEmpty()) {
            return false;
        }

        it->second.metadata.isLocked = false;
        if (timeout > 0) {
            impl->unlockTimes[id] = std::chrono::steady_clock::now() + 
                                   std::chrono::seconds(timeout);
        }

        return true;
    }

    bool Keystore::isKeyLocked(const std::string& id) const {
        auto it = impl->keys.find(id);
        if (it == impl->keys.end()) {
            return true;
        }

        // Check timeout
        auto timeoutIt = impl->unlockTimes.find(id);
        if (timeoutIt != impl->unlockTimes.end()) {
            if (std::chrono::steady_clock::now() > timeoutIt->second) {
                const_cast<Keystore*>(this)->lockKey(id);
                return true;
            }
        }

        return it->second.metadata.isLocked;
    }

    bool Keystore::markBackedUp(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = impl->keys.find(id);
        if (it == impl->keys.end()) {
            return false;
        }

        it->second.metadata.isBackedUp = true;
        return true;
    }

    bool Keystore::changePassword(const std::string& oldPassword,
                                   const std::string& newPassword) {
        std::lock_guard<std::mutex> lock(mutex);

        // Verify old password
        if (!unlock(oldPassword, 0)) {
            return false;
        }

        // Derive new master key
        impl->masterSalt = Random::getSalt(16);
        impl->masterKey = SHA256::pbkdf2(
            reinterpret_cast<const uint8_t*>(newPassword.c_str()), newPassword.length(),
            impl->masterSalt.data(), impl->masterSalt.size(),
            impl->config.keyDerivationIterations, 32
        );

        return true;
    }

    bool Keystore::changeKeyPassword(const std::string& id,
                                      const std::string& oldPassword,
                                      const std::string& newPassword) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = impl->keys.find(id);
        if (it == impl->keys.end()) {
            return false;
        }

        // Decrypt with old password
        auto entry = getKey(id, oldPassword);
        if (entry.isEmpty()) {
            return false;
        }

        // Re-encrypt with new password
        auto key = SHA256::pbkdf2(
            reinterpret_cast<const uint8_t*>(newPassword.c_str()), newPassword.length(),
            impl->masterSalt.data(), impl->masterSalt.size(),
            impl->config.keyDerivationIterations, 32
        );

        AES aes(AESMode::CBC, AESKeyLength::AES_256, AESPadding::PKCS7);
        auto iv = aes.generateIV();
        aes.setKey(key);
        it->second.encryptedData = aes.encrypt(entry.keyData, iv);
        it->second.isEncrypted = true;

        if (impl->cache) {
            impl->cache->remove(id);
        }

        return true;
    }

    void Keystore::clearCache() {
        if (impl->cache) {
            impl->cache->clear();
        }
    }

    bool Keystore::backup(const std::string& backupPath, const std::string& password) {
        return save(backupPath, password);
    }

    bool Keystore::restore(const std::string& backupPath, const std::string& password) {
        return load(backupPath, password);
    }

    size_t Keystore::getKeyCount() const {
        return impl->keys.size();
    }

    size_t Keystore::getEncryptedKeyCount() const {
        size_t count = 0;
        for (const auto& [_, entry] : impl->keys) {
            if (entry.isEncrypted) count++;
        }
        return count;
    }

    void Keystore::setOnKeyAdded(std::function<void(const std::string&, const KeyMetadata&)> callback) {
        impl->onKeyAdded = callback;
    }

    void Keystore::setOnKeyRemoved(std::function<void(const std::string&)> callback) {
        impl->onKeyRemoved = callback;
    }

    void Keystore::setOnKeyUpdated(std::function<void(const std::string&, const KeyMetadata&)> callback) {
        impl->onKeyUpdated = callback;
    }

    void Keystore::setOnLockStateChanged(std::function<void(bool)> callback) {
        impl->onLockStateChanged = callback;
    }

    void Keystore::setOnError(std::function<void(const std::string&)> callback) {
        impl->onError = callback;
    }

    // ============== KeyGenerator Implementation ==============

    std::vector<uint8_t> KeyGenerator::generatePrivateKey() {
        return Random::getPrivateKey();
    }

    Keys KeyGenerator::generateFromSeed(const std::vector<uint8_t>& seed) {
        Keys keys;
        // In production, derive key from seed using BIP32
        keys.generateKeyPair();
        return keys;
    }

    Keys KeyGenerator::deriveHDKey(const std::vector<uint8_t>& seed,
                                    const std::string& path) {
        Keys keys;
        // TODO: Implement BIP32 derivation
        return keys;
    }

    std::vector<uint8_t> KeyGenerator::generateMultisigScript(
        uint32_t required,
        const std::vector<std::vector<uint8_t>>& publicKeys) {
        std::vector<uint8_t> script;

        // Add required signatures (OP_n)
        script.push_back(0x50 + required);

        // Add public keys
        for (const auto& key : publicKeys) {
            script.push_back(key.size());
            script.insert(script.end(), key.begin(), key.end());
        }

        // Add total keys
        script.push_back(0x50 + publicKeys.size());

        // Add OP_CHECKMULTISIG
        script.push_back(0xae);

        return script;
    }

    std::string KeyGenerator::generateKeyId(const std::vector<uint8_t>& keyData,
                                             const KeyMetadata& metadata) {
        std::stringstream ss;
        ss << static_cast<int>(metadata.type) << metadata.label 
           << metadata.accountIndex << metadata.addressIndex;
        for (auto byte : keyData) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
        }
        return SHA256::hash(ss.str()).substr(0, 16);
    }

    // ============== KeyCache Implementation ==============

    KeyCache::KeyCache(size_t maxSize) : maxSize(maxSize) {}

    KeyCache::~KeyCache() = default;

    bool KeyCache::put(const std::string& id, const KeyEntry& key) {
        std::lock_guard<std::mutex> lock(mutex);

        if (cache.size() >= maxSize) {
            prune();
        }

        Entry entry;
        entry.key = key;
        entry.accessTime = std::chrono::steady_clock::now();
        entry.accessCount = 1;

        cache[id] = entry;
        return true;
    }

    KeyEntry KeyCache::get(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = cache.find(id);
        if (it != cache.end()) {
            it->second.accessTime = std::chrono::steady_clock::now();
            it->second.accessCount++;
            return it->second.key;
        }
        return KeyEntry();
    }

    bool KeyCache::remove(const std::string& id) {
        std::lock_guard<std::mutex> lock(mutex);
        return cache.erase(id) > 0;
    }

    void KeyCache::clear() {
        std::lock_guard<std::mutex> lock(mutex);
        cache.clear();
    }

    bool KeyCache::contains(const std::string& id) const {
        std::lock_guard<std::mutex> lock(mutex);
        return cache.find(id) != cache.end();
    }

    size_t KeyCache::size() const {
        std::lock_guard<std::mutex> lock(mutex);
        return cache.size();
    }

    void KeyCache::prune() {
        // Remove oldest entries
        if (cache.size() < maxSize) return;

        std::vector<std::pair<std::string, std::chrono::steady_clock::time_point>> entries;
        for (const auto& [id, entry] : cache) {
            entries.emplace_back(id, entry.accessTime);
        }

        std::sort(entries.begin(), entries.end(),
            [](const auto& a, const auto& b) {
                return a.second < b.second;
            });

        size_t toRemove = cache.size() - maxSize + 10; // Keep some buffer
        for (size_t i = 0; i < toRemove && i < entries.size(); i++) {
            cache.erase(entries[i].first);
        }
    }

} // namespace powercoin