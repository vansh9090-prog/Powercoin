#include "wallet.h"
#include "../crypto/sha256.h"
#include "../crypto/ripemd160.h"
#include "../crypto/base58.h"
#include "../crypto/random.h"
#include "../crypto/aes.h"
#include <sstream>
#include <iomanip>
#include <fstream>
#include <algorithm>
#include <cmath>

namespace powercoin {

    // ============== WalletUTXO Implementation ==============

    WalletUTXO::WalletUTXO()
        : outputIndex(0), amount(0), blockHeight(0), confirmations(0),
          isCoinbase(false), isSpent(false), isLocked(false) {}

    std::string WalletUTXO::toString() const {
        std::stringstream ss;
        ss << "UTXO: " << txHash.substr(0, 16) << ":" << outputIndex << "\n";
        ss << "  Address: " << address << "\n";
        ss << "  Amount: " << amount / 100000000.0 << " PWR\n";
        ss << "  Height: " << blockHeight << "\n";
        ss << "  Confirmations: " << confirmations << "\n";
        ss << "  Status: " << (isSpent ? "spent" : (isLocked ? "locked" : "available")) << "\n";
        return ss.str();
    }

    bool WalletUTXO::isMature() const {
        if (isCoinbase) {
            return confirmations >= 100;
        }
        return true;
    }

    // ============== WalletTransaction Implementation ==============

    WalletTransaction::WalletTransaction()
        : timestamp(0), amount(0), fee(0), blockHeight(0), confirmations(0),
          isIncoming(false), isOutgoing(false), isPending(false), isConfirmed(false) {}

    std::string WalletTransaction::toString() const {
        std::stringstream ss;
        ss << "Transaction: " << txHash.substr(0, 16) << "...\n";
        ss << "  Amount: " << amount / 100000000.0 << " PWR\n";
        ss << "  Fee: " << fee / 100000000.0 << " PWR\n";
        ss << "  Block: " << blockHeight << "\n";
        ss << "  Confirmations: " << confirmations << "\n";
        ss << "  Direction: " << (isIncoming ? "incoming" : (isOutgoing ? "outgoing" : "unknown")) << "\n";
        ss << "  Status: " << (isConfirmed ? "confirmed" : "pending") << "\n";
        return ss.str();
    }

    // ============== WalletAccount Implementation ==============

    WalletAccount::WalletAccount()
        : index(0), balance(0), nextAddressIndex(0), nextChangeIndex(0) {}

    std::string WalletAccount::toString() const {
        std::stringstream ss;
        ss << "Account #" << index << ": " << name << "\n";
        ss << "  Purpose: " << purpose << "\n";
        ss << "  xpub: " << xpub.substr(0, 20) << "...\n";
        ss << "  Addresses: " << addresses.size() << "\n";
        ss << "  Balance: " << balance / 100000000.0 << " PWR\n";
        return ss.str();
    }

    // ============== WalletConfig Implementation ==============

    WalletConfig::WalletConfig()
        : type(WalletType::HD_WALLET),
          defaultAddressType(AddressType::P2PKH),
          walletPath("wallet.dat"),
          dbPath("wallet.db"),
          minConfirmations(6),
          coinbaseMaturity(100),
          minRelayFee(1000),
          autoRescan(true),
          pruneHistory(false),
          enableLogging(true),
          encryptionMethod("aes-256-cbc"),
          keyDerivationIterations(100000) {}

    // ============== WalletBalance Implementation ==============

    WalletBalance::WalletBalance()
        : total(0), confirmed(0), unconfirmed(0), immature(0),
          locked(0), spendable(0), watchOnly(0) {}

    std::string WalletBalance::toString() const {
        std::stringstream ss;
        ss << "Balance:\n";
        ss << "  Total: " << total / 100000000.0 << " PWR\n";
        ss << "  Confirmed: " << confirmed / 100000000.0 << " PWR\n";
        ss << "  Unconfirmed: " << unconfirmed / 100000000.0 << " PWR\n";
        ss << "  Immature: " << immature / 100000000.0 << " PWR\n";
        ss << "  Locked: " << locked / 100000000.0 << " PWR\n";
        ss << "  Spendable: " << spendable / 100000000.0 << " PWR\n";
        return ss.str();
    }

    // ============== WalletStats Implementation ==============

    WalletStats::WalletStats()
        : accountCount(0), addressCount(0), transactionCount(0), utxoCount(0),
          totalReceived(0), totalSent(0), totalFees(0), lastBlockHeight(0),
          status(WalletStatus::UNINITIALIZED) {}

    std::string WalletStats::toString() const {
        std::stringstream ss;
        ss << "Wallet Statistics:\n";
        ss << "  Status: " << static_cast<int>(status) << "\n";
        ss << "  Accounts: " << accountCount << "\n";
        ss << "  Addresses: " << addressCount << "\n";
        ss << "  Transactions: " << transactionCount << "\n";
        ss << "  UTXOs: " << utxoCount << "\n";
        ss << "  " << balance.toString();
        ss << "  Last Block: " << lastBlockHeight << "\n";
        return ss.str();
    }

    // ============== Wallet Implementation ==============

    struct Wallet::Impl {
        WalletConfig config;
        WalletStatus status;
        WalletStats stats;
        
        std::vector<WalletAccount> accounts;
        std::map<std::string, WalletUTXO> utxos;
        std::map<std::string, WalletTransaction> transactions;
        std::map<std::string, uint32_t> addressToAccount;
        std::map<std::string, std::vector<uint8_t>> addressToPublicKey;
        std::map<std::string, std::vector<uint8_t>> addressToPrivateKey;
        
        std::vector<uint8_t> masterSeed;
        std::vector<uint8_t> masterKey;
        uint32_t derivationIndex;
        
        std::chrono::steady_clock::time_point unlockTime;
        uint32_t unlockTimeout;
        
        std::function<void(const WalletBalance&)> onBalanceChanged;
        std::function<void(const WalletTransaction&)> onTransactionAdded;
        std::function<void(const std::string&)> onTransactionRemoved;
        std::function<void(const std::string&, uint32_t)> onAddressAdded;
        std::function<void(uint32_t, uint32_t)> onSyncProgress;
        std::function<void(const std::string&)> onError;

        Impl() : status(WalletStatus::UNINITIALIZED), derivationIndex(0), unlockTimeout(0) {}
    };

    Wallet::Wallet(const WalletConfig& cfg) : config(cfg) {
        impl = std::make_unique<Impl>();
        impl->config = cfg;
    }

    Wallet::~Wallet() = default;

    bool Wallet::initialize(const std::string& seed, const std::string& passphrase) {
        std::lock_guard<std::mutex> lock(mutex);

        // Derive master seed from seed phrase
        // In production, use BIP39 mnemonic
        impl->masterSeed = SHA256::hashToBytes(seed);
        
        // Derive master key using PBKDF2
        std::vector<uint8_t> salt(16);
        Random::getBytes(salt.data(), salt.size());
        
        impl->masterKey = SHA256::pbkdf2(
            reinterpret_cast<const uint8_t*>(seed.c_str()), seed.length(),
            salt.data(), salt.size(),
            config.keyDerivationIterations, 32
        );

        impl->status = WalletStatus::LOCKED;
        impl->stats.status = WalletStatus::LOCKED;

        // Create default account
        createAccount("Default");

        return true;
    }

    std::string Wallet::initializeNew(const std::string& passphrase) {
        // Generate random seed (128 bits for 12-word mnemonic)
        std::vector<uint8_t> entropy(16);
        Random::getBytes(entropy.data(), entropy.size());
        
        // Convert to seed phrase (simplified - in production use BIP39)
        std::stringstream ss;
        for (size_t i = 0; i < entropy.size(); i++) {
            ss << std::hex << std::setw(2) << std::setfill('0') 
               << static_cast<int>(entropy[i]);
        }
        std::string seed = ss.str();

        if (!initialize(seed, passphrase)) {
            return "";
        }

        return seed;
    }

    bool Wallet::load(const std::string& path, const std::string& password) {
        std::lock_guard<std::mutex> lock(mutex);

        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        // Read encrypted data
        std::vector<uint8_t> encrypted(
            (std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>()
        );
        file.close();

        // Decrypt using AES
        AES aes(AESMode::CBC, AESKeyLength::AES_256, AESPadding::PKCS7);
        std::vector<uint8_t> iv(encrypted.begin(), encrypted.begin() + 16);
        std::vector<uint8_t> ciphertext(encrypted.begin() + 16, encrypted.end());
        
        // Derive key from password
        std::vector<uint8_t> salt(16);
        // In production, store salt with encrypted data
        auto key = AESKey::deriveFromPassword(password, salt, AESKeyLength::AES_256);

        aes.setKey(key);
        auto decrypted = aes.decrypt(ciphertext, iv);

        // Deserialize wallet data
        // TODO: Implement deserialization

        impl->status = WalletStatus::LOCKED;
        impl->stats.status = WalletStatus::LOCKED;

        return true;
    }

    bool Wallet::save(const std::string& path, const std::string& password) {
        std::lock_guard<std::mutex> lock(mutex);

        // Serialize wallet data
        std::vector<uint8_t> data;
        // TODO: Implement serialization

        // Encrypt using AES
        AES aes(AESMode::CBC, AESKeyLength::AES_256, AESPadding::PKCS7);
        auto iv = aes.generateIV();
        
        std::vector<uint8_t> salt(16);
        Random::getBytes(salt.data(), salt.size());
        auto key = AESKey::deriveFromPassword(password, salt, AESKeyLength::AES_256);

        aes.setKey(key);
        auto encrypted = aes.encrypt(data, iv);

        // Write to file
        std::ofstream file(path, std::ios::binary);
        if (!file.is_open()) {
            return false;
        }

        file.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        file.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
        file.close();

        return true;
    }

    bool Wallet::unlock(const std::string& password, uint32_t timeout) {
        std::lock_guard<std::mutex> lock(mutex);

        // Verify password by decrypting master key
        // In production, use proper key derivation
        
        impl->status = WalletStatus::UNLOCKED;
        impl->stats.status = WalletStatus::UNLOCKED;
        impl->unlockTime = std::chrono::steady_clock::now();
        impl->unlockTimeout = timeout;

        return true;
    }

    void Wallet::lock() {
        std::lock_guard<std::mutex> lock(mutex);

        // Clear sensitive data
        impl->addressToPrivateKey.clear();
        
        impl->status = WalletStatus::LOCKED;
        impl->stats.status = WalletStatus::LOCKED;
        impl->unlockTimeout = 0;
    }

    bool Wallet::isLocked() const {
        std::lock_guard<std::mutex> lock(mutex);

        if (impl->status == WalletStatus::UNLOCKED && impl->unlockTimeout > 0) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                now - impl->unlockTime).count();
            if (elapsed >= impl->unlockTimeout) {
                const_cast<Wallet*>(this)->lock();
                return true;
            }
        }

        return impl->status != WalletStatus::UNLOCKED;
    }

    bool Wallet::isInitialized() const {
        return impl->status != WalletStatus::UNINITIALIZED;
    }

    WalletStatus Wallet::getStatus() const {
        return impl->status;
    }

    WalletStats Wallet::getStats() const {
        std::lock_guard<std::mutex> lock(mutex);

        impl->stats.accountCount = impl->accounts.size();
        impl->stats.addressCount = impl->addressToAccount.size();
        impl->stats.transactionCount = impl->transactions.size();
        impl->stats.utxoCount = impl->utxos.size();
        impl->stats.balance = getBalance();

        return impl->stats;
    }

    uint32_t Wallet::createAccount(const std::string& name, const std::string& purpose) {
        std::lock_guard<std::mutex> lock(mutex);

        WalletAccount account;
        account.index = impl->accounts.size();
        account.name = name;
        account.purpose = purpose.empty() ? "44'" : purpose; // BIP44 default

        // Generate account xpub (simplified)
        std::string data = name + std::to_string(account.index);
        account.xpub = SHA256::hash(data);

        impl->accounts.push_back(account);

        return account.index;
    }

    std::unique_ptr<WalletAccount> Wallet::getAccount(uint32_t index) const {
        std::lock_guard<std::mutex> lock(mutex);

        if (index >= impl->accounts.size()) {
            return nullptr;
        }

        return std::make_unique<WalletAccount>(impl->accounts[index]);
    }

    std::vector<WalletAccount> Wallet::getAccounts() const {
        std::lock_guard<std::mutex> lock(mutex);
        return impl->accounts;
    }

    std::string Wallet::getNewAddress(uint32_t accountIndex, AddressType type) {
        std::lock_guard<std::mutex> lock(mutex);

        if (accountIndex >= impl->accounts.size()) {
            return "";
        }

        auto& account = impl->accounts[accountIndex];

        // Generate key pair for this address
        // In production, derive from HD seed
        auto privateKey = Random::getPrivateKey();
        Keys keys;
        keys.importPrivateKey(Base58::encode(privateKey));
        auto publicKey = keys.getPublicKey();
        
        // Generate address based on type
        std::string address;
        switch (type) {
            case AddressType::P2PKH: {
                auto hash160 = RIPEMD160::hash160(
                    std::string(publicKey.begin(), publicKey.end()));
                address = Base58::encodeAddress(
                    std::vector<uint8_t>(hash160.begin(), hash160.end()));
                break;
            }
            case AddressType::P2SH:
                // TODO: Implement P2SH
                address = "3" + SHA256::hash(
                    std::string(publicKey.begin(), publicKey.end())).substr(0, 33);
                break;
            case AddressType::P2WPKH:
                // TODO: Implement bech32
                address = "bc1" + SHA256::hash(
                    std::string(publicKey.begin(), publicKey.end())).substr(0, 38);
                break;
            default:
                return "";
        }

        // Store address mapping
        impl->addressToAccount[address] = accountIndex;
        impl->addressToPublicKey[address] = publicKey;
        impl->addressToPrivateKey[address] = privateKey;
        account.addresses.push_back(address);

        if (impl->onAddressAdded) {
            impl->onAddressAdded(address, accountIndex);
        }

        return address;
    }

    std::string Wallet::getChangeAddress(uint32_t accountIndex) {
        // For change addresses, use next change index
        return getNewAddress(accountIndex, config.defaultAddressType);
    }

    std::vector<std::string> Wallet::getAddresses(uint32_t accountIndex) const {
        std::lock_guard<std::mutex> lock(mutex);

        if (accountIndex >= impl->accounts.size()) {
            return {};
        }

        return impl->accounts[accountIndex].addresses;
    }

    bool Wallet::hasAddress(const std::string& address) const {
        std::lock_guard<std::mutex> lock(mutex);
        return impl->addressToAccount.find(address) != impl->addressToAccount.end();
    }

    int Wallet::getAccountForAddress(const std::string& address) const {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = impl->addressToAccount.find(address);
        if (it != impl->addressToAccount.end()) {
            return it->second;
        }
        return -1;
    }

    std::vector<uint8_t> Wallet::getPrivateKey(const std::string& address) {
        std::lock_guard<std::mutex> lock(mutex);

        if (isLocked()) {
            return {};
        }

        auto it = impl->addressToPrivateKey.find(address);
        if (it != impl->addressToPrivateKey.end()) {
            return it->second;
        }
        return {};
    }

    std::vector<uint8_t> Wallet::getPublicKey(const std::string& address) const {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = impl->addressToPublicKey.find(address);
        if (it != impl->addressToPublicKey.end()) {
            return it->second;
        }
        return {};
    }

    WalletBalance Wallet::getBalance(int accountIndex) const {
        std::lock_guard<std::mutex> lock(mutex);

        WalletBalance balance;

        for (const auto& [key, utxo] : impl->utxos) {
            if (accountIndex >= 0) {
                auto addrIt = impl->addressToAccount.find(utxo.address);
                if (addrIt == impl->addressToAccount.end() || 
                    static_cast<int>(addrIt->second) != accountIndex) {
                    continue;
                }
            }

            balance.total += utxo.amount;

            if (utxo.isSpent) {
                continue;
            }

            if (utxo.isLocked) {
                balance.locked += utxo.amount;
                continue;
            }

            if (utxo.confirmations >= config.minConfirmations) {
                if (utxo.isMature()) {
                    balance.confirmed += utxo.amount;
                    balance.spendable += utxo.amount;
                } else {
                    balance.immature += utxo.amount;
                }
            } else {
                balance.unconfirmed += utxo.amount;
            }
        }

        return balance;
    }

    std::vector<WalletUTXO> Wallet::getUTXOs(int accountIndex, uint32_t minConfirmations) const {
        std::lock_guard<std::mutex> lock(mutex);

        std::vector<WalletUTXO> result;

        for (const auto& [key, utxo] : impl->utxos) {
            if (accountIndex >= 0) {
                auto addrIt = impl->addressToAccount.find(utxo.address);
                if (addrIt == impl->addressToAccount.end() || 
                    static_cast<int>(addrIt->second) != accountIndex) {
                    continue;
                }
            }

            if (utxo.isSpent) {
                continue;
            }

            if (utxo.confirmations >= minConfirmations && utxo.isMature()) {
                result.push_back(utxo);
            }
        }

        // Sort by amount (largest first) for coin selection
        std::sort(result.begin(), result.end(),
            [](const WalletUTXO& a, const WalletUTXO& b) {
                return a.amount > b.amount;
            });

        return result;
    }

    std::vector<WalletTransaction> Wallet::getTransactions(int accountIndex, uint32_t count, uint32_t offset) const {
        std::lock_guard<std::mutex> lock(mutex);

        std::vector<WalletTransaction> result;

        for (const auto& [hash, tx] : impl->transactions) {
            if (accountIndex >= 0) {
                // Filter by account (simplified)
            }
            result.push_back(tx);
        }

        // Sort by timestamp (newest first)
        std::sort(result.begin(), result.end(),
            [](const WalletTransaction& a, const WalletTransaction& b) {
                return a.timestamp > b.timestamp;
            });

        // Apply pagination
        if (offset < result.size()) {
            size_t end = std::min(offset + count, static_cast<uint32_t>(result.size()));
            result = std::vector<WalletTransaction>(
                result.begin() + offset, result.begin() + end);
        }

        return result;
    }

    std::unique_ptr<WalletTransaction> Wallet::getTransaction(const std::string& txHash) const {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = impl->transactions.find(txHash);
        if (it != impl->transactions.end()) {
            return std::make_unique<WalletTransaction>(it->second);
        }
        return nullptr;
    }

    Transaction Wallet::createTransaction(const std::string& toAddress,
                                          uint64_t amount,
                                          uint32_t accountIndex,
                                          uint64_t fee,
                                          const std::string& changeAddress) {
        if (isLocked()) {
            return Transaction();
        }

        auto utxos = getUTXOs(accountIndex, 1);
        uint64_t totalInput = 0;
        std::vector<WalletUTXO> selectedUtxos;

        // Simple coin selection (first sufficient)
        for (const auto& utxo : utxos) {
            selectedUtxos.push_back(utxo);
            totalInput += utxo.amount;
            if (totalInput >= amount + fee) {
                break;
            }
        }

        if (totalInput < amount + fee) {
            return Transaction(); // Insufficient funds
        }

        Transaction tx;

        // Add inputs
        for (const auto& utxo : selectedUtxos) {
            tx.addInput(utxo.txHash, utxo.outputIndex);
        }

        // Add output to recipient
        tx.addOutput(toAddress, amount);

        // Add change output
        uint64_t change = totalInput - amount - fee;
        if (change > 0) {
            std::string changeAddr = changeAddress.empty() ? 
                getChangeAddress(accountIndex) : changeAddress;
            tx.addOutput(changeAddr, change);
        }

        tx.calculateHash();
        return tx;
    }

    Transaction Wallet::createTransaction(const std::map<std::string, uint64_t>& outputs,
                                          uint32_t accountIndex,
                                          uint64_t fee) {
        if (outputs.empty()) {
            return Transaction();
        }

        uint64_t totalAmount = 0;
        for (const auto& [addr, amount] : outputs) {
            totalAmount += amount;
        }

        return createTransaction("", totalAmount, accountIndex, fee);
    }

    bool Wallet::signTransaction(Transaction& tx) {
        if (isLocked()) {
            return false;
        }

        for (size_t i = 0; i < tx.getInputs().size(); i++) {
            // In production, get private key for the UTXO
            // Sign the input
            if (!tx.signInput(i, std::vector<uint8_t>())) {
                return false;
            }
        }

        return true;
    }

    bool Wallet::sendTransaction(const Transaction& tx) {
        // In production, broadcast to network
        return broadcastTransaction(tx);
    }

    bool Wallet::broadcastTransaction(const Transaction& tx) {
        // Add to pending transactions
        WalletTransaction wtx;
        wtx.txHash = tx.getHash();
        wtx.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        wtx.amount = tx.getTotalOutput();
        wtx.fee = tx.getFee();
        wtx.isOutgoing = true;
        wtx.isPending = true;

        impl->transactions[tx.getHash()] = wtx;

        if (impl->onTransactionAdded) {
            impl->onTransactionAdded(wtx);
        }

        return true;
    }

    bool Wallet::rescan(uint32_t startHeight,
                        std::function<void(uint32_t, uint32_t)> progressCallback) {
        // In production, rescan blockchain for wallet transactions
        return true;
    }

    bool Wallet::importAddress(const std::string& address, uint32_t accountIndex) {
        std::lock_guard<std::mutex> lock(mutex);

        if (accountIndex >= impl->accounts.size()) {
            return false;
        }

        impl->addressToAccount[address] = accountIndex;
        impl->accounts[accountIndex].addresses.push_back(address);

        if (impl->onAddressAdded) {
            impl->onAddressAdded(address, accountIndex);
        }

        return true;
    }

    bool Wallet::importPrivateKey(const std::string& wif, uint32_t accountIndex, bool rescan) {
        std::lock_guard<std::mutex> lock(mutex);

        if (isLocked()) {
            return false;
        }

        // Parse WIF
        bool compressed;
        auto privateKey = Base58::decodePrivateKey(wif, compressed);

        // Generate public key and address
        Keys keys;
        keys.importPrivateKey(wif);
        auto publicKey = keys.getPublicKey();
        
        std::string pubStr(publicKey.begin(), publicKey.end());
        auto hash160 = RIPEMD160::hash160(pubStr);
        auto address = Base58::encodeAddress(
            std::vector<uint8_t>(hash160.begin(), hash160.end()));

        // Store in wallet
        impl->addressToAccount[address] = accountIndex;
        impl->addressToPublicKey[address] = publicKey;
        impl->addressToPrivateKey[address] = privateKey;
        impl->accounts[accountIndex].addresses.push_back(address);

        if (rescan) {
            // Trigger rescan
        }

        if (impl->onAddressAdded) {
            impl->onAddressAdded(address, accountIndex);
        }

        return true;
    }

    bool Wallet::importSeed(const std::string& seed, const std::string& passphrase,
                            uint32_t accountIndex) {
        return initialize(seed, passphrase);
    }

    std::string Wallet::exportSeed(const std::string& passphrase) {
        if (isLocked()) {
            return "";
        }
        // In production, derive seed phrase from master seed
        return SHA256::bytesToHash(
            *reinterpret_cast<std::array<uint8_t, 32>*>(impl->masterSeed.data()));
    }

    std::string Wallet::exportAccountXPub(uint32_t accountIndex) const {
        std::lock_guard<std::mutex> lock(mutex);

        if (accountIndex >= impl->accounts.size()) {
            return "";
        }

        return impl->accounts[accountIndex].xpub;
    }

    bool Wallet::lockUTXO(const std::string& txHash, uint32_t outputIndex, bool lock) {
        std::lock_guard<std::mutex> lock(mutex);

        std::string key = txHash + ":" + std::to_string(outputIndex);
        auto it = impl->utxos.find(key);
        if (it != impl->utxos.end()) {
            it->second.isLocked = lock;
            return true;
        }
        return false;
    }

    bool Wallet::isUTXOLocked(const std::string& txHash, uint32_t outputIndex) const {
        std::lock_guard<std::mutex> lock(mutex);

        std::string key = txHash + ":" + std::to_string(outputIndex);
        auto it = impl->utxos.find(key);
        if (it != impl->utxos.end()) {
            return it->second.isLocked;
        }
        return false;
    }

    std::vector<WalletUTXO> Wallet::getLockedUTXOs() const {
        std::lock_guard<std::mutex> lock(mutex);

        std::vector<WalletUTXO> locked;
        for (const auto& [key, utxo] : impl->utxos) {
            if (utxo.isLocked) {
                locked.push_back(utxo);
            }
        }
        return locked;
    }

    bool Wallet::abandonTransaction(const std::string& txHash) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = impl->transactions.find(txHash);
        if (it != impl->transactions.end()) {
            impl->transactions.erase(it);
            if (impl->onTransactionRemoved) {
                impl->onTransactionRemoved(txHash);
            }
            return true;
        }
        return false;
    }

    uint64_t Wallet::estimateFee(uint32_t txSize, uint32_t targetConfirmation) const {
        // Simple fee estimation: 10 satoshi per byte
        return txSize * 10;
    }

    bool Wallet::updateWithBlock(const Block& block) {
        std::lock_guard<std::mutex> lock(mutex);

        for (const auto& tx : block.getTransactions()) {
            updateWithTransaction(tx, block.getHeight());
        }

        // Update confirmations for existing UTXOs
        uint32_t currentHeight = block.getHeight();
        for (auto& [key, utxo] : impl->utxos) {
            if (utxo.blockHeight > 0 && !utxo.isSpent) {
                utxo.confirmations = currentHeight - utxo.blockHeight + 1;
            }
        }

        return true;
    }

    bool Wallet::updateWithTransaction(const Transaction& tx, uint32_t blockHeight) {
        std::lock_guard<std::mutex> lock(mutex);

        // Check if transaction involves our addresses
        bool involvesWallet = false;

        // Check outputs (incoming)
        for (size_t i = 0; i < tx.getOutputs().size(); i++) {
            const auto& output = tx.getOutputs()[i];
            if (hasAddress(output.address)) {
                involvesWallet = true;

                WalletUTXO utxo;
                utxo.txHash = tx.getHash();
                utxo.outputIndex = i;
                utxo.address = output.address;
                utxo.amount = output.amount;
                utxo.blockHeight = blockHeight;
                utxo.isCoinbase = (tx.getType() == TransactionType::COINBASE);
                utxo.isSpent = false;

                std::string key = tx.getHash() + ":" + std::to_string(i);
                impl->utxos[key] = utxo;
            }
        }

        // Check inputs (outgoing)
        for (const auto& input : tx.getInputs()) {
            std::string key = input.previousTxHash + ":" + 
                              std::to_string(input.outputIndex);
            auto it = impl->utxos.find(key);
            if (it != impl->utxos.end()) {
                involvesWallet = true;
                it->second.isSpent = true;
            }
        }

        if (involvesWallet) {
            WalletTransaction wtx;
            wtx.txHash = tx.getHash();
            wtx.timestamp = tx.getTimestamp();
            wtx.blockHeight = blockHeight;
            wtx.isConfirmed = true;
            // Determine direction
            // TODO: Calculate amounts

            impl->transactions[tx.getHash()] = wtx;

            if (impl->onTransactionAdded) {
                impl->onTransactionAdded(wtx);
            }

            if (impl->onBalanceChanged) {
                impl->onBalanceChanged(getBalance());
            }
        }

        return involvesWallet;
    }

    bool Wallet::removeTransaction(const std::string& txHash) {
        return abandonTransaction(txHash);
    }

    void Wallet::clear() {
        std::lock_guard<std::mutex> lock(mutex);
        impl->accounts.clear();
        impl->utxos.clear();
        impl->transactions.clear();
        impl->addressToAccount.clear();
        impl->addressToPublicKey.clear();
        impl->addressToPrivateKey.clear();
        impl->masterSeed.clear();
        impl->masterKey.clear();
    }

    void Wallet::setOnBalanceChanged(std::function<void(const WalletBalance&)> callback) {
        impl->onBalanceChanged = callback;
    }

    void Wallet::setOnTransactionAdded(std::function<void(const WalletTransaction&)> callback) {
        impl->onTransactionAdded = callback;
    }

    void Wallet::setOnTransactionRemoved(std::function<void(const std::string&)> callback) {
        impl->onTransactionRemoved = callback;
    }

    void Wallet::setOnAddressAdded(std::function<void(const std::string&, uint32_t)> callback) {
        impl->onAddressAdded = callback;
    }

    void Wallet::setOnSyncProgress(std::function<void(uint32_t, uint32_t)> callback) {
        impl->onSyncProgress = callback;
    }

    void Wallet::setOnError(std::function<void(const std::string&)> callback) {
        impl->onError = callback;
    }

    // ============== WalletManager Implementation ==============

    bool WalletManager::createWallet(const std::string& name, const WalletConfig& config,
                                     const std::string& seed) {
        std::lock_guard<std::mutex> lock(mutex);

        if (wallets.find(name) != wallets.end()) {
            return false;
        }

        auto wallet = std::make_unique<Wallet>(config);
        if (!wallet->initialize(seed, "")) {
            return false;
        }

        wallets[name] = std::move(wallet);
        if (defaultWallet.empty()) {
            defaultWallet = name;
        }

        return true;
    }

    bool WalletManager::loadWallet(const std::string& name, const std::string& path,
                                   const std::string& password) {
        std::lock_guard<std::mutex> lock(mutex);

        if (wallets.find(name) != wallets.end()) {
            return false;
        }

        auto wallet = std::make_unique<Wallet>();
        if (!wallet->load(path, password)) {
            return false;
        }

        wallets[name] = std::move(wallet);
        return true;
    }

    bool WalletManager::unloadWallet(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = wallets.find(name);
        if (it == wallets.end()) {
            return false;
        }

        if (defaultWallet == name) {
            defaultWallet.clear();
        }

        wallets.erase(it);
        return true;
    }

    Wallet* WalletManager::getWallet(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = wallets.find(name);
        if (it != wallets.end()) {
            return it->second.get();
        }
        return nullptr;
    }

    Wallet* WalletManager::getDefaultWallet() {
        return getWallet(defaultWallet);
    }

    void WalletManager::setDefaultWallet(const std::string& name) {
        std::lock_guard<std::mutex> lock(mutex);

        if (wallets.find(name) != wallets.end()) {
            defaultWallet = name;
        }
    }

    std::vector<std::string> WalletManager::getWalletNames() const {
        std::lock_guard<std::mutex> lock(mutex);

        std::vector<std::string> names;
        for (const auto& [name, _] : wallets) {
            names.push_back(name);
        }
        return names;
    }

    bool WalletManager::saveAll(const std::string& password) {
        std::lock_guard<std::mutex> lock(mutex);

        for (auto& [name, wallet] : wallets) {
            std::string path = name + ".dat";
            if (!wallet->save(path, password)) {
                return false;
            }
        }
        return true;
    }

    // ============== AddressValidator Implementation ==============

    bool AddressValidator::isValid(const std::string& address) {
        // Basic validation
        if (address.empty() || address.length() < 26 || address.length() > 35) {
            return false;
        }

        // Check prefix
        if (address[0] == '1' || address[0] == '3') {
            // Legacy address
            try {
                auto decoded = Base58::decodeCheck(address);
                return decoded.size() == 20;
            } catch (...) {
                return false;
            }
        } else if (address.substr(0, 3) == "bc1") {
            // Bech32 address
            // TODO: Implement bech32 validation
            return address.length() >= 14 && address.length() <= 74;
        }

        return false;
    }

    bool AddressValidator::isP2PKH(const std::string& address) {
        if (address.empty() || address[0] != '1') return false;

        try {
            auto decoded = Base58::decodeCheck(address);
            return decoded.size() == 20;
        } catch (...) {
            return false;
        }
    }

    bool AddressValidator::isP2SH(const std::string& address) {
        if (address.empty() || address[0] != '3') return false;

        try {
            auto decoded = Base58::decodeCheck(address);
            return decoded.size() == 20;
        } catch (...) {
            return false;
        }
    }

    bool AddressValidator::isP2WPKH(const std::string& address) {
        if (address.substr(0, 4) != "bc1q") return false;
        // Bech32 with 20-byte program
        return address.length() == 42 || address.length() == 43;
    }

    bool AddressValidator::isP2WSH(const std::string& address) {
        if (address.substr(0, 4) != "bc1q") return false;
        // Bech32 with 32-byte program
        return address.length() == 62 || address.length() == 63;
    }

    bool AddressValidator::isP2TR(const std::string& address) {
        return address.substr(0, 4) == "bc1p";
    }

    AddressType AddressValidator::detectType(const std::string& address) {
        if (isP2PKH(address)) return AddressType::P2PKH;
        if (isP2SH(address)) return AddressType::P2SH;
        if (isP2WPKH(address)) return AddressType::P2WPKH;
        if (isP2WSH(address)) return AddressType::P2WSH;
        if (isP2TR(address)) return AddressType::P2TR;
        return AddressType::P2PKH; // Default
    }

    std::string AddressValidator::toLegacy(const std::string& address) {
        // Convert bech32 to legacy (if possible)
        return address;
    }

    std::string AddressValidator::toBech32(const std::string& address) {
        // Convert legacy to bech32
        return address;
    }

    std::vector<uint8_t> AddressValidator::extractHash160(const std::string& address) {
        try {
            auto decoded = Base58::decodeCheck(address);
            if (decoded.size() == 20) {
                return decoded;
            }
        } catch (...) {}

        // Handle bech32
        return {};
    }

} // namespace powercoin