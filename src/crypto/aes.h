#ifndef POWERCOIN_AES_H
#define POWERCOIN_AES_H

#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <memory>

namespace powercoin {

    /**
     * AES key sizes in bytes
     */
    constexpr size_t AES_KEY_SIZE_128 = 16;
    constexpr size_t AES_KEY_SIZE_192 = 24;
    constexpr size_t AES_KEY_SIZE_256 = 32;

    /**
     * AES block size in bytes
     */
    constexpr size_t AES_BLOCK_SIZE = 16;

    /**
     * AES mode of operation
     */
    enum class AESMode {
        ECB,        // Electronic Codebook (not recommended for most uses)
        CBC,        // Cipher Block Chaining
        CFB,        // Cipher Feedback
        OFB,        // Output Feedback
        CTR,        // Counter
        GCM,        // Galois/Counter Mode (authenticated encryption)
        CCM         // Counter with CBC-MAC (authenticated encryption)
    };

    /**
     * AES key length
     */
    enum class AESKeyLength {
        AES_128,
        AES_192,
        AES_256
    };

    /**
     * AES padding scheme
     */
    enum class AESPadding {
        NONE,           // No padding (data must be multiple of block size)
        PKCS7,          // PKCS#7 padding (default)
        ISO7816,        // ISO/IEC 7816-4 padding
        ANSI_X923,      // ANSI X.923 padding
        ZERO            // Zero padding (not recommended)
    };

    /**
     * AES encryption/decryption class
     * Provides AES encryption with multiple modes and padding schemes
     */
    class AES {
    private:
        struct Context;
        std::unique_ptr<Context> ctx;

        // Internal helper methods
        void checkKeySize(const std::vector<uint8_t>& key) const;
        void checkIV(const std::vector<uint8_t>& iv) const;
        std::vector<uint8_t> pad(const std::vector<uint8_t>& data, AESPadding padding) const;
        std::vector<uint8_t> unpad(const std::vector<uint8_t>& data, AESPadding padding) const;

    public:
        /**
         * Constructor
         * @param mode AES mode of operation
         * @param keyLength AES key length
         * @param padding Padding scheme
         */
        explicit AES(AESMode mode = AESMode::CBC, 
                     AESKeyLength keyLength = AESKeyLength::AES_256,
                     AESPadding padding = AESPadding::PKCS7);

        /**
         * Destructor
         */
        ~AES();

        // Disable copy
        AES(const AES&) = delete;
        AES& operator=(const AES&) = delete;

        /**
         * Set encryption key
         * @param key Key bytes (must match key length)
         * @return true if successful
         */
        bool setKey(const std::vector<uint8_t>& key);

        /**
         * Set encryption key from string
         * @param key Key string (will be hashed to correct length)
         * @return true if successful
         */
        bool setKeyFromString(const std::string& key);

        /**
         * Generate random key
         * @return Random key of appropriate length
         */
        std::vector<uint8_t> generateKey() const;

        /**
         * Generate random IV
         * @return 16-byte random IV
         */
        std::vector<uint8_t> generateIV() const;

        /**
         * Encrypt data
         * @param plaintext Data to encrypt
         * @param iv Initialization vector (required for CBC, CFB, OFB, CTR, GCM, CCM)
         * @return Encrypted ciphertext
         */
        std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                      const std::vector<uint8_t>& iv = {}) const;

        /**
         * Encrypt string
         * @param plaintext String to encrypt
         * @param iv Initialization vector
         * @return Encrypted ciphertext
         */
        std::vector<uint8_t> encrypt(const std::string& plaintext,
                                      const std::vector<uint8_t>& iv = {}) const;

        /**
         * Decrypt data
         * @param ciphertext Data to decrypt
         * @param iv Initialization vector (required for CBC, CFB, OFB, CTR, GCM, CCM)
         * @return Decrypted plaintext
         */
        std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                      const std::vector<uint8_t>& iv = {}) const;

        /**
         * Decrypt to string
         * @param ciphertext Data to decrypt
         * @param iv Initialization vector
         * @return Decrypted string
         */
        std::string decryptToString(const std::vector<uint8_t>& ciphertext,
                                     const std::vector<uint8_t>& iv = {}) const;

        /**
         * Authenticated encryption (GCM mode)
         * @param plaintext Data to encrypt
         * @param iv 12-byte initialization vector
         * @param aad Additional authenticated data
         * @param tag Output authentication tag (16 bytes)
         * @return Encrypted ciphertext
         */
        std::vector<uint8_t> encryptGCM(const std::vector<uint8_t>& plaintext,
                                         const std::vector<uint8_t>& iv,
                                         const std::vector<uint8_t>& aad,
                                         std::vector<uint8_t>& tag) const;

        /**
         * Authenticated decryption (GCM mode)
         * @param ciphertext Data to decrypt
         * @param iv 12-byte initialization vector
         * @param aad Additional authenticated data
         * @param tag Authentication tag (16 bytes)
         * @return Decrypted plaintext
         */
        std::vector<uint8_t> decryptGCM(const std::vector<uint8_t>& ciphertext,
                                         const std::vector<uint8_t>& iv,
                                         const std::vector<uint8_t>& aad,
                                         const std::vector<uint8_t>& tag) const;

        /**
         * Authenticated encryption (CCM mode)
         * @param plaintext Data to encrypt
         * @param iv 12-byte initialization vector
         * @param aad Additional authenticated data
         * @param tag Output authentication tag (16 bytes)
         * @return Encrypted ciphertext
         */
        std::vector<uint8_t> encryptCCM(const std::vector<uint8_t>& plaintext,
                                         const std::vector<uint8_t>& iv,
                                         const std::vector<uint8_t>& aad,
                                         std::vector<uint8_t>& tag) const;

        /**
         * Authenticated decryption (CCM mode)
         * @param ciphertext Data to decrypt
         * @param iv 12-byte initialization vector
         * @param aad Additional authenticated data
         * @param tag Authentication tag (16 bytes)
         * @return Decrypted plaintext
         */
        std::vector<uint8_t> decryptCCM(const std::vector<uint8_t>& ciphertext,
                                         const std::vector<uint8_t>& iv,
                                         const std::vector<uint8_t>& aad,
                                         const std::vector<uint8_t>& tag) const;

        /**
         * Encrypt with CTR mode (stream cipher)
         * @param plaintext Data to encrypt
         * @param iv 16-byte initialization vector
         * @return Encrypted ciphertext
         */
        std::vector<uint8_t> encryptCTR(const std::vector<uint8_t>& plaintext,
                                         const std::vector<uint8_t>& iv) const;

        /**
         * Decrypt with CTR mode
         * @param ciphertext Data to decrypt
         * @param iv 16-byte initialization vector
         * @return Decrypted plaintext
         */
        std::vector<uint8_t> decryptCTR(const std::vector<uint8_t>& ciphertext,
                                         const std::vector<uint8_t>& iv) const;

        /**
         * Encrypt file
         * @param inputPath Input file path
         * @param outputPath Output file path
         * @param iv Initialization vector
         * @return true if successful
         */
        bool encryptFile(const std::string& inputPath,
                         const std::string& outputPath,
                         const std::vector<uint8_t>& iv = {}) const;

        /**
         * Decrypt file
         * @param inputPath Input file path
         * @param outputPath Output file path
         * @param iv Initialization vector
         * @return true if successful
         */
        bool decryptFile(const std::string& inputPath,
                         const std::string& outputPath,
                         const std::vector<uint8_t>& iv = {}) const;

        /**
         * Get key size in bytes
         * @return Key size
         */
        size_t getKeySize() const;

        /**
         * Get block size (always 16)
         * @return Block size
         */
        static constexpr size_t getBlockSize() { return AES_BLOCK_SIZE; }

        /**
         * Get mode
         * @return AES mode
         */
        AESMode getMode() const;

        /**
         * Get key length
         * @return AES key length
         */
        AESKeyLength getKeyLength() const;

        /**
         * Get padding scheme
         * @return Padding scheme
         */
        AESPadding getPadding() const;

        /**
         * Set padding scheme
         * @param padding Padding scheme
         */
        void setPadding(AESPadding padding);

        /**
         * Check if mode requires IV
         * @return true if IV is required
         */
        bool requiresIV() const;

        /**
         * Check if mode is authenticated
         * @return true for GCM/CCM modes
         */
        bool isAuthenticated() const;

        /**
         * Get recommended IV size for current mode
         * @return IV size in bytes (0 if not required)
         */
        size_t getRecommendedIVSize() const;

        /**
         * Convert key length to bytes
         * @param keyLength Key length enum
         * @return Number of bytes
         */
        static size_t keyLengthToBytes(AESKeyLength keyLength);

        /**
         * Convert bytes to key length enum
         * @param bytes Number of bytes
         * @return Key length enum
         */
        static AESKeyLength bytesToKeyLength(size_t bytes);

        /**
         * Get mode name
         * @param mode AES mode
         * @return Mode name string
         */
        static std::string modeToString(AESMode mode);

        /**
         * Get padding name
         * @param padding Padding scheme
         * @return Padding name string
         */
        static std::string paddingToString(AESPadding padding);
    };

    /**
     * AES-CBC convenience class
     */
    class AES_CBC {
    private:
        AES aes;

    public:
        AES_CBC(AESKeyLength keyLength = AESKeyLength::AES_256,
                AESPadding padding = AESPadding::PKCS7);

        std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                      const std::vector<uint8_t>& iv);
        std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                      const std::vector<uint8_t>& iv);
        std::vector<uint8_t> generateIV() const { return aes.generateIV(); }
    };

    /**
     * AES-GCM convenience class (authenticated encryption)
     */
    class AES_GCM {
    private:
        AES aes;

    public:
        AES_GCM(AESKeyLength keyLength = AESKeyLength::AES_256);

        std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                      const std::vector<uint8_t>& iv,
                                      const std::vector<uint8_t>& aad,
                                      std::vector<uint8_t>& tag);
        std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                      const std::vector<uint8_t>& iv,
                                      const std::vector<uint8_t>& aad,
                                      const std::vector<uint8_t>& tag);
        std::vector<uint8_t> generateIV() const { return aes.generateIV(); }
        static constexpr size_t getTagSize() { return 16; }
    };

    /**
     * AES-CTR convenience class (stream cipher)
     */
    class AES_CTR {
    private:
        AES aes;

    public:
        AES_CTR(AESKeyLength keyLength = AESKeyLength::AES_256);

        std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data,
                                      const std::vector<uint8_t>& iv);
        std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data,
                                      const std::vector<uint8_t>& iv);
        std::vector<uint8_t> generateIV() const { return aes.generateIV(); }
    };

    /**
     * AES key wrapper for secure key storage
     */
    class AESKey {
    private:
        std::vector<uint8_t> key;
        AESKeyLength keyLength;

    public:
        AESKey();
        explicit AESKey(const std::vector<uint8_t>& keyData);
        explicit AESKey(const std::string& password);

        bool setKey(const std::vector<uint8_t>& keyData);
        bool setFromPassword(const std::string& password, const std::vector<uint8_t>& salt);
        void clear();

        const std::vector<uint8_t>& getKey() const { return key; }
        AESKeyLength getKeyLength() const { return keyLength; }
        size_t getKeySize() const { return key.size(); }
        bool isEmpty() const { return key.empty(); }

        static std::vector<uint8_t> deriveFromPassword(const std::string& password,
                                                        const std::vector<uint8_t>& salt,
                                                        AESKeyLength keyLength,
                                                        uint32_t iterations = 100000);
    };

} // namespace powercoin

#endif // POWERCOIN_AES_H