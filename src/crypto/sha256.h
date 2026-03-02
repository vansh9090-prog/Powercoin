#ifndef POWERCOIN_SHA256_H
#define POWERCOIN_SHA256_H

#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <cstring>

namespace powercoin {

    /**
     * SHA-256 hash size in bytes
     */
    constexpr size_t SHA256_HASH_SIZE = 32;

    /**
     * SHA-256 block size in bytes
     */
    constexpr size_t SHA256_BLOCK_SIZE = 64;

    /**
     * SHA-256 hash type
     */
    using SHA256Hash = std::array<uint8_t, SHA256_HASH_SIZE>;

    /**
     * SHA-256 implementation
     * Bitcoin-compatible double SHA-256 hashing
     */
    class SHA256 {
    private:
        // Internal state
        uint32_t h[8];
        uint8_t buffer[SHA256_BLOCK_SIZE];
        uint64_t bitCount;
        uint32_t bufferPos;

        // Constants
        static const uint32_t K[64];

        // Internal methods
        void transform(const uint8_t* block);
        void write(const uint8_t* data, size_t len);
        void pad();
        void finalize(uint8_t* hash);

    public:
        /**
         * Constructor - initializes SHA-256 context
         */
        SHA256();

        /**
         * Destructor
         */
        ~SHA256();

        /**
         * Reset the hashing context
         */
        void reset();

        /**
         * Add data to hash
         * @param data Input data
         * @param len Length of data
         */
        void update(const uint8_t* data, size_t len);

        /**
         * Add string data to hash
         * @param str Input string
         */
        void update(const std::string& str);

        /**
         * Add vector data to hash
         * @param data Input vector
         */
        void update(const std::vector<uint8_t>& data);

        /**
         * Finalize hash and get result
         * @param hash Output hash buffer (must be 32 bytes)
         */
        void finalize(uint8_t* hash);

        /**
         * Get hash as bytes
         * @return 32-byte hash
         */
        std::vector<uint8_t> finalize();

        /**
         * Get hash as string
         * @return Hexadecimal hash string
         */
        std::string finalizeHex();

        /**
         * Single-step SHA-256 hash
         * @param data Input data
         * @param len Length of data
         * @return 32-byte hash
         */
        static std::vector<uint8_t> hash(const uint8_t* data, size_t len);

        /**
         * Single-step SHA-256 hash of string
         * @param str Input string
         * @return Hexadecimal hash string
         */
        static std::string hash(const std::string& str);

        /**
         * Single-step SHA-256 hash of vector
         * @param data Input vector
         * @return Hexadecimal hash string
         */
        static std::string hash(const std::vector<uint8_t>& data);

        /**
         * Double SHA-256 hash (SHA-256 of SHA-256)
         * Used in Bitcoin for transaction and block hashing
         * @param data Input data
         * @param len Length of data
         * @return 32-byte hash
         */
        static std::vector<uint8_t> doubleHash(const uint8_t* data, size_t len);

        /**
         * Double SHA-256 hash of string
         * @param str Input string
         * @return Hexadecimal hash string
         */
        static std::string doubleHash(const std::string& str);

        /**
         * Double SHA-256 hash of vector
         * @param data Input vector
         * @return Hexadecimal hash string
         */
        static std::string doubleHash(const std::vector<uint8_t>& data);

        /**
         * Double SHA-256 hash with midstate caching
         * Optimized for mining
         * @param data Input data
         * @param len Length of data
         * @param midstate Pre-computed midstate
         * @return 32-byte hash
         */
        static std::vector<uint8_t> doubleHashWithMidstate(
            const uint8_t* data, size_t len, const uint32_t* midstate);

        /**
         * Compute SHA-256 midstate
         * Used for mining optimizations
         * @param data First 64 bytes of data
         * @return 8-word midstate
         */
        static std::array<uint32_t, 8> computeMidstate(const uint8_t* data);

        /**
         * Verify if hash matches target
         * @param hash Hash to check
         * @param target Target threshold
         * @return true if hash <= target
         */
        static bool checkTarget(const uint8_t* hash, const uint8_t* target);

        /**
         * Verify if hash matches difficulty
         * @param hash Hash to check
         * @param difficulty Difficulty bits
         * @return true if hash meets difficulty
         */
        static bool checkDifficulty(const uint8_t* hash, uint32_t difficulty);

        /**
         * Convert hash to integer for comparison
         * @param hash Hash bytes
         * @return 256-bit integer as byte array
         */
        static std::array<uint8_t, 32> hashToBytes(const std::string& hash);

        /**
         * Convert integer to hash string
         * @param bytes 32-byte array
         * @return Hexadecimal hash string
         */
        static std::string bytesToHash(const std::array<uint8_t, 32>& bytes);

        /**
         * Compare two hashes
         * @param a First hash
         * @param b Second hash
         * @return -1 if a < b, 0 if equal, 1 if a > b
         */
        static int compare(const uint8_t* a, const uint8_t* b);

        /**
         * Check if hash is zero
         * @param hash Hash to check
         * @return true if all bytes are zero
         */
        static bool isZero(const uint8_t* hash);

        /**
         * Get hash as 256-bit integer
         * @param hash Hash bytes
         * @return 256-bit integer as big-endian bytes
         */
        static std::array<uint8_t, 32> toBigEndian(const uint8_t* hash);

        /**
         * Get hash from 256-bit integer
         * @param bigEndian Big-endian bytes
         * @return Hash bytes
         */
        static std::array<uint8_t, 32> fromBigEndian(const uint8_t* bigEndian);

        /**
         * HMAC-SHA256 for message authentication
         * @param key HMAC key
         * @param message Message to authenticate
         * @return 32-byte HMAC
         */
        static std::vector<uint8_t> hmac(const uint8_t* key, size_t keyLen,
                                         const uint8_t* message, size_t messageLen);

        /**
         * HMAC-SHA256 of strings
         * @param key HMAC key
         * @param message Message to authenticate
         * @return Hexadecimal HMAC string
         */
        static std::string hmac(const std::string& key, const std::string& message);

        /**
         * PBKDF2-HMAC-SHA256 for key derivation
         * @param password Password
         * @param salt Salt
         * @param iterations Number of iterations
         * @param dkLen Desired key length
         * @return Derived key
         */
        static std::vector<uint8_t> pbkdf2(const uint8_t* password, size_t passwordLen,
                                           const uint8_t* salt, size_t saltLen,
                                           uint32_t iterations, size_t dkLen);

        /**
         * Get hash length in bytes
         * @return 32
         */
        static constexpr size_t hashSize() { return SHA256_HASH_SIZE; }

        /**
         * Get block size in bytes
         * @return 64
         */
        static constexpr size_t blockSize() { return SHA256_BLOCK_SIZE; }
    };

    /**
     * SHA-256 Hash object for RAII-style hashing
     */
    class SHA256HashObject {
    private:
        SHA256 context;
        bool finalized;
        std::array<uint8_t, SHA256_HASH_SIZE> hash;

    public:
        /**
         * Constructor - starts hashing
         */
        SHA256HashObject();

        /**
         * Destructor
         */
        ~SHA256HashObject();

        /**
         * Add data to hash
         * @param data Input data
         * @param len Length of data
         */
        void update(const uint8_t* data, size_t len);

        /**
         * Add string to hash
         * @param str Input string
         */
        void update(const std::string& str);

        /**
         * Finalize and get hash
         * @return 32-byte hash
         */
        const uint8_t* finalize();

        /**
         * Get hash as bytes
         * @return Hash bytes
         */
        const std::array<uint8_t, SHA256_HASH_SIZE>& getHash() const;

        /**
         * Get hash as hex string
         * @return Hexadecimal string
         */
        std::string getHex() const;

        /**
         * Reset for new hash
         */
        void reset();
    };

    /**
     * Double SHA-256 convenience function
     * @param data Input data
     * @return Double SHA-256 hash
     */
    inline std::string doubleSHA256(const std::string& data) {
        return SHA256::doubleHash(data);
    }

    /**
     * SHA-256 convenience function
     * @param data Input data
     * @return SHA-256 hash
     */
    inline std::string sha256(const std::string& data) {
        return SHA256::hash(data);
    }

} // namespace powercoin

#endif // POWERCOIN_SHA256_H