#ifndef POWERCOIN_RIPEMD160_H
#define POWERCOIN_RIPEMD160_H

#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <cstring>

namespace powercoin {

    /**
     * RIPEMD-160 hash size in bytes
     */
    constexpr size_t RIPEMD160_HASH_SIZE = 20;

    /**
     * RIPEMD-160 block size in bytes
     */
    constexpr size_t RIPEMD160_BLOCK_SIZE = 64;

    /**
     * RIPEMD-160 hash type
     */
    using RIPEMD160Hash = std::array<uint8_t, RIPEMD160_HASH_SIZE>;

    /**
     * RIPEMD-160 implementation
     * Used in Bitcoin for address generation (with SHA-256)
     */
    class RIPEMD160 {
    private:
        // Internal state
        uint32_t h[5];
        uint8_t buffer[RIPEMD160_BLOCK_SIZE];
        uint64_t bitCount;
        uint32_t bufferPos;

        // Constants
        static const uint32_t K[5];   // Round constants for left line
        static const uint32_t Kp[5];  // Round constants for right line
        static const uint8_t R[5];    // Rotation amounts for left line
        static const uint8_t Rp[5];   // Rotation amounts for right line

        // Internal methods
        void transform(const uint8_t* block);
        void write(const uint8_t* data, size_t len);
        void pad();
        
        // RIPEMD-160 round functions
        static uint32_t f1(uint32_t x, uint32_t y, uint32_t z);
        static uint32_t f2(uint32_t x, uint32_t y, uint32_t z);
        static uint32_t f3(uint32_t x, uint32_t y, uint32_t z);
        static uint32_t f4(uint32_t x, uint32_t y, uint32_t z);
        static uint32_t f5(uint32_t x, uint32_t y, uint32_t z);

        // Helper functions for the compression function
        static uint32_t rol(uint32_t x, uint32_t n);
        static void round(uint32_t& a, uint32_t b, uint32_t& c, uint32_t d,
                         uint32_t e, uint32_t x, uint32_t k, uint8_t r,
                         uint32_t (*f)(uint32_t, uint32_t, uint32_t));
        static void roundp(uint32_t& a, uint32_t b, uint32_t& c, uint32_t d,
                          uint32_t e, uint32_t x, uint32_t k, uint8_t r,
                          uint32_t (*f)(uint32_t, uint32_t, uint32_t));

    public:
        /**
         * Constructor - initializes RIPEMD-160 context
         */
        RIPEMD160();

        /**
         * Destructor
         */
        ~RIPEMD160();

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
         * @param hash Output hash buffer (must be 20 bytes)
         */
        void finalize(uint8_t* hash);

        /**
         * Get hash as bytes
         * @return 20-byte hash
         */
        std::vector<uint8_t> finalize();

        /**
         * Get hash as string
         * @return Hexadecimal hash string
         */
        std::string finalizeHex();

        /**
         * Single-step RIPEMD-160 hash
         * @param data Input data
         * @param len Length of data
         * @return 20-byte hash
         */
        static std::vector<uint8_t> hash(const uint8_t* data, size_t len);

        /**
         * Single-step RIPEMD-160 hash of string
         * @param str Input string
         * @return Hexadecimal hash string
         */
        static std::string hash(const std::string& str);

        /**
         * Single-step RIPEMD-160 hash of vector
         * @param data Input vector
         * @return Hexadecimal hash string
         */
        static std::string hash(const std::vector<uint8_t>& data);

        /**
         * Hash160 (SHA-256 then RIPEMD-160)
         * Used in Bitcoin for address generation
         * @param data Input data
         * @param len Length of data
         * @return 20-byte hash
         */
        static std::vector<uint8_t> hash160(const uint8_t* data, size_t len);

        /**
         * Hash160 of string
         * @param str Input string
         * @return Hexadecimal hash string
         */
        static std::string hash160(const std::string& str);

        /**
         * Hash160 of vector
         * @param data Input vector
         * @return Hexadecimal hash string
         */
        static std::string hash160(const std::vector<uint8_t>& data);

        /**
         * Double RIPEMD-160 (RIPEMD-160 of RIPEMD-160)
         * @param data Input data
         * @param len Length of data
         * @return 20-byte hash
         */
        static std::vector<uint8_t> doubleHash(const uint8_t* data, size_t len);

        /**
         * Double RIPEMD-160 of string
         * @param str Input string
         * @return Hexadecimal hash string
         */
        static std::string doubleHash(const std::string& str);

        /**
         * Verify if hash matches expected value
         * @param hash Hash to check
         * @param expected Expected hash bytes
         * @return true if equal
         */
        static bool verify(const uint8_t* hash, const uint8_t* expected);

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
         * Convert hash to hex string
         * @param hash Hash bytes
         * @return Hexadecimal string
         */
        static std::string toHex(const uint8_t* hash);

        /**
         * Convert hex string to hash
         * @param hex Hexadecimal string
         * @return Hash bytes
         */
        static std::vector<uint8_t> fromHex(const std::string& hex);

        /**
         * Get hash length in bytes
         * @return 20
         */
        static constexpr size_t hashSize() { return RIPEMD160_HASH_SIZE; }

        /**
         * Get block size in bytes
         * @return 64
         */
        static constexpr size_t blockSize() { return RIPEMD160_BLOCK_SIZE; }
    };

    /**
     * RIPEMD-160 Hash object for RAII-style hashing
     */
    class RIPEMD160HashObject {
    private:
        RIPEMD160 context;
        bool finalized;
        std::array<uint8_t, RIPEMD160_HASH_SIZE> hash;

    public:
        /**
         * Constructor - starts hashing
         */
        RIPEMD160HashObject();

        /**
         * Destructor
         */
        ~RIPEMD160HashObject();

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
         * @return 20-byte hash
         */
        const uint8_t* finalize();

        /**
         * Get hash as bytes
         * @return Hash bytes
         */
        const std::array<uint8_t, RIPEMD160_HASH_SIZE>& getHash() const;

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
     * Hash160 convenience function (SHA-256 + RIPEMD-160)
     * @param data Input data
     * @return RIPEMD-160 hash
     */
    inline std::string hash160(const std::string& data) {
        return RIPEMD160::hash160(data);
    }

    /**
     * RIPEMD-160 convenience function
     * @param data Input data
     * @return RIPEMD-160 hash
     */
    inline std::string ripemd160(const std::string& data) {
        return RIPEMD160::hash(data);
    }

} // namespace powercoin

#endif // POWERCOIN_RIPEMD160_H