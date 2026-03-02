#ifndef POWERCOIN_RANDOM_H
#define POWERCOIN_RANDOM_H

#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <random>
#include <chrono>

namespace powercoin {

    /**
     * Random number generation utilities
     * Provides cryptographically secure random numbers
     */
    class Random {
    private:
        static std::random_device rd;
        static std::mt19937_64 gen;
        static std::uniform_int_distribution<uint64_t> dis;
        static bool initialized;

        /**
         * Initialize random generator
         */
        static void initialize();

    public:
        /**
         * Generate random bytes
         * @param bytes Output buffer
         * @param len Number of bytes to generate
         * @return true if successful
         */
        static bool getBytes(uint8_t* bytes, size_t len);

        /**
         * Generate random bytes as vector
         * @param len Number of bytes to generate
         * @return Vector of random bytes
         */
        static std::vector<uint8_t> getBytes(size_t len);

        /**
         * Generate random uint32_t
         * @return Random 32-bit integer
         */
        static uint32_t getUint32();

        /**
         * Generate random uint32_t in range [min, max]
         * @param min Minimum value
         * @param max Maximum value
         * @return Random 32-bit integer in range
         */
        static uint32_t getUint32(uint32_t min, uint32_t max);

        /**
         * Generate random uint64_t
         * @return Random 64-bit integer
         */
        static uint64_t getUint64();

        /**
         * Generate random uint64_t in range [min, max]
         * @param min Minimum value
         * @param max Maximum value
         * @return Random 64-bit integer in range
         */
        static uint64_t getUint64(uint64_t min, uint64_t max);

        /**
         * Generate random boolean
         * @return Random boolean
         */
        static bool getBool();

        /**
         * Generate random double in range [0, 1)
         * @return Random double
         */
        static double getDouble();

        /**
         * Generate random double in range [min, max]
         * @param min Minimum value
         * @param max Maximum value
         * @return Random double in range
         */
        static double getDouble(double min, double max);

        /**
         * Generate random string of given length
         * @param len Length of string
         * @param charset Character set to use (default: alphanumeric)
         * @return Random string
         */
        static std::string getString(size_t len, 
                                     const std::string& charset = 
                                     "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");

        /**
         * Generate random hex string of given length
         * @param len Length in bytes (output will be 2*len characters)
         * @return Random hex string
         */
        static std::string getHexString(size_t len);

        /**
         * Generate random base58 string
         * @param len Length of string
         * @return Random base58 string
         */
        static std::string getBase58String(size_t len);

        /**
         * Generate random alphanumeric string
         * @param len Length of string
         * @return Random alphanumeric string
         */
        static std::string getAlphanumericString(size_t len);

        /**
         * Generate random seed for deterministic RNG
         * @param len Seed length in bytes
         * @return Random seed bytes
         */
        static std::vector<uint8_t> getSeed(size_t len = 32);

        /**
         * Shuffle a container
         * @param begin Iterator begin
         * @param end Iterator end
         */
        template<typename Iterator>
        static void shuffle(Iterator begin, Iterator end) {
            initialize();
            std::shuffle(begin, end, gen);
        }

        /**
         * Choose random element from container
         * @param container Container to choose from
         * @return Random element
         */
        template<typename Container>
        static typename Container::value_type choice(const Container& container) {
            if (container.empty()) {
                throw std::runtime_error("Cannot choose from empty container");
            }
            initialize();
            size_t index = getUint64(0, container.size() - 1);
            auto it = container.begin();
            std::advance(it, index);
            return *it;
        }

        /**
         * Generate random permutation of integers
         * @param n Size of permutation
         * @return Vector containing permutation of 0..n-1
         */
        static std::vector<size_t> permutation(size_t n);

        /**
         * Generate random sample without replacement
         * @param population Population size
         * @param sample Sample size
         * @return Vector of sampled indices
         */
        static std::vector<size_t> sample(size_t population, size_t sample);

        /**
         * Generate random UUID v4
         * @return UUID string (36 characters)
         */
        static std::string getUUID();

        /**
         * Generate random private key
         * @return 32-byte random private key
         */
        static std::vector<uint8_t> getPrivateKey();

        /**
         * Generate random IV for AES
         * @param size IV size (default 16 for AES block)
         * @return Random IV bytes
         */
        static std::vector<uint8_t> getIV(size_t size = 16);

        /**
         * Generate random salt for key derivation
         * @param size Salt size (default 16)
         * @return Random salt bytes
         */
        static std::vector<uint8_t> getSalt(size_t size = 16);

        /**
         * Generate random nonce
         * @param size Nonce size (default 12 for GCM)
         * @return Random nonce bytes
         */
        static std::vector<uint8_t> getNonce(size_t size = 12);

        /**
         * Seed the random generator
         * @param seed Seed bytes
         */
        static void seed(const std::vector<uint8_t>& seed);

        /**
         * Reseed with current time
         */
        static void reseed();

        /**
         * Get entropy from system
         * @param bytes Output buffer
         * @param len Number of bytes to get
         * @return true if successful
         */
        static bool getEntropy(uint8_t* bytes, size_t len);

        /**
         * Check if random generator is properly initialized
         * @return true if initialized
         */
        static bool isInitialized() { return initialized; }

        /**
         * Get random generator state
         * @return Current state as string
         */
        static std::string getState();

        /**
         * Set random generator state
         * @param state State string from getState()
         */
        static void setState(const std::string& state);
    };

    /**
     * Secure random number generator for cryptographic operations
     * Uses OS-provided randomness when available
     */
    class SecureRandom {
    public:
        /**
         * Generate cryptographically secure random bytes
         * @param bytes Output buffer
         * @param len Number of bytes to generate
         * @return true if successful
         */
        static bool getBytes(uint8_t* bytes, size_t len);

        /**
         * Generate cryptographically secure random bytes as vector
         * @param len Number of bytes to generate
         * @return Vector of random bytes
         */
        static std::vector<uint8_t> getBytes(size_t len);

        /**
         * Generate cryptographically secure random uint32_t
         * @return Random 32-bit integer
         */
        static uint32_t getUint32();

        /**
         * Generate cryptographically secure random uint64_t
         * @return Random 64-bit integer
         */
        static uint64_t getUint64();

        /**
         * Generate cryptographically secure random in range
         * @param min Minimum value
         * @param max Maximum value
         * @return Random integer in range [min, max]
         */
        static uint64_t getRange(uint64_t min, uint64_t max);
    };

    /**
     * Deterministic random number generator (for testing)
     */
    class DeterministicRandom {
    private:
        std::mt19937_64 gen;
        std::uniform_int_distribution<uint64_t> dis;

    public:
        /**
         * Constructor with seed
         * @param seed Seed value
         */
        explicit DeterministicRandom(uint64_t seed);

        /**
         * Get random bytes
         * @param len Number of bytes
         * @return Random bytes
         */
        std::vector<uint8_t> getBytes(size_t len);

        /**
         * Get random uint64_t
         * @return Random 64-bit integer
         */
        uint64_t getUint64();

        /**
         * Get random uint64_t in range
         * @param min Minimum
         * @param max Maximum
         * @return Random in range
         */
        uint64_t getUint64(uint64_t min, uint64_t max);

        /**
         * Reset generator with new seed
         * @param seed New seed
         */
        void reset(uint64_t seed);
    };

    /**
     * Random number generator wrapper for STL compatibility
     */
    class RandomEngine : public std::random_device {
    public:
        using result_type = uint64_t;

        static result_type min() { return 0; }
        static result_type max() { return UINT64_MAX; }

        result_type operator()() {
            return SecureRandom::getUint64();
        }
    };

} // namespace powercoin

#endif // POWERCOIN_RANDOM_H