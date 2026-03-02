#include "random.h"
#include <openssl/rand.h>
#include <cstring>
#include <chrono>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>

namespace powercoin {

    // Static member initialization
    std::random_device Random::rd;
    std::mt19937_64 Random::gen(rd());
    std::uniform_int_distribution<uint64_t> Random::dis;
    bool Random::initialized = false;

    void Random::initialize() {
        if (!initialized) {
            // Seed with current time and random device
            auto seed = std::chrono::high_resolution_clock::now()
                        .time_since_epoch().count();
            gen.seed(seed ^ rd());
            initialized = true;
        }
    }

    bool Random::getBytes(uint8_t* bytes, size_t len) {
        if (!bytes || len == 0) return false;
        
        // Try OpenSSL RAND_bytes first (cryptographically secure)
        if (RAND_bytes(bytes, len) == 1) {
            return true;
        }

        // Fallback to mt19937
        initialize();
        for (size_t i = 0; i < len; i++) {
            bytes[i] = static_cast<uint8_t>(gen() & 0xFF);
        }
        return true;
    }

    std::vector<uint8_t> Random::getBytes(size_t len) {
        std::vector<uint8_t> result(len);
        getBytes(result.data(), len);
        return result;
    }

    uint32_t Random::getUint32() {
        uint32_t value;
        getBytes(reinterpret_cast<uint8_t*>(&value), sizeof(value));
        return value;
    }

    uint32_t Random::getUint32(uint32_t min, uint32_t max) {
        if (min > max) {
            throw std::invalid_argument("min must be <= max");
        }
        if (min == max) return min;
        
        uint64_t range = static_cast<uint64_t>(max) - min + 1;
        uint64_t value = getUint64();
        return min + static_cast<uint32_t>(value % range);
    }

    uint64_t Random::getUint64() {
        uint64_t value;
        getBytes(reinterpret_cast<uint8_t*>(&value), sizeof(value));
        return value;
    }

    uint64_t Random::getUint64(uint64_t min, uint64_t max) {
        if (min > max) {
            throw std::invalid_argument("min must be <= max");
        }
        if (min == max) return min;
        
        uint64_t range = max - min + 1;
        uint64_t value = getUint64();
        return min + (value % range);
    }

    bool Random::getBool() {
        return (getUint32() & 1) == 1;
    }

    double Random::getDouble() {
        return static_cast<double>(getUint64()) / static_cast<double>(UINT64_MAX);
    }

    double Random::getDouble(double min, double max) {
        if (min > max) {
            throw std::invalid_argument("min must be <= max");
        }
        return min + getDouble() * (max - min);
    }

    std::string Random::getString(size_t len, const std::string& charset) {
        if (charset.empty()) {
            throw std::invalid_argument("Charset cannot be empty");
        }

        std::string result;
        result.reserve(len);
        
        for (size_t i = 0; i < len; i++) {
            size_t index = getUint64(0, charset.length() - 1);
            result += charset[index];
        }
        
        return result;
    }

    std::string Random::getHexString(size_t len) {
        auto bytes = getBytes(len);
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto byte : bytes) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    std::string Random::getBase58String(size_t len) {
        const std::string base58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
        return getString(len, base58);
    }

    std::string Random::getAlphanumericString(size_t len) {
        const std::string alphanum = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        return getString(len, alphanum);
    }

    std::vector<uint8_t> Random::getSeed(size_t len) {
        return getBytes(len);
    }

    std::vector<size_t> Random::permutation(size_t n) {
        std::vector<size_t> result(n);
        for (size_t i = 0; i < n; i++) {
            result[i] = i;
        }
        shuffle(result.begin(), result.end());
        return result;
    }

    std::vector<size_t> Random::sample(size_t population, size_t sample) {
        if (sample > population) {
            throw std::invalid_argument("Sample size cannot exceed population");
        }

        std::vector<size_t> result;
        result.reserve(sample);

        if (sample * 2 < population) {
            // Reservoir sampling
            for (size_t i = 0; i < population; i++) {
                if (result.size() < sample) {
                    result.push_back(i);
                } else {
                    size_t j = getUint64(0, i);
                    if (j < sample) {
                        result[j] = i;
                    }
                }
            }
        } else {
            // Full shuffle for large samples
            auto perm = permutation(population);
            result.insert(result.end(), perm.begin(), perm.begin() + sample);
        }

        return result;
    }

    std::string Random::getUUID() {
        auto bytes = getBytes(16);
        
        // Set version (4) and variant bits
        bytes[6] = (bytes[6] & 0x0F) | 0x40;
        bytes[8] = (bytes[8] & 0x3F) | 0x80;

        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        
        for (int i = 0; i < 16; i++) {
            if (i == 4 || i == 6 || i == 8 || i == 10) {
                ss << '-';
            }
            ss << std::setw(2) << static_cast<int>(bytes[i]);
        }
        
        return ss.str();
    }

    std::vector<uint8_t> Random::getPrivateKey() {
        return getBytes(32);
    }

    std::vector<uint8_t> Random::getIV(size_t size) {
        return getBytes(size);
    }

    std::vector<uint8_t> Random::getSalt(size_t size) {
        return getBytes(size);
    }

    std::vector<uint8_t> Random::getNonce(size_t size) {
        return getBytes(size);
    }

    void Random::seed(const std::vector<uint8_t>& seed) {
        initialize();
        std::seed_seq seq(seed.begin(), seed.end());
        gen.seed(seq);
    }

    void Random::reseed() {
        auto seed = std::chrono::high_resolution_clock::now()
                    .time_since_epoch().count();
        gen.seed(seed ^ rd());
    }

    bool Random::getEntropy(uint8_t* bytes, size_t len) {
        // Use OpenSSL for entropy
        return RAND_bytes(bytes, len) == 1;
    }

    std::string Random::getState() {
        initialize();
        std::stringstream ss;
        ss << gen;
        return ss.str();
    }

    void Random::setState(const std::string& state) {
        initialize();
        std::stringstream ss(state);
        ss >> gen;
    }

    // ============== SecureRandom Implementation ==============

    bool SecureRandom::getBytes(uint8_t* bytes, size_t len) {
        return RAND_bytes(bytes, len) == 1;
    }

    std::vector<uint8_t> SecureRandom::getBytes(size_t len) {
        std::vector<uint8_t> result(len);
        if (!getBytes(result.data(), len)) {
            throw std::runtime_error("Failed to generate secure random bytes");
        }
        return result;
    }

    uint32_t SecureRandom::getUint32() {
        uint32_t value;
        if (!getBytes(reinterpret_cast<uint8_t*>(&value), sizeof(value))) {
            throw std::runtime_error("Failed to generate secure random uint32");
        }
        return value;
    }

    uint64_t SecureRandom::getUint64() {
        uint64_t value;
        if (!getBytes(reinterpret_cast<uint8_t*>(&value), sizeof(value))) {
            throw std::runtime_error("Failed to generate secure random uint64");
        }
        return value;
    }

    uint64_t SecureRandom::getRange(uint64_t min, uint64_t max) {
        if (min > max) {
            throw std::invalid_argument("min must be <= max");
        }
        if (min == max) return min;
        
        uint64_t range = max - min + 1;
        uint64_t value;
        
        // Use rejection sampling to avoid bias
        uint64_t maxValue = UINT64_MAX - (UINT64_MAX % range);
        do {
            value = getUint64();
        } while (value >= maxValue);
        
        return min + (value % range);
    }

    // ============== DeterministicRandom Implementation ==============

    DeterministicRandom::DeterministicRandom(uint64_t seed) : gen(seed) {}

    std::vector<uint8_t> DeterministicRandom::getBytes(size_t len) {
        std::vector<uint8_t> result(len);
        for (size_t i = 0; i < len; i++) {
            result[i] = static_cast<uint8_t>(gen() & 0xFF);
        }
        return result;
    }

    uint64_t DeterministicRandom::getUint64() {
        return gen();
    }

    uint64_t DeterministicRandom::getUint64(uint64_t min, uint64_t max) {
        if (min > max) {
            throw std::invalid_argument("min must be <= max");
        }
        if (min == max) return min;
        
        uint64_t range = max - min + 1;
        return min + (gen() % range);
    }

    void DeterministicRandom::reset(uint64_t seed) {
        gen.seed(seed);
    }

} // namespace powercoin