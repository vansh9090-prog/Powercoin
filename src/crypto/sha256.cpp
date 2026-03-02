#include "sha256.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>

namespace powercoin {

    // SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    const uint32_t SHA256::K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    SHA256::SHA256() {
        reset();
    }

    SHA256::~SHA256() {
        // Secure cleanup
        memset(h, 0, sizeof(h));
        memset(buffer, 0, sizeof(buffer));
        bitCount = 0;
        bufferPos = 0;
    }

    void SHA256::reset() {
        // Initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
        h[0] = 0x6a09e667;
        h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372;
        h[3] = 0xa54ff53a;
        h[4] = 0x510e527f;
        h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab;
        h[7] = 0x5be0cd19;

        bitCount = 0;
        bufferPos = 0;
        memset(buffer, 0, sizeof(buffer));
    }

    void SHA256::transform(const uint8_t* block) {
        uint32_t w[64];
        uint32_t a, b, c, d, e, f, g, h_val;
        uint32_t t1, t2;

        // Prepare message schedule
        for (int i = 0; i < 16; i++) {
            w[i] = (static_cast<uint32_t>(block[i * 4]) << 24) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 8) |
                   static_cast<uint32_t>(block[i * 4 + 3]);
        }

        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ((w[i - 15] >> 7) | (w[i - 15] << 25)) ^
                          ((w[i - 15] >> 18) | (w[i - 15] << 14)) ^
                          (w[i - 15] >> 3);
            uint32_t s1 = ((w[i - 2] >> 17) | (w[i - 2] << 15)) ^
                          ((w[i - 2] >> 19) | (w[i - 2] << 13)) ^
                          (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        // Initialize working variables
        a = h[0];
        b = h[1];
        c = h[2];
        d = h[3];
        e = h[4];
        f = h[5];
        g = h[6];
        h_val = h[7];

        // Main loop
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ((e >> 6) | (e << 26)) ^
                          ((e >> 11) | (e << 21)) ^
                          ((e >> 25) | (e << 7));
            uint32_t ch = (e & f) ^ ((~e) & g);
            t1 = h_val + S1 + ch + K[i] + w[i];

            uint32_t S0 = ((a >> 2) | (a << 30)) ^
                          ((a >> 13) | (a << 19)) ^
                          ((a >> 22) | (a << 10));
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            t2 = S0 + maj;

            h_val = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        // Add compressed chunk to hash value
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h_val;
    }

    void SHA256::write(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; i++) {
            buffer[bufferPos++] = data[i];
            if (bufferPos == SHA256_BLOCK_SIZE) {
                transform(buffer);
                bitCount += SHA256_BLOCK_SIZE * 8;
                bufferPos = 0;
            }
        }
    }

    void SHA256::update(const uint8_t* data, size_t len) {
        if (data && len > 0) {
            write(data, len);
        }
    }

    void SHA256::update(const std::string& str) {
        update(reinterpret_cast<const uint8_t*>(str.c_str()), str.length());
    }

    void SHA256::update(const std::vector<uint8_t>& data) {
        if (!data.empty()) {
            update(data.data(), data.size());
        }
    }

    void SHA256::pad() {
        // Pad with 0x80 followed by zeros
        uint8_t padding[SHA256_BLOCK_SIZE + 8];
        size_t padLen;

        padding[0] = 0x80;
        for (size_t i = 1; i < sizeof(padding); i++) {
            padding[i] = 0;
        }

        // Calculate padding length
        padLen = (bufferPos < 56) ? (56 - bufferPos) : (120 - bufferPos);
        write(padding, padLen);

        // Append length in bits
        uint64_t bitCountBE = htobe64(bitCount);
        write(reinterpret_cast<uint8_t*>(&bitCountBE), 8);
    }

    void SHA256::finalize(uint8_t* hash) {
        pad();

        // Convert hash to big-endian
        for (int i = 0; i < 8; i++) {
            uint32_t h_be = htobe32(h[i]);
            memcpy(hash + i * 4, &h_be, 4);
        }

        // Reset for next use
        reset();
    }

    std::vector<uint8_t> SHA256::finalize() {
        std::vector<uint8_t> hash(SHA256_HASH_SIZE);
        finalize(hash.data());
        return hash;
    }

    std::string SHA256::finalizeHex() {
        auto hash = finalize();
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto byte : hash) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    std::vector<uint8_t> SHA256::hash(const uint8_t* data, size_t len) {
        SHA256 sha;
        sha.update(data, len);
        return sha.finalize();
    }

    std::string SHA256::hash(const std::string& str) {
        SHA256 sha;
        sha.update(str);
        return sha.finalizeHex();
    }

    std::string SHA256::hash(const std::vector<uint8_t>& data) {
        SHA256 sha;
        sha.update(data);
        return sha.finalizeHex();
    }

    std::vector<uint8_t> SHA256::doubleHash(const uint8_t* data, size_t len) {
        auto first = hash(data, len);
        return hash(first.data(), first.size());
    }

    std::string SHA256::doubleHash(const std::string& str) {
        auto first = hash(str);
        return hash(first);
    }

    std::string SHA256::doubleHash(const std::vector<uint8_t>& data) {
        auto first = hash(data);
        return hash(first);
    }

    std::vector<uint8_t> SHA256::doubleHashWithMidstate(
        const uint8_t* data, size_t len, const uint32_t* midstate) {
        
        SHA256 sha;
        
        // Restore midstate
        memcpy(sha.h, midstate, 8 * sizeof(uint32_t));
        sha.bitCount = SHA256_BLOCK_SIZE * 8;
        sha.bufferPos = 0;

        // Process remaining data
        sha.update(data, len);
        return sha.finalize();
    }

    std::array<uint32_t, 8> SHA256::computeMidstate(const uint8_t* data) {
        SHA256 sha;
        sha.update(data, SHA256_BLOCK_SIZE);
        
        std::array<uint32_t, 8> midstate;
        memcpy(midstate.data(), sha.h, 8 * sizeof(uint32_t));
        return midstate;
    }

    bool SHA256::checkTarget(const uint8_t* hash, const uint8_t* target) {
        return compare(hash, target) <= 0;
    }

    bool SHA256::checkDifficulty(const uint8_t* hash, uint32_t difficulty) {
        // Convert difficulty bits to target
        uint32_t exponent = difficulty >> 24;
        uint32_t mantissa = difficulty & 0x007fffff;
        
        std::array<uint8_t, 32> target = {0};
        
        if (exponent <= 3) {
            target[exponent - 1] = (mantissa >> (8 * (3 - exponent))) & 0xff;
            target[exponent] = (mantissa >> (8 * (2 - exponent))) & 0xff;
            target[exponent + 1] = (mantissa >> (8 * (1 - exponent))) & 0xff;
            target[exponent + 2] = mantissa & 0xff;
        } else {
            target[exponent - 3] = (mantissa >> 16) & 0xff;
            target[exponent - 2] = (mantissa >> 8) & 0xff;
            target[exponent - 1] = mantissa & 0xff;
        }

        return checkTarget(hash, target.data());
    }

    std::array<uint8_t, 32> SHA256::hashToBytes(const std::string& hash) {
        std::array<uint8_t, 32> bytes;
        
        if (hash.length() != 64) {
            throw std::invalid_argument("Invalid hash length");
        }

        for (size_t i = 0; i < 32; i++) {
            std::string byteStr = hash.substr(i * 2, 2);
            bytes[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        }

        return bytes;
    }

    std::string SHA256::bytesToHash(const std::array<uint8_t, 32>& bytes) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto byte : bytes) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    int SHA256::compare(const uint8_t* a, const uint8_t* b) {
        for (int i = 0; i < SHA256_HASH_SIZE; i++) {
            if (a[i] < b[i]) return -1;
            if (a[i] > b[i]) return 1;
        }
        return 0;
    }

    bool SHA256::isZero(const uint8_t* hash) {
        for (int i = 0; i < SHA256_HASH_SIZE; i++) {
            if (hash[i] != 0) return false;
        }
        return true;
    }

    std::array<uint8_t, 32> SHA256::toBigEndian(const uint8_t* hash) {
        std::array<uint8_t, 32> be;
        // Already in big-endian from finalize()
        memcpy(be.data(), hash, SHA256_HASH_SIZE);
        return be;
    }

    std::array<uint8_t, 32> SHA256::fromBigEndian(const uint8_t* bigEndian) {
        std::array<uint8_t, 32> hash;
        memcpy(hash.data(), bigEndian, SHA256_HASH_SIZE);
        return hash;
    }

    std::vector<uint8_t> SHA256::hmac(const uint8_t* key, size_t keyLen,
                                       const uint8_t* message, size_t messageLen) {
        uint8_t k_ipad[SHA256_BLOCK_SIZE];
        uint8_t k_opad[SHA256_BLOCK_SIZE];
        uint8_t tempKey[SHA256_HASH_SIZE];

        // If key is longer than block size, hash it
        if (keyLen > SHA256_BLOCK_SIZE) {
            auto hashedKey = hash(key, keyLen);
            memcpy(tempKey, hashedKey.data(), SHA256_HASH_SIZE);
            key = tempKey;
            keyLen = SHA256_HASH_SIZE;
        }

        // Prepare inner and outer pads
        memset(k_ipad, 0, sizeof(k_ipad));
        memset(k_opad, 0, sizeof(k_opad));
        memcpy(k_ipad, key, keyLen);
        memcpy(k_opad, key, keyLen);

        for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
            k_ipad[i] ^= 0x36;
            k_opad[i] ^= 0x5c;
        }

        // Inner hash: H(K XOR ipad || message)
        SHA256 inner;
        inner.update(k_ipad, SHA256_BLOCK_SIZE);
        inner.update(message, messageLen);
        auto innerHash = inner.finalize();

        // Outer hash: H(K XOR opad || innerHash)
        SHA256 outer;
        outer.update(k_opad, SHA256_BLOCK_SIZE);
        outer.update(innerHash.data(), innerHash.size());
        return outer.finalize();
    }

    std::string SHA256::hmac(const std::string& key, const std::string& message) {
        auto hmacBytes = hmac(reinterpret_cast<const uint8_t*>(key.c_str()), key.length(),
                              reinterpret_cast<const uint8_t*>(message.c_str()), message.length());
        
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto byte : hmacBytes) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    std::vector<uint8_t> SHA256::pbkdf2(const uint8_t* password, size_t passwordLen,
                                         const uint8_t* salt, size_t saltLen,
                                         uint32_t iterations, size_t dkLen) {
        size_t blocks = (dkLen + SHA256_HASH_SIZE - 1) / SHA256_HASH_SIZE;
        std::vector<uint8_t> derivedKey(blocks * SHA256_HASH_SIZE);

        for (size_t block = 1; block <= blocks; block++) {
            // U1 = HMAC(password, salt || INT(block))
            uint8_t blockBytes[4];
            blockBytes[0] = (block >> 24) & 0xff;
            blockBytes[1] = (block >> 16) & 0xff;
            blockBytes[2] = (block >> 8) & 0xff;
            blockBytes[3] = block & 0xff;

            std::vector<uint8_t> saltBlock(salt, salt + saltLen);
            saltBlock.insert(saltBlock.end(), blockBytes, blockBytes + 4);

            auto u = hmac(password, passwordLen,
                         saltBlock.data(), saltBlock.size());
            
            std::vector<uint8_t> t = u;

            // U2 = HMAC(password, U1)
            for (uint32_t i = 1; i < iterations; i++) {
                u = hmac(password, passwordLen, u.data(), u.size());
                for (size_t j = 0; j < SHA256_HASH_SIZE; j++) {
                    t[j] ^= u[j];
                }
            }

            // Append to derived key
            memcpy(derivedKey.data() + (block - 1) * SHA256_HASH_SIZE,
                   t.data(), SHA256_HASH_SIZE);
        }

        derivedKey.resize(dkLen);
        return derivedKey;
    }

    // ============== SHA256HashObject Implementation ==============

    SHA256HashObject::SHA256HashObject() : finalized(false) {
        hash.fill(0);
    }

    SHA256HashObject::~SHA256HashObject() = default;

    void SHA256HashObject::update(const uint8_t* data, size_t len) {
        if (!finalized) {
            context.update(data, len);
        }
    }

    void SHA256HashObject::update(const std::string& str) {
        if (!finalized) {
            context.update(str);
        }
    }

    const uint8_t* SHA256HashObject::finalize() {
        if (!finalized) {
            auto result = context.finalize();
            memcpy(hash.data(), result.data(), SHA256_HASH_SIZE);
            finalized = true;
        }
        return hash.data();
    }

    const std::array<uint8_t, SHA256_HASH_SIZE>& SHA256HashObject::getHash() const {
        if (!finalized) {
            throw std::runtime_error("Hash not finalized");
        }
        return hash;
    }

    std::string SHA256HashObject::getHex() const {
        if (!finalized) {
            throw std::runtime_error("Hash not finalized");
        }

        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto byte : hash) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    void SHA256HashObject::reset() {
        context.reset();
        finalized = false;
        hash.fill(0);
    }

} // namespace powercoin