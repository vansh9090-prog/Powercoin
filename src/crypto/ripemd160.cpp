#include "ripemd160.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>
#include "sha256.h"

namespace powercoin {

    // RIPEMD-160 constants
    const uint32_t RIPEMD160::K[5] = {
        0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e
    };

    const uint32_t RIPEMD160::Kp[5] = {
        0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000
    };

    const uint8_t RIPEMD160::R[5] = {
        11, 14, 15, 12, 5
    };

    const uint8_t RIPEMD160::Rp[5] = {
        8, 9, 9, 11, 13
    };

    // RIPEMD-160 round functions
    uint32_t RIPEMD160::f1(uint32_t x, uint32_t y, uint32_t z) {
        return x ^ y ^ z;
    }

    uint32_t RIPEMD160::f2(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) | (~x & z);
    }

    uint32_t RIPEMD160::f3(uint32_t x, uint32_t y, uint32_t z) {
        return (x | ~y) ^ z;
    }

    uint32_t RIPEMD160::f4(uint32_t x, uint32_t y, uint32_t z) {
        return (x & z) | (y & ~z);
    }

    uint32_t RIPEMD160::f5(uint32_t x, uint32_t y, uint32_t z) {
        return x ^ (y | ~z);
    }

    uint32_t RIPEMD160::rol(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    void RIPEMD160::round(uint32_t& a, uint32_t b, uint32_t& c, uint32_t d,
                          uint32_t e, uint32_t x, uint32_t k, uint8_t r,
                          uint32_t (*f)(uint32_t, uint32_t, uint32_t)) {
        a = rol(a + (*f)(b, c, d) + x + k, r) + e;
        c = rol(c, 10);
    }

    void RIPEMD160::roundp(uint32_t& a, uint32_t b, uint32_t& c, uint32_t d,
                           uint32_t e, uint32_t x, uint32_t k, uint8_t r,
                           uint32_t (*f)(uint32_t, uint32_t, uint32_t)) {
        a = rol(a + (*f)(b, c, d) + x + k, r) + e;
        c = rol(c, 10);
    }

    RIPEMD160::RIPEMD160() {
        reset();
    }

    RIPEMD160::~RIPEMD160() {
        // Secure cleanup
        memset(h, 0, sizeof(h));
        memset(buffer, 0, sizeof(buffer));
        bitCount = 0;
        bufferPos = 0;
    }

    void RIPEMD160::reset() {
        // Initial hash values
        h[0] = 0x67452301;
        h[1] = 0xefcdab89;
        h[2] = 0x98badcfe;
        h[3] = 0x10325476;
        h[4] = 0xc3d2e1f0;

        bitCount = 0;
        bufferPos = 0;
        memset(buffer, 0, sizeof(buffer));
    }

    void RIPEMD160::transform(const uint8_t* block) {
        uint32_t x[16];
        uint32_t al, bl, cl, dl, el;
        uint32_t ar, br, cr, dr, er;
        uint32_t temp;

        // Prepare message schedule (little-endian)
        for (int i = 0; i < 16; i++) {
            x[i] = (static_cast<uint32_t>(block[i * 4])) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
        }

        // Initialize working variables
        al = h[0];
        bl = h[1];
        cl = h[2];
        dl = h[3];
        el = h[4];
        
        ar = h[0];
        br = h[1];
        cr = h[2];
        dr = h[3];
        er = h[4];

        // Round 1 (left)
        round(al, bl, cl, dl, el, x[0], K[0], R[0], f1);
        round(el, al, bl, cl, dl, x[1], K[0], R[0], f1);
        round(dl, el, al, bl, cl, x[2], K[0], R[0], f1);
        round(cl, dl, el, al, bl, x[3], K[0], R[0], f1);
        round(bl, cl, dl, el, al, x[4], K[0], R[0], f1);
        round(al, bl, cl, dl, el, x[5], K[0], R[0], f1);
        round(el, al, bl, cl, dl, x[6], K[0], R[0], f1);
        round(dl, el, al, bl, cl, x[7], K[0], R[0], f1);
        round(cl, dl, el, al, bl, x[8], K[0], R[0], f1);
        round(bl, cl, dl, el, al, x[9], K[0], R[0], f1);
        round(al, bl, cl, dl, el, x[10], K[0], R[0], f1);
        round(el, al, bl, cl, dl, x[11], K[0], R[0], f1);
        round(dl, el, al, bl, cl, x[12], K[0], R[0], f1);
        round(cl, dl, el, al, bl, x[13], K[0], R[0], f1);
        round(bl, cl, dl, el, al, x[14], K[0], R[0], f1);
        round(al, bl, cl, dl, el, x[15], K[0], R[0], f1);

        // Round 2 (left)
        round(el, al, bl, cl, dl, x[7], K[1], R[1], f2);
        round(dl, el, al, bl, cl, x[4], K[1], R[1], f2);
        round(cl, dl, el, al, bl, x[13], K[1], R[1], f2);
        round(bl, cl, dl, el, al, x[1], K[1], R[1], f2);
        round(al, bl, cl, dl, el, x[10], K[1], R[1], f2);
        round(el, al, bl, cl, dl, x[6], K[1], R[1], f2);
        round(dl, el, al, bl, cl, x[15], K[1], R[1], f2);
        round(cl, dl, el, al, bl, x[3], K[1], R[1], f2);
        round(bl, cl, dl, el, al, x[12], K[1], R[1], f2);
        round(al, bl, cl, dl, el, x[0], K[1], R[1], f2);
        round(el, al, bl, cl, dl, x[9], K[1], R[1], f2);
        round(dl, el, al, bl, cl, x[5], K[1], R[1], f2);
        round(cl, dl, el, al, bl, x[2], K[1], R[1], f2);
        round(bl, cl, dl, el, al, x[14], K[1], R[1], f2);
        round(al, bl, cl, dl, el, x[11], K[1], R[1], f2);
        round(el, al, bl, cl, dl, x[8], K[1], R[1], f2);

        // Round 3 (left)
        round(dl, el, al, bl, cl, x[3], K[2], R[2], f3);
        round(cl, dl, el, al, bl, x[10], K[2], R[2], f3);
        round(bl, cl, dl, el, al, x[14], K[2], R[2], f3);
        round(al, bl, cl, dl, el, x[4], K[2], R[2], f3);
        round(el, al, bl, cl, dl, x[9], K[2], R[2], f3);
        round(dl, el, al, bl, cl, x[15], K[2], R[2], f3);
        round(cl, dl, el, al, bl, x[8], K[2], R[2], f3);
        round(bl, cl, dl, el, al, x[1], K[2], R[2], f3);
        round(al, bl, cl, dl, el, x[2], K[2], R[2], f3);
        round(el, al, bl, cl, dl, x[7], K[2], R[2], f3);
        round(dl, el, al, bl, cl, x[0], K[2], R[2], f3);
        round(cl, dl, el, al, bl, x[6], K[2], R[2], f3);
        round(bl, cl, dl, el, al, x[13], K[2], R[2], f3);
        round(al, bl, cl, dl, el, x[11], K[2], R[2], f3);
        round(el, al, bl, cl, dl, x[5], K[2], R[2], f3);
        round(dl, el, al, bl, cl, x[12], K[2], R[2], f3);

        // Round 4 (left)
        round(cl, dl, el, al, bl, x[1], K[3], R[3], f4);
        round(bl, cl, dl, el, al, x[9], K[3], R[3], f4);
        round(al, bl, cl, dl, el, x[11], K[3], R[3], f4);
        round(el, al, bl, cl, dl, x[10], K[3], R[3], f4);
        round(dl, el, al, bl, cl, x[0], K[3], R[3], f4);
        round(cl, dl, el, al, bl, x[8], K[3], R[3], f4);
        round(bl, cl, dl, el, al, x[12], K[3], R[3], f4);
        round(al, bl, cl, dl, el, x[4], K[3], R[3], f4);
        round(el, al, bl, cl, dl, x[13], K[3], R[3], f4);
        round(dl, el, al, bl, cl, x[3], K[3], R[3], f4);
        round(cl, dl, el, al, bl, x[7], K[3], R[3], f4);
        round(bl, cl, dl, el, al, x[15], K[3], R[3], f4);
        round(al, bl, cl, dl, el, x[14], K[3], R[3], f4);
        round(el, al, bl, cl, dl, x[5], K[3], R[3], f4);
        round(dl, el, al, bl, cl, x[6], K[3], R[3], f4);
        round(cl, dl, el, al, bl, x[2], K[3], R[3], f4);

        // Round 5 (left)
        round(bl, cl, dl, el, al, x[4], K[4], R[4], f5);
        round(al, bl, cl, dl, el, x[0], K[4], R[4], f5);
        round(el, al, bl, cl, dl, x[5], K[4], R[4], f5);
        round(dl, el, al, bl, cl, x[9], K[4], R[4], f5);
        round(cl, dl, el, al, bl, x[7], K[4], R[4], f5);
        round(bl, cl, dl, el, al, x[12], K[4], R[4], f5);
        round(al, bl, cl, dl, el, x[2], K[4], R[4], f5);
        round(el, al, bl, cl, dl, x[10], K[4], R[4], f5);
        round(dl, el, al, bl, cl, x[14], K[4], R[4], f5);
        round(cl, dl, el, al, bl, x[1], K[4], R[4], f5);
        round(bl, cl, dl, el, al, x[3], K[4], R[4], f5);
        round(al, bl, cl, dl, el, x[8], K[4], R[4], f5);
        round(el, al, bl, cl, dl, x[11], K[4], R[4], f5);
        round(dl, el, al, bl, cl, x[6], K[4], R[4], f5);
        round(cl, dl, el, al, bl, x[15], K[4], R[4], f5);
        round(bl, cl, dl, el, al, x[13], K[4], R[4], f5);

        // Parallel rounds (right line)
        // Round 1 (right)
        roundp(ar, br, cr, dr, er, x[5], Kp[0], Rp[0], f5);
        roundp(er, ar, br, cr, dr, x[14], Kp[0], Rp[0], f5);
        roundp(dr, er, ar, br, cr, x[7], Kp[0], Rp[0], f5);
        roundp(cr, dr, er, ar, br, x[0], Kp[0], Rp[0], f5);
        roundp(br, cr, dr, er, ar, x[9], Kp[0], Rp[0], f5);
        roundp(ar, br, cr, dr, er, x[2], Kp[0], Rp[0], f5);
        roundp(er, ar, br, cr, dr, x[11], Kp[0], Rp[0], f5);
        roundp(dr, er, ar, br, cr, x[4], Kp[0], Rp[0], f5);
        roundp(cr, dr, er, ar, br, x[13], Kp[0], Rp[0], f5);
        roundp(br, cr, dr, er, ar, x[6], Kp[0], Rp[0], f5);
        roundp(ar, br, cr, dr, er, x[15], Kp[0], Rp[0], f5);
        roundp(er, ar, br, cr, dr, x[8], Kp[0], Rp[0], f5);
        roundp(dr, er, ar, br, cr, x[1], Kp[0], Rp[0], f5);
        roundp(cr, dr, er, ar, br, x[10], Kp[0], Rp[0], f5);
        roundp(br, cr, dr, er, ar, x[3], Kp[0], Rp[0], f5);
        roundp(ar, br, cr, dr, er, x[12], Kp[0], Rp[0], f5);

        // Round 2 (right)
        roundp(er, ar, br, cr, dr, x[6], Kp[1], Rp[1], f4);
        roundp(dr, er, ar, br, cr, x[11], Kp[1], Rp[1], f4);
        roundp(cr, dr, er, ar, br, x[3], Kp[1], Rp[1], f4);
        roundp(br, cr, dr, er, ar, x[7], Kp[1], Rp[1], f4);
        roundp(ar, br, cr, dr, er, x[0], Kp[1], Rp[1], f4);
        roundp(er, ar, br, cr, dr, x[13], Kp[1], Rp[1], f4);
        roundp(dr, er, ar, br, cr, x[5], Kp[1], Rp[1], f4);
        roundp(cr, dr, er, ar, br, x[10], Kp[1], Rp[1], f4);
        roundp(br, cr, dr, er, ar, x[14], Kp[1], Rp[1], f4);
        roundp(ar, br, cr, dr, er, x[15], Kp[1], Rp[1], f4);
        roundp(er, ar, br, cr, dr, x[8], Kp[1], Rp[1], f4);
        roundp(dr, er, ar, br, cr, x[12], Kp[1], Rp[1], f4);
        roundp(cr, dr, er, ar, br, x[4], Kp[1], Rp[1], f4);
        roundp(br, cr, dr, er, ar, x[9], Kp[1], Rp[1], f4);
        roundp(ar, br, cr, dr, er, x[1], Kp[1], Rp[1], f4);
        roundp(er, ar, br, cr, dr, x[2], Kp[1], Rp[1], f4);

        // Round 3 (right)
        roundp(dr, er, ar, br, cr, x[15], Kp[2], Rp[2], f3);
        roundp(cr, dr, er, ar, br, x[5], Kp[2], Rp[2], f3);
        roundp(br, cr, dr, er, ar, x[1], Kp[2], Rp[2], f3);
        roundp(ar, br, cr, dr, er, x[3], Kp[2], Rp[2], f3);
        roundp(er, ar, br, cr, dr, x[7], Kp[2], Rp[2], f3);
        roundp(dr, er, ar, br, cr, x[14], Kp[2], Rp[2], f3);
        roundp(cr, dr, er, ar, br, x[6], Kp[2], Rp[2], f3);
        roundp(br, cr, dr, er, ar, x[9], Kp[2], Rp[2], f3);
        roundp(ar, br, cr, dr, er, x[11], Kp[2], Rp[2], f3);
        roundp(er, ar, br, cr, dr, x[8], Kp[2], Rp[2], f3);
        roundp(dr, er, ar, br, cr, x[12], Kp[2], Rp[2], f3);
        roundp(cr, dr, er, ar, br, x[2], Kp[2], Rp[2], f3);
        roundp(br, cr, dr, er, ar, x[10], Kp[2], Rp[2], f3);
        roundp(ar, br, cr, dr, er, x[0], Kp[2], Rp[2], f3);
        roundp(er, ar, br, cr, dr, x[4], Kp[2], Rp[2], f3);
        roundp(dr, er, ar, br, cr, x[13], Kp[2], Rp[2], f3);

        // Round 4 (right)
        roundp(cr, dr, er, ar, br, x[8], Kp[3], Rp[3], f2);
        roundp(br, cr, dr, er, ar, x[6], Kp[3], Rp[3], f2);
        roundp(ar, br, cr, dr, er, x[4], Kp[3], Rp[3], f2);
        roundp(er, ar, br, cr, dr, x[1], Kp[3], Rp[3], f2);
        roundp(dr, er, ar, br, cr, x[3], Kp[3], Rp[3], f2);
        roundp(cr, dr, er, ar, br, x[11], Kp[3], Rp[3], f2);
        roundp(br, cr, dr, er, ar, x[15], Kp[3], Rp[3], f2);
        roundp(ar, br, cr, dr, er, x[0], Kp[3], Rp[3], f2);
        roundp(er, ar, br, cr, dr, x[5], Kp[3], Rp[3], f2);
        roundp(dr, er, ar, br, cr, x[12], Kp[3], Rp[3], f2);
        roundp(cr, dr, er, ar, br, x[2], Kp[3], Rp[3], f2);
        roundp(br, cr, dr, er, ar, x[13], Kp[3], Rp[3], f2);
        roundp(ar, br, cr, dr, er, x[9], Kp[3], Rp[3], f2);
        roundp(er, ar, br, cr, dr, x[7], Kp[3], Rp[3], f2);
        roundp(dr, er, ar, br, cr, x[10], Kp[3], Rp[3], f2);
        roundp(cr, dr, er, ar, br, x[14], Kp[3], Rp[3], f2);

        // Round 5 (right)
        roundp(br, cr, dr, er, ar, x[12], Kp[4], Rp[4], f1);
        roundp(ar, br, cr, dr, er, x[15], Kp[4], Rp[4], f1);
        roundp(er, ar, br, cr, dr, x[10], Kp[4], Rp[4], f1);
        roundp(dr, er, ar, br, cr, x[4], Kp[4], Rp[4], f1);
        roundp(cr, dr, er, ar, br, x[1], Kp[4], Rp[4], f1);
        roundp(br, cr, dr, er, ar, x[5], Kp[4], Rp[4], f1);
        roundp(ar, br, cr, dr, er, x[8], Kp[4], Rp[4], f1);
        roundp(er, ar, br, cr, dr, x[7], Kp[4], Rp[4], f1);
        roundp(dr, er, ar, br, cr, x[6], Kp[4], Rp[4], f1);
        roundp(cr, dr, er, ar, br, x[2], Kp[4], Rp[4], f1);
        roundp(br, cr, dr, er, ar, x[13], Kp[4], Rp[4], f1);
        roundp(ar, br, cr, dr, er, x[14], Kp[4], Rp[4], f1);
        roundp(er, ar, br, cr, dr, x[0], Kp[4], Rp[4], f1);
        roundp(dr, er, ar, br, cr, x[3], Kp[4], Rp[4], f1);
        roundp(cr, dr, er, ar, br, x[9], Kp[4], Rp[4], f1);
        roundp(br, cr, dr, er, ar, x[11], Kp[4], Rp[4], f1);

        // Combine results
        temp = h[1] + cl + dr;
        h[1] = h[2] + dl + er;
        h[2] = h[3] + el + ar;
        h[3] = h[4] + al + br;
        h[4] = h[0] + bl + cr;
        h[0] = temp;
    }

    void RIPEMD160::write(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len; i++) {
            buffer[bufferPos++] = data[i];
            if (bufferPos == RIPEMD160_BLOCK_SIZE) {
                transform(buffer);
                bitCount += RIPEMD160_BLOCK_SIZE * 8;
                bufferPos = 0;
            }
        }
    }

    void RIPEMD160::update(const uint8_t* data, size_t len) {
        if (data && len > 0) {
            write(data, len);
        }
    }

    void RIPEMD160::update(const std::string& str) {
        update(reinterpret_cast<const uint8_t*>(str.c_str()), str.length());
    }

    void RIPEMD160::update(const std::vector<uint8_t>& data) {
        if (!data.empty()) {
            update(data.data(), data.size());
        }
    }

    void RIPEMD160::pad() {
        uint8_t padding[RIPEMD160_BLOCK_SIZE + 8];
        size_t padLen;

        padding[0] = 0x80;
        for (size_t i = 1; i < sizeof(padding); i++) {
            padding[i] = 0;
        }

        padLen = (bufferPos < 56) ? (56 - bufferPos) : (120 - bufferPos);
        write(padding, padLen);

        // Append length in bits (little-endian)
        uint64_t bitCountLE = bitCount;
        write(reinterpret_cast<uint8_t*>(&bitCountLE), 8);
    }

    void RIPEMD160::finalize(uint8_t* hash) {
        pad();

        // Copy hash to output (little-endian)
        for (int i = 0; i < 5; i++) {
            hash[i * 4] = h[i] & 0xff;
            hash[i * 4 + 1] = (h[i] >> 8) & 0xff;
            hash[i * 4 + 2] = (h[i] >> 16) & 0xff;
            hash[i * 4 + 3] = (h[i] >> 24) & 0xff;
        }

        reset();
    }

    std::vector<uint8_t> RIPEMD160::finalize() {
        std::vector<uint8_t> hash(RIPEMD160_HASH_SIZE);
        finalize(hash.data());
        return hash;
    }

    std::string RIPEMD160::finalizeHex() {
        auto hash = finalize();
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (auto byte : hash) {
            ss << std::setw(2) << static_cast<int>(byte);
        }
        return ss.str();
    }

    std::vector<uint8_t> RIPEMD160::hash(const uint8_t* data, size_t len) {
        RIPEMD160 ripemd;
        ripemd.update(data, len);
        return ripemd.finalize();
    }

    std::string RIPEMD160::hash(const std::string& str) {
        RIPEMD160 ripemd;
        ripemd.update(str);
        return ripemd.finalizeHex();
    }

    std::string RIPEMD160::hash(const std::vector<uint8_t>& data) {
        RIPEMD160 ripemd;
        ripemd.update(data);
        return ripemd.finalizeHex();
    }

    std::vector<uint8_t> RIPEMD160::hash160(const uint8_t* data, size_t len) {
        auto sha256Hash = SHA256::hash(data, len);
        return hash(sha256Hash.data(), sha256Hash.size());
    }

    std::string RIPEMD160::hash160(const std::string& str) {
        auto sha256Hash = SHA256::hash(str);
        return hash(sha256Hash);
    }

    std::string RIPEMD160::hash160(const std::vector<uint8_t>& data) {
        auto sha256Hash = SHA256::hash(data);
        return hash(sha256Hash);
    }

    std::vector<uint8_t> RIPEMD160::doubleHash(const uint8_t* data, size_t len) {
        auto first = hash(data, len);
        return hash(first.data(), first.size());
    }

    std::string RIPEMD160::doubleHash(const std::string& str) {
        auto first = hash(str);
        return hash(first);
    }

    bool RIPEMD160::verify(const uint8_t* hash, const uint8_t* expected) {
        return memcmp(hash, expected, RIPEMD160_HASH_SIZE) == 0;
    }

    int RIPEMD160::compare(const uint8_t* a, const uint8_t* b) {
        for (int i = 0; i < RIPEMD160_HASH_SIZE; i++) {
            if (a[i] < b[i]) return -1;
            if (a[i] > b[i]) return 1;
        }
        return 0;
    }

    bool RIPEMD160::isZero(const uint8_t* hash) {
        for (int i = 0; i < RIPEMD160_HASH_SIZE; i++) {
            if (hash[i] != 0) return false;
        }
        return true;
    }

    std::string RIPEMD160::toHex(const uint8_t* hash) {
        std::stringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < RIPEMD160_HASH_SIZE; i++) {
            ss << std::setw(2) << static_cast<int>(hash[i]);
        }
        return ss.str();
    }

    std::vector<uint8_t> RIPEMD160::fromHex(const std::string& hex) {
        if (hex.length() != RIPEMD160_HASH_SIZE * 2) {
            throw std::invalid_argument("Invalid hex length for RIPEMD-160 hash");
        }

        std::vector<uint8_t> bytes(RIPEMD160_HASH_SIZE);
        for (size_t i = 0; i < RIPEMD160_HASH_SIZE; i++) {
            std::string byteStr = hex.substr(i * 2, 2);
            bytes[i] = static_cast<uint8_t>(std::stoul(byteStr, nullptr, 16));
        }
        return bytes;
    }

    // ============== RIPEMD160HashObject Implementation ==============

    RIPEMD160HashObject::RIPEMD160HashObject() : finalized(false) {
        hash.fill(0);
    }

    RIPEMD160HashObject::~RIPEMD160HashObject() = default;

    void RIPEMD160HashObject::update(const uint8_t* data, size_t len) {
        if (!finalized) {
            context.update(data, len);
        }
    }

    void RIPEMD160HashObject::update(const std::string& str) {
        if (!finalized) {
            context.update(str);
        }
    }

    const uint8_t* RIPEMD160HashObject::finalize() {
        if (!finalized) {
            auto result = context.finalize();
            memcpy(hash.data(), result.data(), RIPEMD160_HASH_SIZE);
            finalized = true;
        }
        return hash.data();
    }

    const std::array<uint8_t, RIPEMD160_HASH_SIZE>& RIPEMD160HashObject::getHash() const {
        if (!finalized) {
            throw std::runtime_error("Hash not finalized");
        }
        return hash;
    }

    std::string RIPEMD160HashObject::getHex() const {
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

    void RIPEMD160HashObject::reset() {
        context.reset();
        finalized = false;
        hash.fill(0);
    }

} // namespace powercoin