#include "sha256.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <iostream>  // ✅ Add this

namespace PowerCoin {
    
    const uint32_t SHA256::SHA256_K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    
    SHA256::SHA256() {
        reset();  // ✅ Now this will work
    }
    
    // ✅ Add reset implementation
    void SHA256::reset() {
        h[0] = 0x6a09e667;
        h[1] = 0xbb67ae85;
        h[2] = 0x3c6ef372;
        h[3] = 0xa54ff53a;
        h[4] = 0x510e527f;
        h[5] = 0x9b05688c;
        h[6] = 0x1f83d9ab;
        h[7] = 0x5be0cd19;
        
        data_len = 0;
        buffer.clear();
    }
    
    void SHA256::transform(const uint8_t* chunk) {
        uint32_t w[64];
        
        for (int i = 0; i < 16; i++) {
            w[i] = (chunk[i*4] << 24) | (chunk[i*4 + 1] << 16) | 
                   (chunk[i*4 + 2] << 8) | (chunk[i*4 + 3]);
        }
        
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = ((w[i-15] >> 7) | (w[i-15] << 25)) ^
                          ((w[i-15] >> 18) | (w[i-15] << 14)) ^
                          (w[i-15] >> 3);
            uint32_t s1 = ((w[i-2] >> 17) | (w[i-2] << 15)) ^
                          ((w[i-2] >> 19) | (w[i-2] << 13)) ^
                          (w[i-2] >> 10);
            w[i] = w[i-16] + s0 + w[i-7] + s1;
        }
        
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        uint32_t e = h[4], f = h[5], g = h[6], h_val = h[7];
        
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = ((e >> 6) | (e << 26)) ^
                         ((e >> 11) | (e << 21)) ^
                         ((e >> 25) | (e << 7));
            uint32_t ch = (e & f) ^ ((~e) & g);
            uint32_t temp1 = h_val + S1 + ch + SHA256_K[i] + w[i];
            uint32_t S0 = ((a >> 2) | (a << 30)) ^
                         ((a >> 13) | (a << 19)) ^
                         ((a >> 22) | (a << 10));
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;
            
            h_val = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        
        h[0] += a;
        h[1] += b;
        h[2] += c;
        h[3] += d;
        h[4] += e;
        h[5] += f;
        h[6] += g;
        h[7] += h_val;
    }
    
    void SHA256::update(const std::vector<uint8_t>& data) {
        for (auto byte : data) {
            buffer.push_back(byte);
            if (buffer.size() == 64) {
                transform(buffer.data());
                buffer.clear();
            }
        }
        data_len += data.size();
    }
    
    void SHA256::update(const std::string& data) {
        std::vector<uint8_t> vec(data.begin(), data.end());
        update(vec);
    }
    
    std::vector<uint8_t> SHA256::finalize() {
        uint64_t bit_len = data_len * 8;
        buffer.push_back(0x80);
        
        while (buffer.size() != 56) {
            if (buffer.size() == 64) {
                transform(buffer.data());
                buffer.clear();
            }
            buffer.push_back(0x00);
        }
        
        for (int i = 7; i >= 0; i--) {
            buffer.push_back((bit_len >> (i * 8)) & 0xFF);
        }
        transform(buffer.data());
        
        std::vector<uint8_t> hash(32);
        for (int i = 0; i < 8; i++) {
            for (int j = 3; j >= 0; j--) {
                hash[i*4 + (3-j)] = (h[i] >> (j*8)) & 0xFF;
            }
        }
        
        return hash;
    }
    
    std::string SHA256::hash(const std::string& input) {
        SHA256 sha;
        sha.update(input);
        auto hash_bytes = sha.finalize();
        
        std::stringstream ss;
        for (auto byte : hash_bytes) {
            ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
        }
        return ss.str();
    }
    
    std::string SHA256::doubleHash(const std::string& input) {
        return hash(hash(input));
    }
    
}