#include "base58.h"
#include "sha256.h"
#include <cstring>
#include <algorithm>

namespace PowerCoin {
    
    const char* Base58::ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    const int8_t Base58::TABLE[128] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, -1, -1, -1, -1, -1, -1,
        -1, 9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
        22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
        -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
        47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1
    };
    
    std::string Base58::encode(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> digits;
        digits.push_back(0);
        
        for (uint8_t byte : data) {
            int carry = byte;
            for (size_t j = 0; j < digits.size(); j++) {
                carry += digits[j] << 8;
                digits[j] = carry % 58;
                carry /= 58;
            }
            
            while (carry > 0) {
                digits.push_back(carry % 58);
                carry /= 58;
            }
        }
        
        // Count leading zeros
        size_t zeros = 0;
        while (zeros < data.size() && data[zeros] == 0) {
            zeros++;
        }
        
        // Encode
        std::string result;
        for (size_t i = 0; i < zeros; i++) {
            result += ALPHABET[0];
        }
        
        for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
            result += ALPHABET[*it];
        }
        
        return result;
    }
    
    std::vector<uint8_t> Base58::decode(const std::string& str) {
        std::vector<uint8_t> result;
        
        for (char c : str) {
            if (c < 0 || c >= 128 || TABLE[c] == -1) {
                return {}; // Invalid character
            }
            
            int carry = TABLE[c];
            for (size_t j = 0; j < result.size(); j++) {
                carry += result[j] * 58;
                result[j] = carry & 0xFF;
                carry >>= 8;
            }
            
            while (carry > 0) {
                result.push_back(carry & 0xFF);
                carry >>= 8;
            }
        }
        
        // Count leading zeros
        size_t zeros = 0;
        while (zeros < str.size() && str[zeros] == ALPHABET[0]) {
            zeros++;
        }
        
        // Add leading zeros
        for (size_t i = 0; i < zeros; i++) {
            result.push_back(0);
        }
        
        std::reverse(result.begin(), result.end());
        return result;
    }
    
    std::string Base58::encodeCheck(const std::vector<uint8_t>& data) {
        // Calculate checksum (first 4 bytes of double SHA256)
        std::string dataStr(data.begin(), data.end());
        std::string hash = SHA256::doubleHash(dataStr);
        
        std::vector<uint8_t> extended = data;
        for (int i = 0; i < 4; i++) {
            extended.push_back(static_cast<uint8_t>(hash[i]));
        }
        
        return encode(extended);
    }
    
    std::vector<uint8_t> Base58::decodeCheck(const std::string& str) {
        std::vector<uint8_t> decoded = decode(str);
        
        if (decoded.size() < 4) {
            return {}; // Too short
        }
        
        // Split into data and checksum
        std::vector<uint8_t> data(decoded.begin(), decoded.end() - 4);
        std::vector<uint8_t> checksum(decoded.end() - 4, decoded.end());
        
        // Verify checksum
        std::string dataStr(data.begin(), data.end());
        std::string hash = SHA256::doubleHash(dataStr);
        
        for (int i = 0; i < 4; i++) {
            if (checksum[i] != static_cast<uint8_t>(hash[i])) {
                return {}; // Invalid checksum
            }
        }
        
        return data;
    }
    
    bool Base58::isValid(const std::string& str) {
        for (char c : str) {
            if (c < 0 || c >= 128 || TABLE[c] == -1) {
                return false;
            }
        }
        return true;
    }
    
}