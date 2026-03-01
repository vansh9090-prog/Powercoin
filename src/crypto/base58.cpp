#include "base58.h"
#include <algorithm>

namespace PowerCoin {
    
    const char* ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
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
        
        std::string result;
        for (auto it = digits.rbegin(); it != digits.rend(); ++it) {
            result += ALPHABET[*it];
        }
        return result;
    }
    
    std::vector<uint8_t> Base58::decode(const std::string& str) {
        std::vector<uint8_t> result;
        for (char c : str) {
            int val = 0;
            const char* pos = strchr(ALPHABET, c);
            if (!pos) return {};
            val = pos - ALPHABET;
            
            int carry = val;
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
        std::reverse(result.begin(), result.end());
        return result;
    }
    
}