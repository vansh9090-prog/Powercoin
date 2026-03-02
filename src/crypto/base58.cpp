#include "base58.h"
#include "sha256.h"
#include <cstring>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <stdexcept>

namespace powercoin {

    const char* Base58::ALPHABET = BASE58_ALPHABET;

    // Base58 decoding table
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

    std::array<uint8_t, 4> Base58::calculateChecksum(const std::vector<uint8_t>& data) {
        auto hash = SHA256::doubleHash(data.data(), data.size());
        std::array<uint8_t, 4> checksum;
        memcpy(checksum.data(), hash.data(), 4);
        return checksum;
    }

    std::vector<uint8_t> Base58::toBase58(const std::vector<uint8_t>& data) {
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

        // Add leading zeros as '1's
        std::vector<uint8_t> result;
        for (size_t i = 0; i < zeros; i++) {
            result.push_back(0);
        }

        // Reverse digits
        std::reverse_copy(digits.begin(), digits.end(), std::back_inserter(result));
        return result;
    }

    std::vector<uint8_t> Base58::fromBase58(const std::vector<uint8_t>& digits) {
        std::vector<uint8_t> result;

        for (uint8_t digit : digits) {
            int carry = digit;
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
        while (zeros < digits.size() && digits[zeros] == 0) {
            zeros++;
        }

        // Add leading zeros
        for (size_t i = 0; i < zeros; i++) {
            result.push_back(0);
        }

        std::reverse(result.begin(), result.end());
        return result;
    }

    std::string Base58::encode(const std::vector<uint8_t>& data) {
        auto digits = toBase58(data);
        std::string result;
        for (uint8_t digit : digits) {
            result += ALPHABET[digit];
        }
        return result;
    }

    std::string Base58::encode(const std::string& str) {
        std::vector<uint8_t> data(str.begin(), str.end());
        return encode(data);
    }

    std::vector<uint8_t> Base58::decode(const std::string& str) {
        if (!isValid(str)) {
            throw std::invalid_argument("Invalid Base58 string");
        }

        std::vector<uint8_t> digits;
        for (char c : str) {
            digits.push_back(TABLE[static_cast<uint8_t>(c)]);
        }

        return fromBase58(digits);
    }

    bool Base58::isValid(const std::string& str) {
        for (char c : str) {
            if (c < 0 || c >= 128 || TABLE[static_cast<uint8_t>(c)] == -1) {
                return false;
            }
        }
        return true;
    }

    std::string Base58::encodeCheck(const std::vector<uint8_t>& data, Base58Version version) {
        return encodeCheck(data, static_cast<uint8_t>(version));
    }

    std::string Base58::encodeCheck(const std::vector<uint8_t>& data, uint8_t version) {
        std::vector<uint8_t> extended;
        extended.push_back(version);
        extended.insert(extended.end(), data.begin(), data.end());

        auto checksum = calculateChecksum(extended);
        extended.insert(extended.end(), checksum.begin(), checksum.end());

        return encode(extended);
    }

    std::string Base58::encodeCheck(const std::vector<uint8_t>& data, uint32_t version) {
        std::vector<uint8_t> extended;
        extended.push_back((version >> 24) & 0xFF);
        extended.push_back((version >> 16) & 0xFF);
        extended.push_back((version >> 8) & 0xFF);
        extended.push_back(version & 0xFF);
        extended.insert(extended.end(), data.begin(), data.end());

        auto checksum = calculateChecksum(extended);
        extended.insert(extended.end(), checksum.begin(), checksum.end());

        return encode(extended);
    }

    std::vector<uint8_t> Base58::decodeCheck(const std::string& str) {
        auto decoded = decode(str);

        if (decoded.size() < 5) {
            throw std::invalid_argument("Base58Check string too short");
        }

        // Split into data and checksum
        std::vector<uint8_t> data(decoded.begin(), decoded.end() - 4);
        std::vector<uint8_t> checksum(decoded.end() - 4, decoded.end());

        // Verify checksum
        auto expectedChecksum = calculateChecksum(data);
        if (!std::equal(checksum.begin(), checksum.end(), expectedChecksum.begin())) {
            throw std::invalid_argument("Invalid Base58Check checksum");
        }

        return data;
    }

    std::vector<uint8_t> Base58::decodeCheck(const std::string& str, uint8_t& version) {
        auto data = decodeCheck(str);
        version = data[0];
        return std::vector<uint8_t>(data.begin() + 1, data.end());
    }

    std::vector<uint8_t> Base58::decodeCheck(const std::string& str, uint32_t& version) {
        auto data = decodeCheck(str);
        version = (static_cast<uint32_t>(data[0]) << 24) |
                  (static_cast<uint32_t>(data[1]) << 16) |
                  (static_cast<uint32_t>(data[2]) << 8) |
                  static_cast<uint32_t>(data[3]);
        return std::vector<uint8_t>(data.begin() + 4, data.end());
    }

    std::string Base58::encodeAddress(const std::vector<uint8_t>& hash160) {
        if (hash160.size() != 20) {
            throw std::invalid_argument("Hash160 must be 20 bytes");
        }
        return encodeCheck(hash160, Base58Version::PUBKEY_ADDRESS);
    }

    std::string Base58::encodeScriptAddress(const std::vector<uint8_t>& hash160) {
        if (hash160.size() != 20) {
            throw std::invalid_argument("Hash160 must be 20 bytes");
        }
        return encodeCheck(hash160, Base58Version::SCRIPT_ADDRESS);
    }

    std::string Base58::encodePrivateKey(const std::vector<uint8_t>& privateKey, bool compressed) {
        if (privateKey.size() != 32) {
            throw std::invalid_argument("Private key must be 32 bytes");
        }

        std::vector<uint8_t> data = privateKey;
        if (compressed) {
            data.push_back(0x01);
        }

        return encodeCheck(data, Base58Version::PRIVATE_KEY);
    }

    std::vector<uint8_t> Base58::decodePrivateKey(const std::string& wif, bool& compressed) {
        uint8_t version;
        auto data = decodeCheck(wif, version);

        if (version != static_cast<uint8_t>(Base58Version::PRIVATE_KEY)) {
            throw std::invalid_argument("Invalid private key version");
        }

        if (data.size() == 33 && data.back() == 0x01) {
            compressed = true;
            return std::vector<uint8_t>(data.begin(), data.end() - 1);
        } else if (data.size() == 32) {
            compressed = false;
            return data;
        } else {
            throw std::invalid_argument("Invalid private key length");
        }
    }

    std::string Base58::encodeExtendedPubKey(const std::vector<uint8_t>& data) {
        if (data.size() != 78) {
            throw std::invalid_argument("Extended public key must be 78 bytes");
        }
        return encodeCheck(data, 0x0488B21E); // xpub magic
    }

    std::string Base58::encodeExtendedPrivKey(const std::vector<uint8_t>& data) {
        if (data.size() != 78) {
            throw std::invalid_argument("Extended private key must be 78 bytes");
        }
        return encodeCheck(data, 0x0488ADE4); // xprv magic
    }

    std::vector<uint8_t> Base58::decodeExtendedKey(const std::string& str, uint32_t& version) {
        auto data = decodeCheck(str, version);
        if (data.size() != 78) {
            throw std::invalid_argument("Invalid extended key length");
        }
        return data;
    }

    bool Base58::validateAddress(const std::string& address) {
        try {
            uint8_t version;
            auto hash160 = decodeCheck(address, version);

            if (hash160.size() != 20) {
                return false;
            }

            if (version != static_cast<uint8_t>(Base58Version::PUBKEY_ADDRESS) &&
                version != static_cast<uint8_t>(Base58Version::SCRIPT_ADDRESS)) {
                return false;
            }

            return true;
        } catch (...) {
            return false;
        }
    }

    bool Base58::validatePrivateKey(const std::string& wif) {
        try {
            bool compressed;
            decodePrivateKey(wif, compressed);
            return true;
        } catch (...) {
            return false;
        }
    }

    uint8_t Base58::getAddressVersion(const std::string& address) {
        uint8_t version;
        decodeCheck(address, version);
        return version;
    }

    std::vector<uint8_t> Base58::addressToHash160(const std::string& address) {
        uint8_t version;
        auto hash160 = decodeCheck(address, version);
        return hash160;
    }

    bool Base58::isP2SHAddress(const std::string& address) {
        try {
            uint8_t version = getAddressVersion(address);
            return version == static_cast<uint8_t>(Base58Version::SCRIPT_ADDRESS);
        } catch (...) {
            return false;
        }
    }

    bool Base58::isP2PKHAddress(const std::string& address) {
        try {
            uint8_t version = getAddressVersion(address);
            return version == static_cast<uint8_t>(Base58Version::PUBKEY_ADDRESS);
        } catch (...) {
            return false;
        }
    }

    bool Base58::isValidExtendedKey(const std::string& str) {
        try {
            uint32_t version;
            decodeExtendedKey(str, version);
            return version == 0x0488B21E || version == 0x0488ADE4;
        } catch (...) {
            return false;
        }
    }

    std::string Base58::getExtendedKeyType(const std::string& str) {
        try {
            uint32_t version;
            decodeExtendedKey(str, version);
            if (version == 0x0488B21E) return "xpub";
            if (version == 0x0488ADE4) return "xprv";
            return "";
        } catch (...) {
            return "";
        }
    }

    std::string Base58::encodeNumber(uint64_t num) {
        std::vector<uint8_t> bytes;
        while (num > 0) {
            bytes.push_back(num & 0xFF);
            num >>= 8;
        }
        std::reverse(bytes.begin(), bytes.end());
        return encode(bytes);
    }

    uint64_t Base58::decodeNumber(const std::string& str) {
        auto bytes = decode(str);
        uint64_t num = 0;
        for (uint8_t byte : bytes) {
            num = (num << 8) | byte;
        }
        return num;
    }

    int8_t Base58::getCharValue(char c) {
        if (c < 0 || c >= 128) return -1;
        return TABLE[static_cast<uint8_t>(c)];
    }

    bool Base58::isValidChar(char c) {
        return c >= 0 && c < 128 && TABLE[static_cast<uint8_t>(c)] != -1;
    }

    // ============== Base58CheckEncoder Implementation ==============

    Base58CheckEncoder& Base58CheckEncoder::withVersion(uint8_t version) {
        data.push_back(version);
        return *this;
    }

    Base58CheckEncoder& Base58CheckEncoder::withVersion(uint32_t version) {
        data.push_back((version >> 24) & 0xFF);
        data.push_back((version >> 16) & 0xFF);
        data.push_back((version >> 8) & 0xFF);
        data.push_back(version & 0xFF);
        return *this;
    }

    Base58CheckEncoder& Base58CheckEncoder::withPayload(const std::vector<uint8_t>& payload) {
        data.insert(data.end(), payload.begin(), payload.end());
        return *this;
    }

    Base58CheckEncoder& Base58CheckEncoder::withPayload(const std::string& payload) {
        data.insert(data.end(), payload.begin(), payload.end());
        return *this;
    }

    std::string Base58CheckEncoder::build() const {
        auto checksum = Base58::calculateChecksum(data);
        std::vector<uint8_t> extended = data;
        extended.insert(extended.end(), checksum.begin(), checksum.end());
        return Base58::encode(extended);
    }

    void Base58CheckEncoder::clear() {
        data.clear();
    }

    // ============== Base58CheckDecoder Implementation ==============

    bool Base58CheckDecoder::decode(const std::string& str, uint8_t& version,
                                    std::vector<uint8_t>& payload) {
        try {
            auto data = Base58::decodeCheck(str, version);
            payload = data;
            return true;
        } catch (...) {
            return false;
        }
    }

    bool Base58CheckDecoder::decode(const std::string& str, uint32_t& version,
                                    std::vector<uint8_t>& payload) {
        try {
            auto data = Base58::decodeCheck(str, version);
            payload = data;
            return true;
        } catch (...) {
            return false;
        }
    }

} // namespace powercoin