#ifndef POWERCOIN_BASE58_H
#define POWERCOIN_BASE58_H

#include <string>
#include <vector>
#include <cstdint>
#include <array>

namespace powercoin {

    /**
     * Base58 alphabet (Bitcoin-style)
     * Removes ambiguous characters: 0OIl
     */
    constexpr const char* BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /**
     * Base58Check version bytes
     */
    enum class Base58Version : uint8_t {
        PUBKEY_ADDRESS = 0x00,      // Starts with 1
        SCRIPT_ADDRESS = 0x05,      // Starts with 3
        PRIVATE_KEY = 0x80,         // Starts with 5 or K/L
        EXT_PUBLIC_KEY = 0x0488B21E, // xpub
        EXT_PRIVATE_KEY = 0x0488ADE4 // xprv
    };

    /**
     * Base58 encoding/decoding utilities
     * Bitcoin-compatible with Base58Check
     */
    class Base58 {
    private:
        static const char* ALPHABET;
        static const int8_t TABLE[128];

        /**
         * Calculate double SHA-256 checksum
         * @param data Input data
         * @return First 4 bytes of double SHA-256
         */
        static std::array<uint8_t, 4> calculateChecksum(const std::vector<uint8_t>& data);

        /**
         * Convert byte vector to multi-precision integer
         * @param data Input bytes
         * @return Multi-precision integer as vector of base58 digits
         */
        static std::vector<uint8_t> toBase58(const std::vector<uint8_t>& data);

        /**
         * Convert base58 digits to byte vector
         * @param digits Base58 digits
         * @return Decoded bytes
         */
        static std::vector<uint8_t> fromBase58(const std::vector<uint8_t>& digits);

    public:
        /**
         * Encode bytes to Base58
         * @param data Input bytes
         * @return Base58 encoded string
         */
        static std::string encode(const std::vector<uint8_t>& data);

        /**
         * Encode string to Base58
         * @param str Input string
         * @return Base58 encoded string
         */
        static std::string encode(const std::string& str);

        /**
         * Decode Base58 string to bytes
         * @param str Base58 encoded string
         * @return Decoded bytes
         * @throws std::invalid_argument if invalid Base58 string
         */
        static std::vector<uint8_t> decode(const std::string& str);

        /**
         * Check if string is valid Base58
         * @param str String to check
         * @return true if all characters are in Base58 alphabet
         */
        static bool isValid(const std::string& str);

        /**
         * Base58Check encode (with version byte and checksum)
         * Used for Bitcoin addresses and private keys
         * @param data Input data
         * @param version Version byte
         * @return Base58Check encoded string
         */
        static std::string encodeCheck(const std::vector<uint8_t>& data, Base58Version version);

        /**
         * Base58Check encode with custom version byte
         * @param data Input data
         * @param version Version byte
         * @return Base58Check encoded string
         */
        static std::string encodeCheck(const std::vector<uint8_t>& data, uint8_t version);

        /**
         * Base58Check encode with 4-byte version
         * @param data Input data
         * @param version 4-byte version (for xpub/xprv)
         * @return Base58Check encoded string
         */
        static std::string encodeCheck(const std::vector<uint8_t>& data, uint32_t version);

        /**
         * Base58Check decode (verifies checksum)
         * @param str Base58Check encoded string
         * @return Decoded bytes (including version)
         * @throws std::invalid_argument if invalid checksum
         */
        static std::vector<uint8_t> decodeCheck(const std::string& str);

        /**
         * Base58Check decode and extract version
         * @param str Base58Check encoded string
         * @param version Output version byte
         * @return Decoded data (without version)
         * @throws std::invalid_argument if invalid checksum
         */
        static std::vector<uint8_t> decodeCheck(const std::string& str, uint8_t& version);

        /**
         * Base58Check decode for 4-byte versions
         * @param str Base58Check encoded string
         * @param version Output 4-byte version
         * @return Decoded data (without version)
         * @throws std::invalid_argument if invalid checksum
         */
        static std::vector<uint8_t> decodeCheck(const std::string& str, uint32_t& version);

        /**
         * Encode public key hash to Bitcoin address
         * @param hash160 20-byte hash160 of public key
         * @return Bitcoin address (starts with 1)
         */
        static std::string encodeAddress(const std::vector<uint8_t>& hash160);

        /**
         * Encode script hash to P2SH address
         * @param hash160 20-byte hash160 of script
         * @return P2SH address (starts with 3)
         */
        static std::string encodeScriptAddress(const std::vector<uint8_t>& hash160);

        /**
         * Encode private key to WIF (Wallet Import Format)
         * @param privateKey 32-byte private key
         * @param compressed Whether public key is compressed
         * @return WIF string
         */
        static std::string encodePrivateKey(const std::vector<uint8_t>& privateKey, bool compressed = true);

        /**
         * Decode WIF to private key
         * @param wif WIF string
         * @param compressed Output whether public key is compressed
         * @return 32-byte private key
         * @throws std::invalid_argument if invalid WIF
         */
        static std::vector<uint8_t> decodePrivateKey(const std::string& wif, bool& compressed);

        /**
         * Encode extended public key (xpub)
         * @param data Extended public key data (78 bytes)
         * @return xpub string
         */
        static std::string encodeExtendedPubKey(const std::vector<uint8_t>& data);

        /**
         * Encode extended private key (xprv)
         * @param data Extended private key data (78 bytes)
         * @return xprv string
         */
        static std::string encodeExtendedPrivKey(const std::vector<uint8_t>& data);

        /**
         * Decode extended key (xpub/xprv)
         * @param str Extended key string
         * @param version Output version (4 bytes)
         * @return Extended key data (78 bytes)
         * @throws std::invalid_argument if invalid extended key
         */
        static std::vector<uint8_t> decodeExtendedKey(const std::string& str, uint32_t& version);

        /**
         * Validate Bitcoin address
         * @param address Address to validate
         * @return true if valid address
         */
        static bool validateAddress(const std::string& address);

        /**
         * Validate WIF private key
         * @param wif WIF to validate
         * @return true if valid WIF
         */
        static bool validatePrivateKey(const std::string& wif);

        /**
         * Get address version from address
         * @param address Bitcoin address
         * @return Version byte (0x00 for mainnet, 0x6f for testnet)
         * @throws std::invalid_argument if invalid address
         */
        static uint8_t getAddressVersion(const std::string& address);

        /**
         * Convert address to hash160
         * @param address Bitcoin address
         * @return 20-byte hash160
         * @throws std::invalid_argument if invalid address
         */
        static std::vector<uint8_t> addressToHash160(const std::string& address);

        /**
         * Check if address is P2SH (starts with 3)
         * @param address Bitcoin address
         * @return true if P2SH address
         */
        static bool isP2SHAddress(const std::string& address);

        /**
         * Check if address is P2PKH (starts with 1)
         * @param address Bitcoin address
         * @return true if P2PKH address
         */
        static bool isP2PKHAddress(const std::string& address);

        /**
         * Check if string is valid extended key (xpub/xprv)
         * @param str String to check
         * @return true if valid extended key
         */
        static bool isValidExtendedKey(const std::string& str);

        /**
         * Get extended key type
         * @param str Extended key string
         * @return "xpub", "xprv", or empty if invalid
         */
        static std::string getExtendedKeyType(const std::string& str);

        /**
         * Encode number to Base58 (for small numbers)
         * @param num Number to encode
         * @return Base58 encoded string
         */
        static std::string encodeNumber(uint64_t num);

        /**
         * Decode Base58 to number
         * @param str Base58 encoded string
         * @return Decoded number
         * @throws std::invalid_argument if number too large
         */
        static uint64_t decodeNumber(const std::string& str);

        /**
         * Get Base58 character value
         * @param c Base58 character
         * @return Value (0-57) or -1 if invalid
         */
        static int8_t getCharValue(char c);

        /**
         * Check if character is valid in Base58
         * @param c Character to check
         * @return true if valid
         */
        static bool isValidChar(char c);

        /**
         * Get alphabet index
         * @return Base58 alphabet string
         */
        static const char* getAlphabet() { return ALPHABET; }

        /**
         * Get alphabet length
         * @return 58
         */
        static constexpr size_t getAlphabetLength() { return 58; }
    };

    /**
     * Base58Check encoder for building addresses
     */
    class Base58CheckEncoder {
    private:
        std::vector<uint8_t> data;

    public:
        Base58CheckEncoder() = default;

        /**
         * Add version byte
         * @param version Version byte
         * @return Reference to this encoder
         */
        Base58CheckEncoder& withVersion(uint8_t version);

        /**
         * Add 4-byte version
         * @param version 4-byte version
         * @return Reference to this encoder
         */
        Base58CheckEncoder& withVersion(uint32_t version);

        /**
         * Add payload data
         * @param payload Payload bytes
         * @return Reference to this encoder
         */
        Base58CheckEncoder& withPayload(const std::vector<uint8_t>& payload);

        /**
         * Add payload from string
         * @param payload Payload string
         * @return Reference to this encoder
         */
        Base58CheckEncoder& withPayload(const std::string& payload);

        /**
         * Build Base58Check encoded string
         * @return Encoded string
         */
        std::string build() const;

        /**
         * Clear encoder state
         */
        void clear();
    };

    /**
     * Base58Check decoder for parsing addresses
     */
    class Base58CheckDecoder {
    public:
        /**
         * Decode Base58Check string
         * @param str Encoded string
         * @param version Output version byte
         * @param payload Output payload
         * @return true if successful
         */
        static bool decode(const std::string& str, uint8_t& version, std::vector<uint8_t>& payload);

        /**
         * Decode Base58Check string with 4-byte version
         * @param str Encoded string
         * @param version Output 4-byte version
         * @param payload Output payload
         * @return true if successful
         */
        static bool decode(const std::string& str, uint32_t& version, std::vector<uint8_t>& payload);
    };

} // namespace powercoin

#endif // POWERCOIN_BASE58_H