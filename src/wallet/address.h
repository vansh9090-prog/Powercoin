#ifndef POWERCOIN_ADDRESS_H
#define POWERCOIN_ADDRESS_H

#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <memory>

namespace powercoin {

    /**
     * Address types supported by Power Coin
     */
    enum class AddressFormat {
        LEGACY,         // P2PKH (starts with 1)
        P2SH,           // Pay to Script Hash (starts with 3)
        BECH32,         // Native SegWit (starts with bc1)
        BECH32M,        // Taproot (starts with bc1p)
        P2PK,           // Pay to Public Key (rare)
        POWR            // Power Coin custom format
    };

    /**
     * Network type for address
     */
    enum class AddressNetwork {
        MAINNET,
        TESTNET,
        REGTEST,
        SIMNET
    };

    /**
     * Address validation result
     */
    struct AddressValidationResult {
        bool isValid;
        AddressFormat format;
        AddressNetwork network;
        std::string error;
        std::vector<uint8_t> hash160;
        std::string bech32;
        std::string legacy;
        
        AddressValidationResult();
        std::string toString() const;
    };

    /**
     * Address prefix bytes for different networks
     */
    struct AddressPrefixes {
        static constexpr uint8_t PUBKEY_ADDRESS_MAIN = 0x00;
        static constexpr uint8_t SCRIPT_ADDRESS_MAIN = 0x05;
        static constexpr uint8_t PUBKEY_ADDRESS_TEST = 0x6F;
        static constexpr uint8_t SCRIPT_ADDRESS_TEST = 0xC4;
        static constexpr uint8_t PUBKEY_ADDRESS_REGTEST = 0x6F;
        static constexpr uint8_t SCRIPT_ADDRESS_REGTEST = 0xC4;
        
        static constexpr const char* BECH32_HRP_MAIN = "bc";
        static constexpr const char* BECH32_HRP_TEST = "tb";
        static constexpr const char* BECH32_HRP_REGTEST = "bcrt";
        
        static constexpr const char* POWR_HRP_MAIN = "pw";
        static constexpr const char* POWR_HRP_TEST = "tpw";
    };

    /**
     * Main address class
     * Handles address generation, validation, and conversion
     */
    class Address {
    private:
        std::vector<uint8_t> hash160;
        std::vector<uint8_t> script;
        std::string bech32;
        std::string legacy;
        AddressFormat format;
        AddressNetwork network;
        
    public:
        /**
         * Constructor
         */
        Address();
        
        /**
         * Constructor from hash160
         * @param hash160 20-byte hash160
         * @param format Address format
         * @param network Network type
         */
        Address(const std::vector<uint8_t>& hash160, 
                AddressFormat format = AddressFormat::LEGACY,
                AddressNetwork network = AddressNetwork::MAINNET);
        
        /**
         * Constructor from public key
         * @param publicKey Public key bytes
         * @param format Address format
         * @param network Network type
         */
        Address(const std::vector<uint8_t>& publicKey,
                AddressFormat format = AddressFormat::LEGACY,
                AddressNetwork network = AddressNetwork::MAINNET);
        
        /**
         * Constructor from script
         * @param script Script bytes
         * @param format Address format
         * @param network Network type
         */
        Address(const std::vector<uint8_t>& script,
                AddressFormat format,
                AddressNetwork network = AddressNetwork::MAINNET);
        
        /**
         * Constructor from string
         * @param addressStr Address string
         */
        explicit Address(const std::string& addressStr);
        
        /**
         * Copy constructor
         */
        Address(const Address& other) = default;
        
        /**
         * Assignment operator
         */
        Address& operator=(const Address& other) = default;
        
        /**
         * Destructor
         */
        ~Address() = default;
        
        /**
         * Compare addresses
         * @param other Other address
         * @return true if equal
         */
        bool operator==(const Address& other) const;
        
        /**
         * Compare addresses
         * @param other Other address
         * @return true if not equal
         */
        bool operator!=(const Address& other) const;
        
        /**
         * Compare addresses (less than)
         * @param other Other address
         * @return true if this < other
         */
        bool operator<(const Address& other) const;
        
        /**
         * Get address in legacy format
         * @return Legacy address string
         */
        std::string toLegacy() const;
        
        /**
         * Get address in bech32 format
         * @return Bech32 address string
         */
        std::string toBech32() const;
        
        /**
         * Get address in P2SH format
         * @return P2SH address string
         */
        std::string toP2SH() const;
        
        /**
         * Get address in specified format
         * @param format Desired format
         * @return Address string
         */
        std::string toString(AddressFormat format) const;
        
        /**
         * Get address as string (default format)
         * @return Address string
         */
        std::string toString() const;
        
        /**
         * Get hash160
         * @return 20-byte hash160
         */
        const std::vector<uint8_t>& getHash160() const { return hash160; }
        
        /**
         * Get script (for P2SH/P2WSH)
         * @return Script bytes
         */
        const std::vector<uint8_t>& getScript() const { return script; }
        
        /**
         * Get address format
         * @return Format
         */
        AddressFormat getFormat() const { return format; }
        
        /**
         * Get network type
         * @return Network
         */
        AddressNetwork getNetwork() const { return network; }
        
        /**
         * Check if address is valid
         * @return true if valid
         */
        bool isValid() const;
        
        /**
         * Get validation result
         * @return Validation result
         */
        AddressValidationResult validate() const;
        
        /**
         * Static validation
         * @param address Address string
         * @return true if valid
         */
        static bool isValid(const std::string& address);
        
        /**
         * Static validation with details
         * @param address Address string
         * @return Validation result
         */
        static AddressValidationResult validate(const std::string& address);
        
        /**
         * Detect address format
         * @param address Address string
         * @return Detected format
         */
        static AddressFormat detectFormat(const std::string& address);
        
        /**
         * Detect network
         * @param address Address string
         * @return Detected network
         */
        static AddressNetwork detectNetwork(const std::string& address);
        
        /**
         * Extract hash160 from address
         * @param address Address string
         * @return 20-byte hash160 (empty if invalid)
         */
        static std::vector<uint8_t> extractHash160(const std::string& address);
        
        /**
         * Convert address between formats
         * @param address Source address
         * @param targetFormat Target format
         * @return Converted address
         */
        static std::string convertFormat(const std::string& address, 
                                         AddressFormat targetFormat);
        
        /**
         * Create address from public key
         * @param publicKey Public key bytes
         * @param format Address format
         * @param network Network type
         * @return Address string
         */
        static std::string fromPublicKey(const std::vector<uint8_t>& publicKey,
                                         AddressFormat format = AddressFormat::LEGACY,
                                         AddressNetwork network = AddressNetwork::MAINNET);
        
        /**
         * Create address from script
         * @param script Script bytes
         * @param format Address format
         * @param network Network type
         * @return Address string
         */
        static std::string fromScript(const std::vector<uint8_t>& script,
                                      AddressFormat format,
                                      AddressNetwork network = AddressNetwork::MAINNET);
        
        /**
         * Create P2PKH address from hash160
         * @param hash160 20-byte hash160
         * @param network Network type
         * @return Legacy address
         */
        static std::string fromHash160(const std::vector<uint8_t>& hash160,
                                       AddressNetwork network = AddressNetwork::MAINNET);
        
        /**
         * Create P2SH address from script hash
         * @param scriptHash 20-byte script hash
         * @param network Network type
         * @return P2SH address
         */
        static std::string fromScriptHash(const std::vector<uint8_t>& scriptHash,
                                          AddressNetwork network = AddressNetwork::MAINNET);
        
        /**
         * Create bech32 address from witness program
         * @param witnessVersion Witness version (0 for segwit, 1 for taproot)
         * @param witnessProgram Witness program bytes
         * @param network Network type
         * @return Bech32 address
         */
        static std::string fromWitnessProgram(uint8_t witnessVersion,
                                              const std::vector<uint8_t>& witnessProgram,
                                              AddressNetwork network = AddressNetwork::MAINNET);
        
        /**
         * Create P2WPKH address from public key
         * @param publicKey Public key bytes
         * @param network Network type
         * @return Bech32 address
         */
        static std::string fromPublicKeyWitness(const std::vector<uint8_t>& publicKey,
                                                AddressNetwork network = AddressNetwork::MAINNET);
        
        /**
         * Create P2WSH address from script
         * @param script Script bytes
         * @param network Network type
         * @return Bech32 address
         */
        static std::string fromScriptWitness(const std::vector<uint8_t>& script,
                                             AddressNetwork network = AddressNetwork::MAINNET);
        
        /**
         * Create P2TR (Taproot) address from public key
         * @param publicKey 32-byte x-only public key
         * @param network Network type
         * @return Bech32m address
         */
        static std::string fromTaprootKey(const std::vector<uint8_t>& publicKey,
                                          AddressNetwork network = AddressNetwork::MAINNET);
        
        /**
         * Get address type name
         * @param format Address format
         * @return Type name string
         */
        static std::string formatToString(AddressFormat format);
        
        /**
         * Get network name
         * @param network Network type
         * @return Network name string
         */
        static std::string networkToString(AddressNetwork network);
        
        /**
         * Get prefix for network and format
         * @param format Address format
         * @param network Network type
         * @return Prefix string/byte
         */
        static std::string getPrefix(AddressFormat format, AddressNetwork network);
    };

    /**
     * Address builder for fluent address creation
     */
    class AddressBuilder {
    private:
        std::vector<uint8_t> publicKey;
        std::vector<uint8_t> script;
        std::vector<uint8_t> hash160;
        AddressFormat format;
        AddressNetwork network;
        uint8_t witnessVersion;
        
    public:
        AddressBuilder();
        
        AddressBuilder& withPublicKey(const std::vector<uint8_t>& key);
        AddressBuilder& withScript(const std::vector<uint8_t>& scr);
        AddressBuilder& withHash160(const std::vector<uint8_t>& hash);
        AddressBuilder& withFormat(AddressFormat fmt);
        AddressBuilder& withNetwork(AddressNetwork net);
        AddressBuilder& withWitnessVersion(uint8_t version);
        
        std::string build() const;
        Address buildAddress() const;
    };

    /**
     * Bech32 encoder/decoder (BIP173)
     */
    class Bech32 {
    private:
        static const char* CHARSET;
        static const int8_t CHARSET_REV[128];
        
        static std::vector<uint8_t> polymod(const std::vector<uint8_t>& values);
        static bool verifyChecksum(const std::string& hrp, const std::vector<uint8_t>& data);
        static std::vector<uint8_t> createChecksum(const std::string& hrp, 
                                                    const std::vector<uint8_t>& data);
        
    public:
        static std::string encode(const std::string& hrp, const std::vector<uint8_t>& data);
        static std::pair<std::string, std::vector<uint8_t>> decode(const std::string& bech);
        static bool isValid(const std::string& bech);
    };

    /**
     * Bech32m encoder/decoder (BIP350) for Taproot
     */
    class Bech32m {
    private:
        static const char* CHARSET;
        static const int8_t CHARSET_REV[128];
        
        static std::vector<uint8_t> polymod(const std::vector<uint8_t>& values);
        static bool verifyChecksum(const std::string& hrp, const std::vector<uint8_t>& data);
        static std::vector<uint8_t> createChecksum(const std::string& hrp, 
                                                    const std::vector<uint8_t>& data);
        
    public:
        static std::string encode(const std::string& hrp, const std::vector<uint8_t>& data);
        static std::pair<std::string, std::vector<uint8_t>> decode(const std::string& bech);
        static bool isValid(const std::string& bech);
    };

} // namespace powercoin

#endif // POWERCOIN_ADDRESS_H