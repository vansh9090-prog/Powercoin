#include "address.h"
#include "../crypto/sha256.h"
#include "../crypto/ripemd160.h"
#include "../crypto/base58.h"
#include "../crypto/random.h"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace powercoin {

    // ============== Bech32 Implementation ==============

    const char* Bech32::CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const int8_t Bech32::CHARSET_REV[128] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
    };

    std::vector<uint8_t> Bech32::polymod(const std::vector<uint8_t>& values) {
        uint32_t chk = 1;
        for (uint8_t v : values) {
            uint8_t top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (size_t i = 0; i < 5; i++) {
                if ((top >> i) & 1) {
                    chk ^= (0x3b6a57b2UL >> (i * 5)) & 0x1ffffff;
                }
            }
        }
        return {static_cast<uint8_t>((chk >> 25) & 0x7f),
                static_cast<uint8_t>((chk >> 20) & 0x1f),
                static_cast<uint8_t>((chk >> 15) & 0x1f),
                static_cast<uint8_t>((chk >> 10) & 0x1f),
                static_cast<uint8_t>((chk >> 5) & 0x1f),
                static_cast<uint8_t>(chk & 0x1f)};
    }

    bool Bech32::verifyChecksum(const std::string& hrp, const std::vector<uint8_t>& data) {
        std::vector<uint8_t> values;
        for (char c : hrp) {
            values.push_back(static_cast<uint8_t>(c) >> 5);
        }
        values.push_back(0);
        for (char c : hrp) {
            values.push_back(static_cast<uint8_t>(c) & 0x1f);
        }
        values.insert(values.end(), data.begin(), data.end());
        auto poly = polymod(values);
        return poly[0] == 0;
    }

    std::vector<uint8_t> Bech32::createChecksum(const std::string& hrp, 
                                                 const std::vector<uint8_t>& data) {
        std::vector<uint8_t> values;
        for (char c : hrp) {
            values.push_back(static_cast<uint8_t>(c) >> 5);
        }
        values.push_back(0);
        for (char c : hrp) {
            values.push_back(static_cast<uint8_t>(c) & 0x1f);
        }
        values.insert(values.end(), data.begin(), data.end());
        values.resize(values.size() + 6, 0);
        auto poly = polymod(values);
        poly[0] ^= 1;
        return std::vector<uint8_t>(poly.begin() + 1, poly.end());
    }

    std::string Bech32::encode(const std::string& hrp, const std::vector<uint8_t>& data) {
        std::vector<uint8_t> combined = data;
        auto checksum = createChecksum(hrp, data);
        combined.insert(combined.end(), checksum.begin(), checksum.end());

        std::string result = hrp + '1';
        for (uint8_t v : combined) {
            if (v >= 32) return "";
            result += CHARSET[v];
        }
        return result;
    }

    std::pair<std::string, std::vector<uint8_t>> Bech32::decode(const std::string& bech) {
        if (bech.length() < 8 || bech.length() > 90) {
            return {"", {}};
        }

        bool hasLower = false, hasUpper = false;
        for (char c : bech) {
            if (c >= 'a' && c <= 'z') hasLower = true;
            if (c >= 'A' && c <= 'Z') hasUpper = true;
        }
        if (hasLower && hasUpper) return {"", {}};

        size_t pos = bech.rfind('1');
        if (pos == std::string::npos || pos == 0 || pos + 7 > bech.length()) {
            return {"", {}};
        }

        std::string hrp = bech.substr(0, pos);
        for (char c : hrp) {
            if (c < 33 || c > 126) return {"", {}};
        }

        std::vector<uint8_t> data;
        for (size_t i = pos + 1; i < bech.length(); i++) {
            char c = bech[i];
            if (c < 0 || c >= 128) return {"", {}};
            int8_t v = CHARSET_REV[static_cast<uint8_t>(c)];
            if (v == -1) return {"", {}};
            data.push_back(v);
        }

        if (!verifyChecksum(hrp, data)) {
            return {"", {}};
        }

        data.resize(data.size() - 6);
        return {hrp, data};
    }

    bool Bech32::isValid(const std::string& bech) {
        return !decode(bech).first.empty();
    }

    // ============== Bech32m Implementation ==============

    const char* Bech32m::CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    const int8_t Bech32m::CHARSET_REV[128] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
        -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
        1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
    };

    std::vector<uint8_t> Bech32m::polymod(const std::vector<uint8_t>& values) {
        uint32_t chk = 1;
        for (uint8_t v : values) {
            uint8_t top = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (size_t i = 0; i < 5; i++) {
                if ((top >> i) & 1) {
                    chk ^= (0x3b6a57b2UL >> (i * 5)) & 0x1ffffff;
                }
            }
        }
        return {static_cast<uint8_t>((chk >> 25) & 0x7f),
                static_cast<uint8_t>((chk >> 20) & 0x1f),
                static_cast<uint8_t>((chk >> 15) & 0x1f),
                static_cast<uint8_t>((chk >> 10) & 0x1f),
                static_cast<uint8_t>((chk >> 5) & 0x1f),
                static_cast<uint8_t>(chk & 0x1f)};
    }

    bool Bech32m::verifyChecksum(const std::string& hrp, const std::vector<uint8_t>& data) {
        std::vector<uint8_t> values;
        for (char c : hrp) {
            values.push_back(static_cast<uint8_t>(c) >> 5);
        }
        values.push_back(0);
        for (char c : hrp) {
            values.push_back(static_cast<uint8_t>(c) & 0x1f);
        }
        values.insert(values.end(), data.begin(), data.end());
        auto poly = polymod(values);
        return poly[0] == 0x2bc830a3 >> 25;
    }

    std::vector<uint8_t> Bech32m::createChecksum(const std::string& hrp, 
                                                  const std::vector<uint8_t>& data) {
        std::vector<uint8_t> values;
        for (char c : hrp) {
            values.push_back(static_cast<uint8_t>(c) >> 5);
        }
        values.push_back(0);
        for (char c : hrp) {
            values.push_back(static_cast<uint8_t>(c) & 0x1f);
        }
        values.insert(values.end(), data.begin(), data.end());
        values.resize(values.size() + 6, 0);
        auto poly = polymod(values);
        poly[0] ^= 0x2bc830a3 >> 25;
        return std::vector<uint8_t>(poly.begin() + 1, poly.end());
    }

    std::string Bech32m::encode(const std::string& hrp, const std::vector<uint8_t>& data) {
        std::vector<uint8_t> combined = data;
        auto checksum = createChecksum(hrp, data);
        combined.insert(combined.end(), checksum.begin(), checksum.end());

        std::string result = hrp + '1';
        for (uint8_t v : combined) {
            if (v >= 32) return "";
            result += CHARSET[v];
        }
        return result;
    }

    std::pair<std::string, std::vector<uint8_t>> Bech32m::decode(const std::string& bech) {
        if (bech.length() < 8 || bech.length() > 90) {
            return {"", {}};
        }

        bool hasLower = false, hasUpper = false;
        for (char c : bech) {
            if (c >= 'a' && c <= 'z') hasLower = true;
            if (c >= 'A' && c <= 'Z') hasUpper = true;
        }
        if (hasLower && hasUpper) return {"", {}};

        size_t pos = bech.rfind('1');
        if (pos == std::string::npos || pos == 0 || pos + 7 > bech.length()) {
            return {"", {}};
        }

        std::string hrp = bech.substr(0, pos);
        for (char c : hrp) {
            if (c < 33 || c > 126) return {"", {}};
        }

        std::vector<uint8_t> data;
        for (size_t i = pos + 1; i < bech.length(); i++) {
            char c = bech[i];
            if (c < 0 || c >= 128) return {"", {}};
            int8_t v = CHARSET_REV[static_cast<uint8_t>(c)];
            if (v == -1) return {"", {}};
            data.push_back(v);
        }

        if (!verifyChecksum(hrp, data)) {
            return {"", {}};
        }

        data.resize(data.size() - 6);
        return {hrp, data};
    }

    bool Bech32m::isValid(const std::string& bech) {
        return !decode(bech).first.empty();
    }

    // ============== AddressValidationResult Implementation ==============

    AddressValidationResult::AddressValidationResult()
        : isValid(false), format(AddressFormat::LEGACY), network(AddressNetwork::MAINNET) {}

    std::string AddressValidationResult::toString() const {
        std::stringstream ss;
        ss << "Address Validation: " << (isValid ? "VALID" : "INVALID") << "\n";
        if (!isValid) {
            ss << "  Error: " << error << "\n";
        } else {
            ss << "  Format: " << Address::formatToString(format) << "\n";
            ss << "  Network: " << Address::networkToString(network) << "\n";
            if (!hash160.empty()) {
                ss << "  Hash160: ";
                for (auto byte : hash160) {
                    ss << std::hex << std::setw(2) << std::setfill('0') 
                       << static_cast<int>(byte);
                }
                ss << "\n";
            }
        }
        return ss.str();
    }

    // ============== Address Implementation ==============

    Address::Address() : format(AddressFormat::LEGACY), network(AddressNetwork::MAINNET) {}

    Address::Address(const std::vector<uint8_t>& h160, AddressFormat fmt, AddressNetwork net)
        : hash160(h160), format(fmt), network(net) {
        if (format == AddressFormat::LEGACY) {
            legacy = toLegacy();
        } else if (format == AddressFormat::BECH32) {
            bech32 = toBech32();
        }
    }

    Address::Address(const std::vector<uint8_t>& pubKey, AddressFormat fmt, AddressNetwork net)
        : format(fmt), network(net) {
        std::string pubStr(pubKey.begin(), pubKey.end());
        auto hash = RIPEMD160::hash160(pubStr);
        hash160 = std::vector<uint8_t>(hash.begin(), hash.end());
        
        if (format == AddressFormat::LEGACY) {
            legacy = toLegacy();
        } else if (format == AddressFormat::BECH32) {
            bech32 = toBech32();
        }
    }

    Address::Address(const std::vector<uint8_t>& scr, AddressFormat fmt, AddressNetwork net)
        : script(scr), format(fmt), network(net) {
        std::string scriptStr(scr.begin(), scr.end());
        auto hash = RIPEMD160::hash160(scriptStr);
        hash160 = std::vector<uint8_t>(hash.begin(), hash.end());
        
        if (format == AddressFormat::P2SH) {
            legacy = toP2SH();
        } else if (format == AddressFormat::BECH32) {
            bech32 = toBech32();
        }
    }

    Address::Address(const std::string& addressStr) {
        auto result = validate(addressStr);
        isValid() = result.isValid;
        format = result.format;
        network = result.network;
        hash160 = result.hash160;
        
        if (isValid()) {
            if (format == AddressFormat::LEGACY) {
                legacy = addressStr;
            } else if (format == AddressFormat::P2SH) {
                legacy = addressStr;
            } else if (format == AddressFormat::BECH32) {
                bech32 = addressStr;
            }
        }
    }

    bool Address::operator==(const Address& other) const {
        return hash160 == other.hash160 && format == other.format && network == other.network;
    }

    bool Address::operator!=(const Address& other) const {
        return !(*this == other);
    }

    bool Address::operator<(const Address& other) const {
        return hash160 < other.hash160;
    }

    std::string Address::toLegacy() const {
        if (format == AddressFormat::LEGACY || format == AddressFormat::P2SH) {
            std::vector<uint8_t> data;
            uint8_t prefix = (network == AddressNetwork::MAINNET) ? 
                AddressPrefixes::PUBKEY_ADDRESS_MAIN : AddressPrefixes::PUBKEY_ADDRESS_TEST;
            
            if (format == AddressFormat::P2SH) {
                prefix = (network == AddressNetwork::MAINNET) ? 
                    AddressPrefixes::SCRIPT_ADDRESS_MAIN : AddressPrefixes::SCRIPT_ADDRESS_TEST;
            }
            
            data.push_back(prefix);
            data.insert(data.end(), hash160.begin(), hash160.end());
            return Base58::encodeCheck(data);
        }
        return "";
    }

    std::string Address::toBech32() const {
        if (format == AddressFormat::BECH32 || format == AddressFormat::BECH32M) {
            std::string hrp;
            switch (network) {
                case AddressNetwork::MAINNET:
                    hrp = (format == AddressFormat::BECH32M) ? "bc" : "bc";
                    break;
                case AddressNetwork::TESTNET:
                    hrp = (format == AddressFormat::BECH32M) ? "tb" : "tb";
                    break;
                case AddressNetwork::REGTEST:
                    hrp = "bcrt";
                    break;
                default:
                    hrp = "bc";
            }

            uint8_t witnessVersion = (format == AddressFormat::BECH32M) ? 1 : 0;
            
            // Convert hash160 to 5-bit words
            std::vector<uint8_t> data;
            data.push_back(witnessVersion);
            
            // Convert 8-bit to 5-bit
            uint32_t buffer = 0;
            int bits = 0;
            for (uint8_t byte : hash160) {
                buffer = (buffer << 8) | byte;
                bits += 8;
                while (bits >= 5) {
                    data.push_back((buffer >> (bits - 5)) & 0x1f);
                    bits -= 5;
                }
            }
            if (bits > 0) {
                data.push_back((buffer << (5 - bits)) & 0x1f);
            }

            if (format == AddressFormat::BECH32M) {
                return Bech32m::encode(hrp, data);
            } else {
                return Bech32::encode(hrp, data);
            }
        }
        return "";
    }

    std::string Address::toP2SH() const {
        if (!script.empty()) {
            std::string scriptStr(script.begin(), script.end());
            auto hash = RIPEMD160::hash160(scriptStr);
            std::vector<uint8_t> data;
            uint8_t prefix = (network == AddressNetwork::MAINNET) ? 
                AddressPrefixes::SCRIPT_ADDRESS_MAIN : AddressPrefixes::SCRIPT_ADDRESS_TEST;
            data.push_back(prefix);
            data.insert(data.end(), hash.begin(), hash.end());
            return Base58::encodeCheck(data);
        }
        return "";
    }

    std::string Address::toString(AddressFormat fmt) const {
        switch (fmt) {
            case AddressFormat::LEGACY:
            case AddressFormat::P2PK:
                return toLegacy();
            case AddressFormat::P2SH:
                return toP2SH();
            case AddressFormat::BECH32:
            case AddressFormat::BECH32M:
                return toBech32();
            default:
                return toString();
        }
    }

    std::string Address::toString() const {
        switch (format) {
            case AddressFormat::LEGACY:
            case AddressFormat::P2PK:
                return toLegacy();
            case AddressFormat::P2SH:
                return toP2SH();
            case AddressFormat::BECH32:
            case AddressFormat::BECH32M:
                return toBech32();
            default:
                return "";
        }
    }

    bool Address::isValid() const {
        return !hash160.empty() || !script.empty();
    }

    AddressValidationResult Address::validate() const {
        AddressValidationResult result;
        result.isValid = isValid();
        result.format = format;
        result.network = network;
        result.hash160 = hash160;
        return result;
    }

    bool Address::isValid(const std::string& address) {
        return !validate(address).isValid;
    }

    AddressValidationResult Address::validate(const std::string& address) {
        AddressValidationResult result;

        // Try Base58Check decoding (legacy/P2SH)
        try {
            std::vector<uint8_t> decoded = Base58::decodeCheck(address);
            if (decoded.size() == 21) {
                uint8_t version = decoded[0];
                result.hash160 = std::vector<uint8_t>(decoded.begin() + 1, decoded.end());
                
                if (version == AddressPrefixes::PUBKEY_ADDRESS_MAIN) {
                    result.format = AddressFormat::LEGACY;
                    result.network = AddressNetwork::MAINNET;
                    result.isValid = true;
                } else if (version == AddressPrefixes::SCRIPT_ADDRESS_MAIN) {
                    result.format = AddressFormat::P2SH;
                    result.network = AddressNetwork::MAINNET;
                    result.isValid = true;
                } else if (version == AddressPrefixes::PUBKEY_ADDRESS_TEST) {
                    result.format = AddressFormat::LEGACY;
                    result.network = AddressNetwork::TESTNET;
                    result.isValid = true;
                } else if (version == AddressPrefixes::SCRIPT_ADDRESS_TEST) {
                    result.format = AddressFormat::P2SH;
                    result.network = AddressNetwork::TESTNET;
                    result.isValid = true;
                }
            }
        } catch (...) {}

        // Try Bech32 decoding
        if (!result.isValid) {
            auto [hrp, data] = Bech32::decode(address);
            if (!hrp.empty() && !data.empty()) {
                result.isValid = true;
                result.format = AddressFormat::BECH32;
                
                if (hrp == "bc") {
                    result.network = AddressNetwork::MAINNET;
                } else if (hrp == "tb") {
                    result.network = AddressNetwork::TESTNET;
                } else if (hrp == "bcrt") {
                    result.network = AddressNetwork::REGTEST;
                }

                // Convert 5-bit data to hash160
                uint32_t buffer = 0;
                int bits = 0;
                for (size_t i = 1; i < data.size(); i++) { // Skip witness version
                    buffer = (buffer << 5) | data[i];
                    bits += 5;
                    while (bits >= 8) {
                        result.hash160.push_back((buffer >> (bits - 8)) & 0xff);
                        bits -= 8;
                    }
                }
            }
        }

        // Try Bech32m decoding (Taproot)
        if (!result.isValid) {
            auto [hrp, data] = Bech32m::decode(address);
            if (!hrp.empty() && !data.empty()) {
                result.isValid = true;
                result.format = AddressFormat::BECH32M;
                
                if (hrp == "bc") {
                    result.network = AddressNetwork::MAINNET;
                } else if (hrp == "tb") {
                    result.network = AddressNetwork::TESTNET;
                } else if (hrp == "bcrt") {
                    result.network = AddressNetwork::REGTEST;
                }

                // Convert 5-bit data
                uint32_t buffer = 0;
                int bits = 0;
                for (size_t i = 1; i < data.size(); i++) {
                    buffer = (buffer << 5) | data[i];
                    bits += 5;
                    while (bits >= 8) {
                        result.hash160.push_back((buffer >> (bits - 8)) & 0xff);
                        bits -= 8;
                    }
                }
            }
        }

        if (!result.isValid) {
            result.error = "Invalid address format";
        }

        return result;
    }

    AddressFormat Address::detectFormat(const std::string& address) {
        return validate(address).format;
    }

    AddressNetwork Address::detectNetwork(const std::string& address) {
        return validate(address).network;
    }

    std::vector<uint8_t> Address::extractHash160(const std::string& address) {
        return validate(address).hash160;
    }

    std::string Address::convertFormat(const std::string& address, AddressFormat targetFormat) {
        auto validation = validate(address);
        if (!validation.isValid) {
            return "";
        }

        Address addr(validation.hash160, targetFormat, validation.network);
        return addr.toString(targetFormat);
    }

    std::string Address::fromPublicKey(const std::vector<uint8_t>& publicKey,
                                        AddressFormat format,
                                        AddressNetwork network) {
        Address addr(publicKey, format, network);
        return addr.toString();
    }

    std::string Address::fromScript(const std::vector<uint8_t>& script,
                                     AddressFormat format,
                                     AddressNetwork network) {
        Address addr(script, format, network);
        return addr.toString();
    }

    std::string Address::fromHash160(const std::vector<uint8_t>& hash160,
                                      AddressNetwork network) {
        Address addr(hash160, AddressFormat::LEGACY, network);
        return addr.toString();
    }

    std::string Address::fromScriptHash(const std::vector<uint8_t>& scriptHash,
                                         AddressNetwork network) {
        Address addr(scriptHash, AddressFormat::P2SH, network);
        return addr.toString();
    }

    std::string Address::fromWitnessProgram(uint8_t witnessVersion,
                                             const std::vector<uint8_t>& witnessProgram,
                                             AddressNetwork network) {
        AddressFormat format = (witnessVersion == 0) ? 
            AddressFormat::BECH32 : AddressFormat::BECH32M;
        
        // Convert witness program to hash160 (simplified)
        std::string progStr(witnessProgram.begin(), witnessProgram.end());
        auto hash = RIPEMD160::hash160(progStr);
        std::vector<uint8_t> hash160(hash.begin(), hash.end());
        
        Address addr(hash160, format, network);
        return addr.toString();
    }

    std::string Address::fromPublicKeyWitness(const std::vector<uint8_t>& publicKey,
                                               AddressNetwork network) {
        std::string pubStr(publicKey.begin(), publicKey.end());
        auto hash = RIPEMD160::hash160(pubStr);
        std::vector<uint8_t> hash160(hash.begin(), hash.end());
        
        Address addr(hash160, AddressFormat::BECH32, network);
        return addr.toString();
    }

    std::string Address::fromScriptWitness(const std::vector<uint8_t>& script,
                                            AddressNetwork network) {
        std::string scriptStr(script.begin(), script.end());
        auto hash = SHA256::hash(scriptStr);
        std::vector<uint8_t> hash256(hash.begin(), hash.end());
        
        Address addr(hash256, AddressFormat::BECH32, network);
        return addr.toString();
    }

    std::string Address::fromTaprootKey(const std::vector<uint8_t>& publicKey,
                                         AddressNetwork network) {
        // x-only public key (32 bytes)
        if (publicKey.size() != 32) {
            return "";
        }

        Address addr(publicKey, AddressFormat::BECH32M, network);
        return addr.toString();
    }

    std::string Address::formatToString(AddressFormat format) {
        switch (format) {
            case AddressFormat::LEGACY:
                return "P2PKH (Legacy)";
            case AddressFormat::P2SH:
                return "P2SH";
            case AddressFormat::BECH32:
                return "Bech32 (SegWit)";
            case AddressFormat::BECH32M:
                return "Bech32m (Taproot)";
            case AddressFormat::P2PK:
                return "P2PK";
            case AddressFormat::POWR:
                return "Power Coin";
            default:
                return "Unknown";
        }
    }

    std::string Address::networkToString(AddressNetwork network) {
        switch (network) {
            case AddressNetwork::MAINNET:
                return "Mainnet";
            case AddressNetwork::TESTNET:
                return "Testnet";
            case AddressNetwork::REGTEST:
                return "Regtest";
            case AddressNetwork::SIMNET:
                return "Simnet";
            default:
                return "Unknown";
        }
    }

    std::string Address::getPrefix(AddressFormat format, AddressNetwork network) {
        switch (format) {
            case AddressFormat::LEGACY:
                return (network == AddressNetwork::MAINNET) ? "1" : "m";
            case AddressFormat::P2SH:
                return (network == AddressNetwork::MAINNET) ? "3" : "2";
            case AddressFormat::BECH32:
            case AddressFormat::BECH32M:
                switch (network) {
                    case AddressNetwork::MAINNET:
                        return "bc";
                    case AddressNetwork::TESTNET:
                        return "tb";
                    case AddressNetwork::REGTEST:
                        return "bcrt";
                    default:
                        return "bc";
                }
            default:
                return "";
        }
    }

    // ============== AddressBuilder Implementation ==============

    AddressBuilder::AddressBuilder() : format(AddressFormat::LEGACY), 
                                       network(AddressNetwork::MAINNET),
                                       witnessVersion(0) {}

    AddressBuilder& AddressBuilder::withPublicKey(const std::vector<uint8_t>& key) {
        publicKey = key;
        return *this;
    }

    AddressBuilder& AddressBuilder::withScript(const std::vector<uint8_t>& scr) {
        script = scr;
        return *this;
    }

    AddressBuilder& AddressBuilder::withHash160(const std::vector<uint8_t>& hash) {
        hash160 = hash;
        return *this;
    }

    AddressBuilder& AddressBuilder::withFormat(AddressFormat fmt) {
        format = fmt;
        return *this;
    }

    AddressBuilder& AddressBuilder::withNetwork(AddressNetwork net) {
        network = net;
        return *this;
    }

    AddressBuilder& AddressBuilder::withWitnessVersion(uint8_t version) {
        witnessVersion = version;
        return *this;
    }

    std::string AddressBuilder::build() const {
        if (!publicKey.empty()) {
            return Address::fromPublicKey(publicKey, format, network);
        } else if (!script.empty()) {
            return Address::fromScript(script, format, network);
        } else if (!hash160.empty()) {
            if (format == AddressFormat::P2SH) {
                return Address::fromScriptHash(hash160, network);
            } else if (format == AddressFormat::BECH32 || format == AddressFormat::BECH32M) {
                return Address::fromWitnessProgram(witnessVersion, hash160, network);
            } else {
                return Address::fromHash160(hash160, network);
            }
        }
        return "";
    }

    Address AddressBuilder::buildAddress() const {
        if (!publicKey.empty()) {
            return Address(publicKey, format, network);
        } else if (!script.empty()) {
            return Address(script, format, network);
        } else if (!hash160.empty()) {
            return Address(hash160, format, network);
        }
        return Address();
    }

} // namespace powercoin