#include "aes.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <cstring>
#include <stdexcept>
#include <fstream>
#include <vector>
#include <algorithm>

namespace powercoin {

    // Internal context structure
    struct AES::Context {
        EVP_CIPHER_CTX* ctx;
        AESMode mode;
        AESKeyLength keyLength;
        AESPadding padding;
        std::vector<uint8_t> key;

        Context() : ctx(nullptr) {
            ctx = EVP_CIPHER_CTX_new();
        }

        ~Context() {
            if (ctx) {
                EVP_CIPHER_CTX_free(ctx);
            }
        }
    };

    // Helper function to get OpenSSL cipher based on mode and key length
    static const EVP_CIPHER* getCipher(AESMode mode, AESKeyLength keyLength) {
        switch (mode) {
            case AESMode::ECB:
                switch (keyLength) {
                    case AESKeyLength::AES_128: return EVP_aes_128_ecb();
                    case AESKeyLength::AES_192: return EVP_aes_192_ecb();
                    case AESKeyLength::AES_256: return EVP_aes_256_ecb();
                }
                break;
            case AESMode::CBC:
                switch (keyLength) {
                    case AESKeyLength::AES_128: return EVP_aes_128_cbc();
                    case AESKeyLength::AES_192: return EVP_aes_192_cbc();
                    case AESKeyLength::AES_256: return EVP_aes_256_cbc();
                }
                break;
            case AESMode::CFB:
                switch (keyLength) {
                    case AESKeyLength::AES_128: return EVP_aes_128_cfb();
                    case AESKeyLength::AES_192: return EVP_aes_192_cfb();
                    case AESKeyLength::AES_256: return EVP_aes_256_cfb();
                }
                break;
            case AESMode::OFB:
                switch (keyLength) {
                    case AESKeyLength::AES_128: return EVP_aes_128_ofb();
                    case AESKeyLength::AES_192: return EVP_aes_192_ofb();
                    case AESKeyLength::AES_256: return EVP_aes_256_ofb();
                }
                break;
            case AESMode::CTR:
                switch (keyLength) {
                    case AESKeyLength::AES_128: return EVP_aes_128_ctr();
                    case AESKeyLength::AES_192: return EVP_aes_192_ctr();
                    case AESKeyLength::AES_256: return EVP_aes_256_ctr();
                }
                break;
            case AESMode::GCM:
                switch (keyLength) {
                    case AESKeyLength::AES_128: return EVP_aes_128_gcm();
                    case AESKeyLength::AES_192: return EVP_aes_192_gcm();
                    case AESKeyLength::AES_256: return EVP_aes_256_gcm();
                }
                break;
            case AESMode::CCM:
                switch (keyLength) {
                    case AESKeyLength::AES_128: return EVP_aes_128_ccm();
                    case AESKeyLength::AES_192: return EVP_aes_192_ccm();
                    case AESKeyLength::AES_256: return EVP_aes_256_ccm();
                }
                break;
        }
        return nullptr;
    }

    AES::AES(AESMode mode, AESKeyLength keyLength, AESPadding padding) {
        ctx = std::make_unique<Context>();
        ctx->mode = mode;
        ctx->keyLength = keyLength;
        ctx->padding = padding;
    }

    AES::~AES() = default;

    void AES::checkKeySize(const std::vector<uint8_t>& key) const {
        size_t expectedSize = keyLengthToBytes(ctx->keyLength);
        if (key.size() != expectedSize) {
            throw std::invalid_argument("Invalid key size: expected " + 
                                        std::to_string(expectedSize) + 
                                        " bytes, got " + std::to_string(key.size()));
        }
    }

    void AES::checkIV(const std::vector<uint8_t>& iv) const {
        if (requiresIV() && iv.empty()) {
            throw std::invalid_argument("IV required for this mode");
        }
        if (!iv.empty() && iv.size() != AES_BLOCK_SIZE && 
            ctx->mode != AESMode::GCM && ctx->mode != AESMode::CCM) {
            throw std::invalid_argument("IV must be " + std::to_string(AES_BLOCK_SIZE) + " bytes");
        }
        if (ctx->mode == AESMode::GCM && iv.size() != 12) {
            throw std::invalid_argument("GCM mode requires 12-byte IV");
        }
        if (ctx->mode == AESMode::CCM && iv.size() != 12) {
            throw std::invalid_argument("CCM mode requires 12-byte IV");
        }
    }

    std::vector<uint8_t> AES::pad(const std::vector<uint8_t>& data, AESPadding padding) const {
        if (padding == AESPadding::NONE) {
            if (data.size() % AES_BLOCK_SIZE != 0) {
                throw std::invalid_argument("Data size must be multiple of block size when padding is NONE");
            }
            return data;
        }

        size_t padLen = AES_BLOCK_SIZE - (data.size() % AES_BLOCK_SIZE);
        std::vector<uint8_t> padded = data;
        padded.reserve(data.size() + padLen);

        switch (padding) {
            case AESPadding::PKCS7:
                for (size_t i = 0; i < padLen; i++) {
                    padded.push_back(static_cast<uint8_t>(padLen));
                }
                break;
            case AESPadding::ISO7816:
                padded.push_back(0x80);
                for (size_t i = 1; i < padLen; i++) {
                    padded.push_back(0x00);
                }
                break;
            case AESPadding::ANSI_X923:
                for (size_t i = 0; i < padLen - 1; i++) {
                    padded.push_back(0x00);
                }
                padded.push_back(static_cast<uint8_t>(padLen));
                break;
            case AESPadding::ZERO:
                for (size_t i = 0; i < padLen; i++) {
                    padded.push_back(0x00);
                }
                break;
            default:
                break;
        }

        return padded;
    }

    std::vector<uint8_t> AES::unpad(const std::vector<uint8_t>& data, AESPadding padding) const {
        if (padding == AESPadding::NONE || data.empty()) {
            return data;
        }

        if (data.size() % AES_BLOCK_SIZE != 0) {
            throw std::invalid_argument("Invalid padded data size");
        }

        uint8_t lastByte = data.back();
        size_t padLen = 0;

        switch (padding) {
            case AESPadding::PKCS7:
                padLen = lastByte;
                if (padLen > AES_BLOCK_SIZE || padLen == 0) {
                    throw std::invalid_argument("Invalid PKCS7 padding");
                }
                for (size_t i = data.size() - padLen; i < data.size(); i++) {
                    if (data[i] != padLen) {
                        throw std::invalid_argument("Invalid PKCS7 padding");
                    }
                }
                break;
            case AESPadding::ISO7816:
                for (auto it = data.rbegin(); it != data.rend(); ++it) {
                    if (*it == 0x80) {
                        padLen = std::distance(data.rbegin(), it) + 1;
                        break;
                    }
                    if (*it != 0x00) {
                        throw std::invalid_argument("Invalid ISO7816 padding");
                    }
                }
                break;
            case AESPadding::ANSI_X923:
                padLen = lastByte;
                if (padLen > AES_BLOCK_SIZE || padLen == 0) {
                    throw std::invalid_argument("Invalid ANSI X923 padding");
                }
                for (size_t i = data.size() - padLen + 1; i < data.size() - 1; i++) {
                    if (data[i] != 0x00) {
                        throw std::invalid_argument("Invalid ANSI X923 padding");
                    }
                }
                break;
            case AESPadding::ZERO:
                for (auto it = data.rbegin(); it != data.rend(); ++it) {
                    if (*it != 0x00) {
                        padLen = std::distance(data.rbegin(), it);
                        break;
                    }
                }
                break;
            default:
                break;
        }

        if (padLen == 0 || padLen > data.size()) {
            throw std::invalid_argument("Invalid padding");
        }

        return std::vector<uint8_t>(data.begin(), data.end() - padLen);
    }

    bool AES::setKey(const std::vector<uint8_t>& key) {
        try {
            checkKeySize(key);
            ctx->key = key;
            return true;
        } catch (...) {
            return false;
        }
    }

    bool AES::setKeyFromString(const std::string& key) {
        // Simple key derivation - in production use proper KDF
        std::vector<uint8_t> keyBytes(key.begin(), key.end());
        size_t expectedSize = keyLengthToBytes(ctx->keyLength);
        
        if (keyBytes.size() > expectedSize) {
            keyBytes.resize(expectedSize);
        } else if (keyBytes.size() < expectedSize) {
            keyBytes.insert(keyBytes.end(), expectedSize - keyBytes.size(), 0);
        }
        
        return setKey(keyBytes);
    }

    std::vector<uint8_t> AES::generateKey() const {
        std::vector<uint8_t> key(keyLengthToBytes(ctx->keyLength));
        if (RAND_bytes(key.data(), key.size()) != 1) {
            throw std::runtime_error("Failed to generate random key");
        }
        return key;
    }

    std::vector<uint8_t> AES::generateIV() const {
        std::vector<uint8_t> iv(getRecommendedIVSize());
        if (RAND_bytes(iv.data(), iv.size()) != 1) {
            throw std::runtime_error("Failed to generate random IV");
        }
        return iv;
    }

    std::vector<uint8_t> AES::encrypt(const std::vector<uint8_t>& plaintext,
                                       const std::vector<uint8_t>& iv) const {
        checkIV(iv);
        
        const EVP_CIPHER* cipher = getCipher(ctx->mode, ctx->keyLength);
        if (!cipher) {
            throw std::runtime_error("Unsupported cipher mode");
        }

        std::vector<uint8_t> padded = pad(plaintext, ctx->padding);
        std::vector<uint8_t> ciphertext(padded.size() + AES_BLOCK_SIZE);
        
        int len = 0;
        int ciphertextLen = 0;

        EVP_CIPHER_CTX* evpCtx = EVP_CIPHER_CTX_new();
        if (!evpCtx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        try {
            if (EVP_EncryptInit_ex(evpCtx, cipher, nullptr, ctx->key.data(), 
                                   iv.empty() ? nullptr : iv.data()) != 1) {
                throw std::runtime_error("Failed to initialize encryption");
            }

            if (EVP_EncryptUpdate(evpCtx, ciphertext.data(), &len, 
                                  padded.data(), padded.size()) != 1) {
                throw std::runtime_error("Failed to encrypt data");
            }
            ciphertextLen = len;

            if (EVP_EncryptFinal_ex(evpCtx, ciphertext.data() + len, &len) != 1) {
                throw std::runtime_error("Failed to finalize encryption");
            }
            ciphertextLen += len;

            ciphertext.resize(ciphertextLen);
            
        } catch (...) {
            EVP_CIPHER_CTX_free(evpCtx);
            throw;
        }

        EVP_CIPHER_CTX_free(evpCtx);
        return ciphertext;
    }

    std::vector<uint8_t> AES::encrypt(const std::string& plaintext,
                                       const std::vector<uint8_t>& iv) const {
        std::vector<uint8_t> data(plaintext.begin(), plaintext.end());
        return encrypt(data, iv);
    }

    std::vector<uint8_t> AES::decrypt(const std::vector<uint8_t>& ciphertext,
                                       const std::vector<uint8_t>& iv) const {
        checkIV(iv);

        const EVP_CIPHER* cipher = getCipher(ctx->mode, ctx->keyLength);
        if (!cipher) {
            throw std::runtime_error("Unsupported cipher mode");
        }

        std::vector<uint8_t> plaintext(ciphertext.size() + AES_BLOCK_SIZE);
        int len = 0;
        int plaintextLen = 0;

        EVP_CIPHER_CTX* evpCtx = EVP_CIPHER_CTX_new();
        if (!evpCtx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        try {
            if (EVP_DecryptInit_ex(evpCtx, cipher, nullptr, ctx->key.data(),
                                   iv.empty() ? nullptr : iv.data()) != 1) {
                throw std::runtime_error("Failed to initialize decryption");
            }

            if (EVP_DecryptUpdate(evpCtx, plaintext.data(), &len,
                                  ciphertext.data(), ciphertext.size()) != 1) {
                throw std::runtime_error("Failed to decrypt data");
            }
            plaintextLen = len;

            if (EVP_DecryptFinal_ex(evpCtx, plaintext.data() + len, &len) != 1) {
                throw std::runtime_error("Failed to finalize decryption");
            }
            plaintextLen += len;

            plaintext.resize(plaintextLen);
            
        } catch (...) {
            EVP_CIPHER_CTX_free(evpCtx);
            throw;
        }

        EVP_CIPHER_CTX_free(evpCtx);
        return unpad(plaintext, ctx->padding);
    }

    std::string AES::decryptToString(const std::vector<uint8_t>& ciphertext,
                                      const std::vector<uint8_t>& iv) const {
        auto plaintext = decrypt(ciphertext, iv);
        return std::string(plaintext.begin(), plaintext.end());
    }

    std::vector<uint8_t> AES::encryptGCM(const std::vector<uint8_t>& plaintext,
                                          const std::vector<uint8_t>& iv,
                                          const std::vector<uint8_t>& aad,
                                          std::vector<uint8_t>& tag) const {
        if (ctx->mode != AESMode::GCM) {
            throw std::runtime_error("GCM mode required");
        }

        const EVP_CIPHER* cipher = getCipher(AESMode::GCM, ctx->keyLength);
        if (!cipher) {
            throw std::runtime_error("Unsupported cipher mode");
        }

        std::vector<uint8_t> ciphertext(plaintext.size());
        int len = 0;

        EVP_CIPHER_CTX* evpCtx = EVP_CIPHER_CTX_new();
        if (!evpCtx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        try {
            if (EVP_EncryptInit_ex(evpCtx, cipher, nullptr, nullptr, nullptr) != 1) {
                throw std::runtime_error("Failed to initialize encryption");
            }

            if (EVP_CIPHER_CTX_ctrl(evpCtx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
                throw std::runtime_error("Failed to set IV length");
            }

            if (EVP_EncryptInit_ex(evpCtx, nullptr, nullptr, ctx->key.data(), iv.data()) != 1) {
                throw std::runtime_error("Failed to set key and IV");
            }

            if (!aad.empty()) {
                if (EVP_EncryptUpdate(evpCtx, nullptr, &len, aad.data(), aad.size()) != 1) {
                    throw std::runtime_error("Failed to process AAD");
                }
            }

            if (EVP_EncryptUpdate(evpCtx, ciphertext.data(), &len,
                                  plaintext.data(), plaintext.size()) != 1) {
                throw std::runtime_error("Failed to encrypt data");
            }

            if (EVP_EncryptFinal_ex(evpCtx, nullptr, &len) != 1) {
                throw std::runtime_error("Failed to finalize encryption");
            }

            tag.resize(16);
            if (EVP_CIPHER_CTX_ctrl(evpCtx, EVP_CTRL_GCM_GET_TAG, 16, tag.data()) != 1) {
                throw std::runtime_error("Failed to get authentication tag");
            }

        } catch (...) {
            EVP_CIPHER_CTX_free(evpCtx);
            throw;
        }

        EVP_CIPHER_CTX_free(evpCtx);
        return ciphertext;
    }

    std::vector<uint8_t> AES::decryptGCM(const std::vector<uint8_t>& ciphertext,
                                          const std::vector<uint8_t>& iv,
                                          const std::vector<uint8_t>& aad,
                                          const std::vector<uint8_t>& tag) const {
        if (ctx->mode != AESMode::GCM) {
            throw std::runtime_error("GCM mode required");
        }

        const EVP_CIPHER* cipher = getCipher(AESMode::GCM, ctx->keyLength);
        if (!cipher) {
            throw std::runtime_error("Unsupported cipher mode");
        }

        std::vector<uint8_t> plaintext(ciphertext.size());
        int len = 0;

        EVP_CIPHER_CTX* evpCtx = EVP_CIPHER_CTX_new();
        if (!evpCtx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        try {
            if (EVP_DecryptInit_ex(evpCtx, cipher, nullptr, nullptr, nullptr) != 1) {
                throw std::runtime_error("Failed to initialize decryption");
            }

            if (EVP_CIPHER_CTX_ctrl(evpCtx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), nullptr) != 1) {
                throw std::runtime_error("Failed to set IV length");
            }

            if (EVP_DecryptInit_ex(evpCtx, nullptr, nullptr, ctx->key.data(), iv.data()) != 1) {
                throw std::runtime_error("Failed to set key and IV");
            }

            if (EVP_CIPHER_CTX_ctrl(evpCtx, EVP_CTRL_GCM_SET_TAG, tag.size(),
                                    const_cast<uint8_t*>(tag.data())) != 1) {
                throw std::runtime_error("Failed to set authentication tag");
            }

            if (!aad.empty()) {
                if (EVP_DecryptUpdate(evpCtx, nullptr, &len, aad.data(), aad.size()) != 1) {
                    throw std::runtime_error("Failed to process AAD");
                }
            }

            if (EVP_DecryptUpdate(evpCtx, plaintext.data(), &len,
                                  ciphertext.data(), ciphertext.size()) != 1) {
                throw std::runtime_error("Failed to decrypt data");
            }

            if (EVP_DecryptFinal_ex(evpCtx, nullptr, &len) != 1) {
                throw std::runtime_error("Authentication failed");
            }

        } catch (...) {
            EVP_CIPHER_CTX_free(evpCtx);
            throw;
        }

        EVP_CIPHER_CTX_free(evpCtx);
        return plaintext;
    }

    std::vector<uint8_t> AES::encryptCTR(const std::vector<uint8_t>& plaintext,
                                          const std::vector<uint8_t>& iv) const {
        if (ctx->mode != AESMode::CTR) {
            throw std::runtime_error("CTR mode required");
        }
        return encrypt(plaintext, iv);
    }

    std::vector<uint8_t> AES::decryptCTR(const std::vector<uint8_t>& ciphertext,
                                          const std::vector<uint8_t>& iv) const {
        if (ctx->mode != AESMode::CTR) {
            throw std::runtime_error("CTR mode required");
        }
        return decrypt(ciphertext, iv);
    }

    bool AES::encryptFile(const std::string& inputPath,
                          const std::string& outputPath,
                          const std::vector<uint8_t>& iv) const {
        try {
            std::ifstream in(inputPath, std::ios::binary);
            if (!in) {
                return false;
            }

            std::ofstream out(outputPath, std::ios::binary);
            if (!out) {
                return false;
            }

            std::vector<uint8_t> buffer(4096);
            std::vector<uint8_t> encrypted;

            while (in.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
                auto chunk = encrypt(buffer, iv);
                out.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            }

            // Process remaining data
            if (in.gcount() > 0) {
                buffer.resize(in.gcount());
                auto chunk = encrypt(buffer, iv);
                out.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            }

            return true;
        } catch (...) {
            return false;
        }
    }

    bool AES::decryptFile(const std::string& inputPath,
                          const std::string& outputPath,
                          const std::vector<uint8_t>& iv) const {
        try {
            std::ifstream in(inputPath, std::ios::binary);
            if (!in) {
                return false;
            }

            std::ofstream out(outputPath, std::ios::binary);
            if (!out) {
                return false;
            }

            std::vector<uint8_t> buffer(4096);
            std::vector<uint8_t> decrypted;

            while (in.read(reinterpret_cast<char*>(buffer.data()), buffer.size())) {
                auto chunk = decrypt(buffer, iv);
                out.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            }

            // Process remaining data
            if (in.gcount() > 0) {
                buffer.resize(in.gcount());
                auto chunk = decrypt(buffer, iv);
                out.write(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            }

            return true;
        } catch (...) {
            return false;
        }
    }

    size_t AES::getKeySize() const {
        return keyLengthToBytes(ctx->keyLength);
    }

    AESMode AES::getMode() const {
        return ctx->mode;
    }

    AESKeyLength AES::getKeyLength() const {
        return ctx->keyLength;
    }

    AESPadding AES::getPadding() const {
        return ctx->padding;
    }

    void AES::setPadding(AESPadding padding) {
        ctx->padding = padding;
    }

    bool AES::requiresIV() const {
        return ctx->mode != AESMode::ECB;
    }

    bool AES::isAuthenticated() const {
        return ctx->mode == AESMode::GCM || ctx->mode == AESMode::CCM;
    }

    size_t AES::getRecommendedIVSize() const {
        switch (ctx->mode) {
            case AESMode::GCM:
            case AESMode::CCM:
                return 12;
            case AESMode::ECB:
                return 0;
            default:
                return AES_BLOCK_SIZE;
        }
    }

    size_t AES::keyLengthToBytes(AESKeyLength keyLength) {
        switch (keyLength) {
            case AESKeyLength::AES_128: return 16;
            case AESKeyLength::AES_192: return 24;
            case AESKeyLength::AES_256: return 32;
            default: return 32;
        }
    }

    AESKeyLength AES::bytesToKeyLength(size_t bytes) {
        switch (bytes) {
            case 16: return AESKeyLength::AES_128;
            case 24: return AESKeyLength::AES_192;
            case 32: return AESKeyLength::AES_256;
            default: throw std::invalid_argument("Invalid key size");
        }
    }

    std::string AES::modeToString(AESMode mode) {
        switch (mode) {
            case AESMode::ECB: return "ECB";
            case AESMode::CBC: return "CBC";
            case AESMode::CFB: return "CFB";
            case AESMode::OFB: return "OFB";
            case AESMode::CTR: return "CTR";
            case AESMode::GCM: return "GCM";
            case AESMode::CCM: return "CCM";
            default: return "Unknown";
        }
    }

    std::string AES::paddingToString(AESPadding padding) {
        switch (padding) {
            case AESPadding::NONE: return "None";
            case AESPadding::PKCS7: return "PKCS7";
            case AESPadding::ISO7816: return "ISO7816";
            case AESPadding::ANSI_X923: return "ANSI X923";
            case AESPadding::ZERO: return "Zero";
            default: return "Unknown";
        }
    }

    // ============== AES_CBC Implementation ==============

    AES_CBC::AES_CBC(AESKeyLength keyLength, AESPadding padding)
        : aes(AESMode::CBC, keyLength, padding) {}

    std::vector<uint8_t> AES_CBC::encrypt(const std::vector<uint8_t>& plaintext,
                                           const std::vector<uint8_t>& iv) {
        return aes.encrypt(plaintext, iv);
    }

    std::vector<uint8_t> AES_CBC::decrypt(const std::vector<uint8_t>& ciphertext,
                                           const std::vector<uint8_t>& iv) {
        return aes.decrypt(ciphertext, iv);
    }

    // ============== AES_GCM Implementation ==============

    AES_GCM::AES_GCM(AESKeyLength keyLength)
        : aes(AESMode::GCM, keyLength, AESPadding::NONE) {}

    std::vector<uint8_t> AES_GCM::encrypt(const std::vector<uint8_t>& plaintext,
                                           const std::vector<uint8_t>& iv,
                                           const std::vector<uint8_t>& aad,
                                           std::vector<uint8_t>& tag) {
        return aes.encryptGCM(plaintext, iv, aad, tag);
    }

    std::vector<uint8_t> AES_GCM::decrypt(const std::vector<uint8_t>& ciphertext,
                                           const std::vector<uint8_t>& iv,
                                           const std::vector<uint8_t>& aad,
                                           const std::vector<uint8_t>& tag) {
        return aes.decryptGCM(ciphertext, iv, aad, tag);
    }

    // ============== AES_CTR Implementation ==============

    AES_CTR::AES_CTR(AESKeyLength keyLength)
        : aes(AESMode::CTR, keyLength, AESPadding::NONE) {}

    std::vector<uint8_t> AES_CTR::encrypt(const std::vector<uint8_t>& data,
                                           const std::vector<uint8_t>& iv) {
        return aes.encryptCTR(data, iv);
    }

    std::vector<uint8_t> AES_CTR::decrypt(const std::vector<uint8_t>& data,
                                           const std::vector<uint8_t>& iv) {
        return aes.decryptCTR(data, iv);
    }

    // ============== AESKey Implementation ==============

    AESKey::AESKey() : keyLength(AESKeyLength::AES_256) {}

    AESKey::AESKey(const std::vector<uint8_t>& keyData) {
        setKey(keyData);
    }

    AESKey::AESKey(const std::string& password) {
        std::vector<uint8_t> salt(16);
        RAND_bytes(salt.data(), salt.size());
        setFromPassword(password, salt);
    }

    bool AESKey::setKey(const std::vector<uint8_t>& keyData) {
        try {
            keyLength = AES::bytesToKeyLength(keyData.size());
            key = keyData;
            return true;
        } catch (...) {
            return false;
        }
    }

    bool AESKey::setFromPassword(const std::string& password, const std::vector<uint8_t>& salt) {
        try {
            key = deriveFromPassword(password, salt, keyLength);
            return true;
        } catch (...) {
            return false;
        }
    }

    void AESKey::clear() {
        key.clear();
        key.shrink_to_fit();
    }

    std::vector<uint8_t> AESKey::deriveFromPassword(const std::string& password,
                                                     const std::vector<uint8_t>& salt,
                                                     AESKeyLength keyLength,
                                                     uint32_t iterations) {
        size_t keySize = AES::keyLengthToBytes(keyLength);
        std::vector<uint8_t> key(keySize);

        if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                              salt.data(), salt.size(),
                              iterations,
                              EVP_sha256(),
                              keySize, key.data()) != 1) {
            throw std::runtime_error("Key derivation failed");
        }

        return key;
    }

} // namespace powercoin