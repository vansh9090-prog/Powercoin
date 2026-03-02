#include "secp256k1.h"
#include <secp256k1.h>
#include <secp256k1_ecdh.h>
#include <secp256k1_schnorrsig.h>
#include <cstring>
#include <stdexcept>
#include <random>

namespace powercoin {

    // Internal context structure
    struct Secp256k1::Context {
        secp256k1_context* ctx;
        Secp256k1ContextFlag flags;
        Secp256k1Error lastError;

        Context(Secp256k1ContextFlag f) : flags(f), lastError(Secp256k1Error::SUCCESS) {
            unsigned int cflags = 0;
            if (static_cast<int>(f) & static_cast<int>(Secp256k1ContextFlag::SIGN)) {
                cflags |= SECP256K1_CONTEXT_SIGN;
            }
            if (static_cast<int>(f) & static_cast<int>(Secp256k1ContextFlag::VERIFY)) {
                cflags |= SECP256K1_CONTEXT_VERIFY;
            }
            ctx = secp256k1_context_create(cflags);
        }

        ~Context() {
            if (ctx) {
                secp256k1_context_destroy(ctx);
            }
        }
    };

    Secp256k1::Secp256k1(Secp256k1ContextFlag flags) {
        ctx = std::make_unique<Context>(flags);
    }

    Secp256k1::~Secp256k1() = default;

    bool Secp256k1::isValidPrivateKey(const uint8_t* key) const {
        return secp256k1_ec_seckey_verify(ctx->ctx, key) == 1;
    }

    bool Secp256k1::isValidPublicKey(const uint8_t* key, size_t len) const {
        secp256k1_pubkey pubkey;
        return secp256k1_ec_pubkey_parse(ctx->ctx, &pubkey, key, len) == 1;
    }

    bool Secp256k1::isValidSignature(const uint8_t* sig, size_t len) const {
        if (len == 64) {
            secp256k1_ecdsa_signature s;
            return secp256k1_ecdsa_signature_parse_compact(ctx->ctx, &s, sig) == 1;
        }
        return false;
    }

    std::vector<uint8_t> Secp256k1::generatePrivateKey() const {
        std::vector<uint8_t> key(SECP256K1_PRIVATE_KEY_SIZE);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        do {
            for (size_t i = 0; i < key.size(); i++) {
                key[i] = static_cast<uint8_t>(dis(gen));
            }
        } while (!isValidPrivateKey(key.data()));

        return key;
    }

    std::vector<uint8_t> Secp256k1::generatePrivateKeyFromSeed(const std::vector<uint8_t>& seed) const {
        if (seed.empty()) {
            ctx->lastError = Secp256k1Error::INVALID_PRIVATE_KEY;
            return {};
        }

        // Use SHA256 to derive private key from seed
        std::vector<uint8_t> key(SECP256K1_PRIVATE_KEY_SIZE);
        // Simplified - in production use proper KDF
        for (size_t i = 0; i < key.size() && i < seed.size(); i++) {
            key[i] = seed[i];
        }

        if (!isValidPrivateKey(key.data())) {
            ctx->lastError = Secp256k1Error::INVALID_PRIVATE_KEY;
            return {};
        }

        return key;
    }

    std::vector<uint8_t> Secp256k1::computePublicKey(const std::vector<uint8_t>& privateKey,
                                                     bool compressed) const {
        if (!isValidPrivateKey(privateKey.data())) {
            ctx->lastError = Secp256k1Error::INVALID_PRIVATE_KEY;
            return {};
        }

        secp256k1_pubkey pubkey;
        if (secp256k1_ec_pubkey_create(ctx->ctx, &pubkey, privateKey.data()) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_PRIVATE_KEY;
            return {};
        }

        size_t len = compressed ? SECP256K1_PUBLIC_KEY_SIZE : SECP256K1_PUBLIC_KEY_UNCOMPRESSED_SIZE;
        std::vector<uint8_t> result(len);
        unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

        secp256k1_ec_pubkey_serialize(ctx->ctx, result.data(), &len, &pubkey, flags);
        return result;
    }

    bool Secp256k1::computePublicKey(const std::vector<uint8_t>& privateKey,
                                     std::vector<uint8_t>& compressed,
                                     std::vector<uint8_t>& uncompressed) const {
        if (!isValidPrivateKey(privateKey.data())) {
            ctx->lastError = Secp256k1Error::INVALID_PRIVATE_KEY;
            return false;
        }

        secp256k1_pubkey pubkey;
        if (secp256k1_ec_pubkey_create(ctx->ctx, &pubkey, privateKey.data()) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_PRIVATE_KEY;
            return false;
        }

        size_t len = SECP256K1_PUBLIC_KEY_SIZE;
        compressed.resize(len);
        secp256k1_ec_pubkey_serialize(ctx->ctx, compressed.data(), &len, &pubkey,
                                      SECP256K1_EC_COMPRESSED);

        len = SECP256K1_PUBLIC_KEY_UNCOMPRESSED_SIZE;
        uncompressed.resize(len);
        secp256k1_ec_pubkey_serialize(ctx->ctx, uncompressed.data(), &len, &pubkey,
                                      SECP256K1_EC_UNCOMPRESSED);

        return true;
    }

    std::vector<uint8_t> Secp256k1::sign(const std::vector<uint8_t>& privateKey,
                                         const std::vector<uint8_t>& hash) const {
        if (!isValidPrivateKey(privateKey.data())) {
            ctx->lastError = Secp256k1Error::INVALID_PRIVATE_KEY;
            return {};
        }

        if (hash.size() != 32) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        secp256k1_ecdsa_signature sig;
        if (secp256k1_ecdsa_sign(ctx->ctx, &sig, hash.data(), privateKey.data(),
                                 nullptr, nullptr) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        std::vector<uint8_t> result(SECP256K1_SIGNATURE_SIZE);
        secp256k1_ecdsa_signature_serialize_compact(ctx->ctx, result.data(), &sig);
        return result;
    }

    std::vector<uint8_t> Secp256k1::signCompact(const std::vector<uint8_t>& privateKey,
                                                const std::vector<uint8_t>& hash) const {
        if (!isValidPrivateKey(privateKey.data())) {
            ctx->lastError = Secp256k1Error::INVALID_PRIVATE_KEY;
            return {};
        }

        if (hash.size() != 32) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        secp256k1_ecdsa_recoverable_signature sig;
        if (secp256k1_ecdsa_sign_recoverable(ctx->ctx, &sig, hash.data(),
                                            privateKey.data(), nullptr, nullptr) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        std::vector<uint8_t> result(SECP256K1_COMPACT_SIGNATURE_SIZE);
        int recid;
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx->ctx, result.data(), &recid, &sig);
        result[64] = static_cast<uint8_t>(recid);
        return result;
    }

    bool Secp256k1::verify(const std::vector<uint8_t>& signature,
                           const std::vector<uint8_t>& hash,
                           const std::vector<uint8_t>& publicKey) const {
        if (!isValidPublicKey(publicKey.data(), publicKey.size())) {
            ctx->lastError = Secp256k1Error::INVALID_PUBLIC_KEY;
            return false;
        }

        if (hash.size() != 32) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return false;
        }

        if (signature.size() != SECP256K1_SIGNATURE_SIZE) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return false;
        }

        secp256k1_pubkey pubkey;
        if (secp256k1_ec_pubkey_parse(ctx->ctx, &pubkey, publicKey.data(), publicKey.size()) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_PUBLIC_KEY;
            return false;
        }

        secp256k1_ecdsa_signature sig;
        if (secp256k1_ecdsa_signature_parse_compact(ctx->ctx, &sig, signature.data()) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return false;
        }

        // Normalize signature (ensure low S)
        secp256k1_ecdsa_signature sig_norm;
        secp256k1_ecdsa_signature_normalize(ctx->ctx, &sig_norm, &sig);

        int result = secp256k1_ecdsa_verify(ctx->ctx, &sig_norm, hash.data(), &pubkey);
        if (result != 1) {
            ctx->lastError = Secp256k1Error::VERIFICATION_FAILED;
        }
        return result == 1;
    }

    std::vector<uint8_t> Secp256k1::recoverPublicKey(const std::vector<uint8_t>& signature,
                                                     const std::vector<uint8_t>& hash,
                                                     bool compressed) const {
        if (signature.size() != SECP256K1_COMPACT_SIGNATURE_SIZE) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        if (hash.size() != 32) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        secp256k1_ecdsa_recoverable_signature sig;
        if (secp256k1_ecdsa_recoverable_signature_parse_compact(ctx->ctx, &sig,
                                                                signature.data(),
                                                                signature[64]) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        secp256k1_pubkey pubkey;
        if (secp256k1_ecdsa_recover(ctx->ctx, &pubkey, &sig, hash.data()) != 1) {
            ctx->lastError = Secp256k1Error::RECOVERY_FAILED;
            return {};
        }

        size_t len = compressed ? SECP256K1_PUBLIC_KEY_SIZE : SECP256K1_PUBLIC_KEY_UNCOMPRESSED_SIZE;
        std::vector<uint8_t> result(len);
        unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

        secp256k1_ec_pubkey_serialize(ctx->ctx, result.data(), &len, &pubkey, flags);
        return result;
    }

    std::vector<uint8_t> Secp256k1::tweakPrivateKey(const std::vector<uint8_t>& privateKey,
                                                    const std::vector<uint8_t>& tweak) const {
        if (!isValidPrivateKey(privateKey.data())) {
            ctx->lastError = Secp256k1Error::INVALID_PRIVATE_KEY;
            return {};
        }

        if (tweak.size() != 32) {
            ctx->lastError = Secp256k1Error::INVALID_TWEAK;
            return {};
        }

        std::vector<uint8_t> result = privateKey;
        if (secp256k1_ec_privkey_tweak_add(ctx->ctx, result.data(), tweak.data()) != 1) {
            ctx->lastError = Secp256k1Error::TWEAK_FAILED;
            return {};
        }

        return result;
    }

    std::vector<uint8_t> Secp256k1::tweakPublicKey(const std::vector<uint8_t>& publicKey,
                                                   const std::vector<uint8_t>& tweak) const {
        if (!isValidPublicKey(publicKey.data(), publicKey.size())) {
            ctx->lastError = Secp256k1Error::INVALID_PUBLIC_KEY;
            return {};
        }

        if (tweak.size() != 32) {
            ctx->lastError = Secp256k1Error::INVALID_TWEAK;
            return {};
        }

        secp256k1_pubkey pubkey;
        if (secp256k1_ec_pubkey_parse(ctx->ctx, &pubkey, publicKey.data(), publicKey.size()) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_PUBLIC_KEY;
            return {};
        }

        if (secp256k1_ec_pubkey_tweak_add(ctx->ctx, &pubkey, tweak.data()) != 1) {
            ctx->lastError = Secp256k1Error::TWEAK_FAILED;
            return {};
        }

        bool compressed = (publicKey.size() == SECP256K1_PUBLIC_KEY_SIZE);
        size_t len = compressed ? SECP256K1_PUBLIC_KEY_SIZE : SECP256K1_PUBLIC_KEY_UNCOMPRESSED_SIZE;
        std::vector<uint8_t> result(len);
        unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

        secp256k1_ec_pubkey_serialize(ctx->ctx, result.data(), &len, &pubkey, flags);
        return result;
    }

    std::vector<uint8_t> Secp256k1::negatePrivateKey(const std::vector<uint8_t>& privateKey) const {
        if (!isValidPrivateKey(privateKey.data())) {
            ctx->lastError = Secp256k1Error::INVALID_PRIVATE_KEY;
            return {};
        }

        std::vector<uint8_t> result = privateKey;
        if (secp256k1_ec_privkey_negate(ctx->ctx, result.data()) != 1) {
            ctx->lastError = Secp256k1Error::NEGATION_FAILED;
            return {};
        }

        return result;
    }

    std::vector<uint8_t> Secp256k1::negatePublicKey(const std::vector<uint8_t>& publicKey) const {
        if (!isValidPublicKey(publicKey.data(), publicKey.size())) {
            ctx->lastError = Secp256k1Error::INVALID_PUBLIC_KEY;
            return {};
        }

        secp256k1_pubkey pubkey;
        if (secp256k1_ec_pubkey_parse(ctx->ctx, &pubkey, publicKey.data(), publicKey.size()) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_PUBLIC_KEY;
            return {};
        }

        if (secp256k1_ec_pubkey_negate(ctx->ctx, &pubkey) != 1) {
            ctx->lastError = Secp256k1Error::NEGATION_FAILED;
            return {};
        }

        bool compressed = (publicKey.size() == SECP256K1_PUBLIC_KEY_SIZE);
        size_t len = compressed ? SECP256K1_PUBLIC_KEY_SIZE : SECP256K1_PUBLIC_KEY_UNCOMPRESSED_SIZE;
        std::vector<uint8_t> result(len);
        unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

        secp256k1_ec_pubkey_serialize(ctx->ctx, result.data(), &len, &pubkey, flags);
        return result;
    }

    std::vector<uint8_t> Secp256k1::convertPublicKey(const std::vector<uint8_t>& publicKey,
                                                     bool compressed) const {
        if (!isValidPublicKey(publicKey.data(), publicKey.size())) {
            ctx->lastError = Secp256k1Error::INVALID_PUBLIC_KEY;
            return {};
        }

        secp256k1_pubkey pubkey;
        if (secp256k1_ec_pubkey_parse(ctx->ctx, &pubkey, publicKey.data(), publicKey.size()) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_PUBLIC_KEY;
            return {};
        }

        size_t len = compressed ? SECP256K1_PUBLIC_KEY_SIZE : SECP256K1_PUBLIC_KEY_UNCOMPRESSED_SIZE;
        std::vector<uint8_t> result(len);
        unsigned int flags = compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED;

        secp256k1_ec_pubkey_serialize(ctx->ctx, result.data(), &len, &pubkey, flags);
        return result;
    }

    PublicKeyType Secp256k1::getPublicKeyType(const std::vector<uint8_t>& publicKey) const {
        if (publicKey.size() == SECP256K1_PUBLIC_KEY_SIZE &&
            (publicKey[0] == 0x02 || publicKey[0] == 0x03)) {
            return PublicKeyType::COMPRESSED;
        } else if (publicKey.size() == SECP256K1_PUBLIC_KEY_UNCOMPRESSED_SIZE &&
                   publicKey[0] == 0x04) {
            return PublicKeyType::UNCOMPRESSED;
        }
        ctx->lastError = Secp256k1Error::INVALID_PUBLIC_KEY;
        return PublicKeyType::COMPRESSED; // Default
    }

    bool Secp256k1::isPrivateKeyValid(const std::vector<uint8_t>& privateKey) const {
        return privateKey.size() == SECP256K1_PRIVATE_KEY_SIZE &&
               isValidPrivateKey(privateKey.data());
    }

    bool Secp256k1::isPublicKeyValid(const std::vector<uint8_t>& publicKey) const {
        return isValidPublicKey(publicKey.data(), publicKey.size());
    }

    bool Secp256k1::isSignatureValid(const std::vector<uint8_t>& signature) const {
        return signature.size() == SECP256K1_SIGNATURE_SIZE &&
               isValidSignature(signature.data(), signature.size());
    }

    uint8_t Secp256k1::getRecoveryId(const std::vector<uint8_t>& signature) const {
        if (signature.size() != SECP256K1_COMPACT_SIGNATURE_SIZE) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return 0;
        }
        return signature[64];
    }

    std::vector<uint8_t> Secp256k1::normalizeSignature(const std::vector<uint8_t>& signature) const {
        if (!isSignatureValid(signature)) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        secp256k1_ecdsa_signature sig;
        if (secp256k1_ecdsa_signature_parse_compact(ctx->ctx, &sig, signature.data()) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        secp256k1_ecdsa_signature sig_norm;
        secp256k1_ecdsa_signature_normalize(ctx->ctx, &sig_norm, &sig);

        std::vector<uint8_t> result(SECP256K1_SIGNATURE_SIZE);
        secp256k1_ecdsa_signature_serialize_compact(ctx->ctx, result.data(), &sig_norm);
        return result;
    }

    std::vector<uint8_t> Secp256k1::serializeToDER(const std::vector<uint8_t>& signature) const {
        if (!isSignatureValid(signature)) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        secp256k1_ecdsa_signature sig;
        if (secp256k1_ecdsa_signature_parse_compact(ctx->ctx, &sig, signature.data()) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        std::vector<uint8_t> der(72); // Max DER size
        size_t len = der.size();
        if (secp256k1_ecdsa_signature_serialize_der(ctx->ctx, der.data(), &len, &sig) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        der.resize(len);
        return der;
    }

    std::vector<uint8_t> Secp256k1::parseFromDER(const std::vector<uint8_t>& der) const {
        secp256k1_ecdsa_signature sig;
        if (secp256k1_ecdsa_signature_parse_der(ctx->ctx, &sig, der.data(), der.size()) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        std::vector<uint8_t> result(SECP256K1_SIGNATURE_SIZE);
        secp256k1_ecdsa_signature_serialize_compact(ctx->ctx, result.data(), &sig);
        return result;
    }

    std::vector<uint8_t> Secp256k1::computeSharedSecret(const std::vector<uint8_t>& privateKey,
                                                        const std::vector<uint8_t>& publicKey) const {
        if (!isValidPrivateKey(privateKey.data())) {
            ctx->lastError = Secp256k1Error::INVALID_PRIVATE_KEY;
            return {};
        }

        if (!isValidPublicKey(publicKey.data(), publicKey.size())) {
            ctx->lastError = Secp256k1Error::INVALID_PUBLIC_KEY;
            return {};
        }

        secp256k1_pubkey pubkey;
        if (secp256k1_ec_pubkey_parse(ctx->ctx, &pubkey, publicKey.data(), publicKey.size()) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_PUBLIC_KEY;
            return {};
        }

        std::vector<uint8_t> secret(32);
        if (secp256k1_ecdh(ctx->ctx, secret.data(), &pubkey, privateKey.data(), nullptr, nullptr) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_SECRET;
            return {};
        }

        return secret;
    }

    std::vector<uint8_t> Secp256k1::signSchnorr(const std::vector<uint8_t>& privateKey,
                                                const std::vector<uint8_t>& hash) const {
        if (!isValidPrivateKey(privateKey.data())) {
            ctx->lastError = Secp256k1Error::INVALID_PRIVATE_KEY;
            return {};
        }

        if (hash.size() != 32) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        std::vector<uint8_t> result(64);
        if (secp256k1_schnorrsig_sign32(ctx->ctx, result.data(), hash.data(),
                                        privateKey.data(), nullptr, nullptr) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return {};
        }

        return result;
    }

    bool Secp256k1::verifySchnorr(const std::vector<uint8_t>& signature,
                                   const std::vector<uint8_t>& hash,
                                   const std::vector<uint8_t>& publicKey) const {
        if (signature.size() != 64) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return false;
        }

        if (hash.size() != 32) {
            ctx->lastError = Secp256k1Error::INVALID_SIGNATURE;
            return false;
        }

        if (publicKey.size() != 32) { // x-only public key
            ctx->lastError = Secp256k1Error::INVALID_PUBLIC_KEY;
            return false;
        }

        secp256k1_xonly_pubkey xonly;
        if (secp256k1_xonly_pubkey_parse(ctx->ctx, &xonly, publicKey.data()) != 1) {
            ctx->lastError = Secp256k1Error::INVALID_PUBLIC_KEY;
            return false;
        }

        int result = secp256k1_schnorrsig_verify32(ctx->ctx, signature.data(), hash.data(), 32, &xonly);
        if (result != 1) {
            ctx->lastError = Secp256k1Error::VERIFICATION_FAILED;
        }
        return result == 1;
    }

    std::string Secp256k1::getErrorMessage(Secp256k1Error error) {
        switch (error) {
            case Secp256k1Error::SUCCESS:
                return "Success";
            case Secp256k1Error::INVALID_PRIVATE_KEY:
                return "Invalid private key";
            case Secp256k1Error::INVALID_PUBLIC_KEY:
                return "Invalid public key";
            case Secp256k1Error::INVALID_SIGNATURE:
                return "Invalid signature";
            case Secp256k1Error::INVALID_RECOVERY_ID:
                return "Invalid recovery ID";
            case Secp256k1Error::VERIFICATION_FAILED:
                return "Signature verification failed";
            case Secp256k1Error::RECOVERY_FAILED:
                return "Public key recovery failed";
            case Secp256k1Error::TWEAK_FAILED:
                return "Key tweak failed";
            case Secp256k1Error::NEGATION_FAILED:
                return "Key negation failed";
            case Secp256k1Error::INVALID_SECRET:
                return "Invalid shared secret";
            case Secp256k1Error::INVALID_TWEAK:
                return "Invalid tweak value";
            default:
                return "Unknown error";
        }
    }

    Secp256k1Error Secp256k1::getLastError() const {
        return ctx->lastError;
    }

    void Secp256k1::clearLastError() {
        ctx->lastError = Secp256k1Error::SUCCESS;
    }

    Secp256k1ContextFlag Secp256k1::getContextFlags() const {
        return ctx->flags;
    }

    void Secp256k1::randomize(const std::vector<uint8_t>& seed) {
        if (seed.size() >= 32) {
            secp256k1_context_randomize(ctx->ctx, seed.data());
        }
    }

    // ============== Secp256k1KeyPair Implementation ==============

    Secp256k1KeyPair::Secp256k1KeyPair(const Secp256k1& ctx) {
        privateKey = ctx.generatePrivateKey();
        ctx.computePublicKey(privateKey, compressed, uncompressed);
    }

    Secp256k1KeyPair::Secp256k1KeyPair(const Secp256k1& ctx, const std::vector<uint8_t>& privKey) {
        if (!ctx.isPrivateKeyValid(privKey)) {
            throw std::invalid_argument("Invalid private key");
        }
        privateKey = privKey;
        ctx.computePublicKey(privateKey, compressed, uncompressed);
    }

    std::vector<uint8_t> Secp256k1KeyPair::sign(const Secp256k1& ctx,
                                                const std::vector<uint8_t>& hash) const {
        return ctx.sign(privateKey, hash);
    }

    bool Secp256k1KeyPair::verify(const Secp256k1& ctx, const std::vector<uint8_t>& signature,
                                   const std::vector<uint8_t>& hash) const {
        return ctx.verify(signature, hash, compressed);
    }

    // ============== Secp256k1Signature Implementation ==============

    Secp256k1Signature::Secp256k1Signature(const std::vector<uint8_t>& sig, SignatureType t)
        : signature(sig), type(t), recoveryId(0) {
        if (t == SignatureType::COMPACT && sig.size() == SECP256K1_COMPACT_SIGNATURE_SIZE) {
            recoveryId = sig[64];
        }
    }

    bool Secp256k1Signature::verify(const Secp256k1& ctx, const std::vector<uint8_t>& hash,
                                     const std::vector<uint8_t>& pubKey) const {
        if (type == SignatureType::COMPACT) {
            std::vector<uint8_t> normal(signature.begin(), signature.begin() + 64);
            return ctx.verify(normal, hash, pubKey);
        }
        return ctx.verify(signature, hash, pubKey);
    }

    std::vector<uint8_t> Secp256k1Signature::toDER(const Secp256k1& ctx) const {
        if (type == SignatureType::COMPACT) {
            std::vector<uint8_t> normal(signature.begin(), signature.begin() + 64);
            return ctx.serializeToDER(normal);
        }
        return ctx.serializeToDER(signature);
    }

    Secp256k1Signature Secp256k1Signature::fromDER(const Secp256k1& ctx,
                                                   const std::vector<uint8_t>& der) {
        auto sig = ctx.parseFromDER(der);
        return Secp256k1Signature(sig, SignatureType::NORMAL);
    }

} // namespace powercoin