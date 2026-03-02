#ifndef POWERCOIN_SECP256K1_H
#define POWERCOIN_SECP256K1_H

#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <memory>

namespace powercoin {

    /**
     * secp256k1 curve parameters
     * Used in Bitcoin for public key cryptography
     */
    constexpr size_t SECP256K1_PRIVATE_KEY_SIZE = 32;
    constexpr size_t SECP256K1_PUBLIC_KEY_SIZE = 33;  // Compressed
    constexpr size_t SECP256K1_PUBLIC_KEY_UNCOMPRESSED_SIZE = 65;
    constexpr size_t SECP256K1_SIGNATURE_SIZE = 64;
    constexpr size_t SECP256K1_COMPACT_SIGNATURE_SIZE = 65;  // With recovery ID

    /**
     * secp256k1 public key type
     */
    enum class PublicKeyType {
        COMPRESSED,      // 33 bytes (0x02 or 0x03 + x coordinate)
        UNCOMPRESSED     // 65 bytes (0x04 + x + y)
    };

    /**
     * secp256k1 signature type
     */
    enum class SignatureType {
        NORMAL,          // 64 bytes (r + s)
        COMPACT          // 65 bytes (r + s + recovery ID)
    };

    /**
     * secp256k1 error codes
     */
    enum class Secp256k1Error {
        SUCCESS,
        INVALID_PRIVATE_KEY,
        INVALID_PUBLIC_KEY,
        INVALID_SIGNATURE,
        INVALID_RECOVERY_ID,
        VERIFICATION_FAILED,
        RECOVERY_FAILED,
        TWEAK_FAILED,
        NEGATION_FAILED,
        INVALID_SECRET,
        INVALID_TWEAK
    };

    /**
     * secp256k1 context flags
     */
    enum class Secp256k1ContextFlag {
        NONE = 0,
        VERIFY = 1,
        SIGN = 2,
        ALL = 3
    };

    /**
     * secp256k1 implementation
     * Provides elliptic curve cryptography for Bitcoin
     */
    class Secp256k1 {
    private:
        struct Context;
        std::unique_ptr<Context> ctx;

        // Internal helper methods
        bool isValidPrivateKey(const uint8_t* key) const;
        bool isValidPublicKey(const uint8_t* key, size_t len) const;
        bool isValidSignature(const uint8_t* sig, size_t len) const;

    public:
        /**
         * Constructor - initializes secp256k1 context
         * @param flags Context flags (SIGN, VERIFY, or ALL)
         */
        explicit Secp256k1(Secp256k1ContextFlag flags = Secp256k1ContextFlag::ALL);

        /**
         * Destructor
         */
        ~Secp256k1();

        // Disable copy
        Secp256k1(const Secp256k1&) = delete;
        Secp256k1& operator=(const Secp256k1&) = delete;

        /**
         * Generate a new private key
         * @return 32-byte private key
         */
        std::vector<uint8_t> generatePrivateKey() const;

        /**
         * Generate private key from seed
         * @param seed Seed bytes
         * @return 32-byte private key
         */
        std::vector<uint8_t> generatePrivateKeyFromSeed(const std::vector<uint8_t>& seed) const;

        /**
         * Compute public key from private key
         * @param privateKey 32-byte private key
         * @param compressed Whether to return compressed public key
         * @return Public key bytes
         * @throws Secp256k1Error if private key invalid
         */
        std::vector<uint8_t> computePublicKey(const std::vector<uint8_t>& privateKey,
                                              bool compressed = true) const;

        /**
         * Compute public key from private key (both formats)
         * @param privateKey 32-byte private key
         * @param compressed Output compressed public key
         * @param uncompressed Output uncompressed public key
         * @return true if successful
         */
        bool computePublicKey(const std::vector<uint8_t>& privateKey,
                              std::vector<uint8_t>& compressed,
                              std::vector<uint8_t>& uncompressed) const;

        /**
         * Sign a message hash
         * @param privateKey 32-byte private key
         * @param hash 32-byte message hash
         * @return 64-byte signature (r + s)
         * @throws Secp256k1Error if signing fails
         */
        std::vector<uint8_t> sign(const std::vector<uint8_t>& privateKey,
                                   const std::vector<uint8_t>& hash) const;

        /**
         * Sign with compact signature (includes recovery ID)
         * @param privateKey 32-byte private key
         * @param hash 32-byte message hash
         * @return 65-byte compact signature (r + s + recovery ID)
         * @throws Secp256k1Error if signing fails
         */
        std::vector<uint8_t> signCompact(const std::vector<uint8_t>& privateKey,
                                          const std::vector<uint8_t>& hash) const;

        /**
         * Verify signature
         * @param signature 64-byte signature
         * @param hash 32-byte message hash
         * @param publicKey Public key bytes
         * @return true if signature is valid
         */
        bool verify(const std::vector<uint8_t>& signature,
                    const std::vector<uint8_t>& hash,
                    const std::vector<uint8_t>& publicKey) const;

        /**
         * Recover public key from compact signature
         * @param signature 65-byte compact signature (with recovery ID)
         * @param hash 32-byte message hash
         * @param compressed Whether to return compressed public key
         * @return Recovered public key
         * @throws Secp256k1Error if recovery fails
         */
        std::vector<uint8_t> recoverPublicKey(const std::vector<uint8_t>& signature,
                                               const std::vector<uint8_t>& hash,
                                               bool compressed = true) const;

        /**
         * Tweak private key (add a tweak value)
         * @param privateKey Original private key
         * @param tweak 32-byte tweak value
         * @return Tweaked private key
         * @throws Secp256k1Error if tweak fails
         */
        std::vector<uint8_t> tweakPrivateKey(const std::vector<uint8_t>& privateKey,
                                              const std::vector<uint8_t>& tweak) const;

        /**
         * Tweak public key (add a tweak value)
         * @param publicKey Original public key
         * @param tweak 32-byte tweak value
         * @return Tweaked public key
         * @throws Secp256k1Error if tweak fails
         */
        std::vector<uint8_t> tweakPublicKey(const std::vector<uint8_t>& publicKey,
                                             const std::vector<uint8_t>& tweak) const;

        /**
         * Negate private key
         * @param privateKey Original private key
         * @return Negated private key
         * @throws Secp256k1Error if negation fails
         */
        std::vector<uint8_t> negatePrivateKey(const std::vector<uint8_t>& privateKey) const;

        /**
         * Negate public key
         * @param publicKey Original public key
         * @return Negated public key
         * @throws Secp256k1Error if negation fails
         */
        std::vector<uint8_t> negatePublicKey(const std::vector<uint8_t>& publicKey) const;

        /**
         * Convert public key between compressed and uncompressed
         * @param publicKey Original public key
         * @param compressed Whether to output compressed format
         * @return Converted public key
         * @throws Secp256k1Error if conversion fails
         */
        std::vector<uint8_t> convertPublicKey(const std::vector<uint8_t>& publicKey,
                                               bool compressed) const;

        /**
         * Get public key type
         * @param publicKey Public key bytes
         * @return Public key type
         * @throws Secp256k1Error if invalid public key
         */
        PublicKeyType getPublicKeyType(const std::vector<uint8_t>& publicKey) const;

        /**
         * Check if private key is valid
         * @param privateKey 32-byte private key
         * @return true if valid
         */
        bool isPrivateKeyValid(const std::vector<uint8_t>& privateKey) const;

        /**
         * Check if public key is valid
         * @param publicKey Public key bytes
         * @return true if valid
         */
        bool isPublicKeyValid(const std::vector<uint8_t>& publicKey) const;

        /**
         * Check if signature is valid
         * @param signature Signature bytes
         * @return true if valid format
         */
        bool isSignatureValid(const std::vector<uint8_t>& signature) const;

        /**
         * Get recovery ID from compact signature
         * @param signature 65-byte compact signature
         * @return Recovery ID (0-3)
         * @throws Secp256k1Error if invalid signature
         */
        uint8_t getRecoveryId(const std::vector<uint8_t>& signature) const;

        /**
         * Normalize signature (ensure low S value)
         * @param signature 64-byte signature
         * @return Normalized signature
         */
        std::vector<uint8_t> normalizeSignature(const std::vector<uint8_t>& signature) const;

        /**
         * Serialize signature to DER format
         * @param signature 64-byte signature
         * @return DER-encoded signature
         */
        std::vector<uint8_t> serializeToDER(const std::vector<uint8_t>& signature) const;

        /**
         * Parse signature from DER format
         * @param der DER-encoded signature
         * @return 64-byte signature
         * @throws Secp256k1Error if invalid DER
         */
        std::vector<uint8_t> parseFromDER(const std::vector<uint8_t>& der) const;

        /**
         * Compute shared secret (ECDH)
         * @param privateKey Private key
         * @param publicKey Other party's public key
         * @return 32-byte shared secret
         * @throws Secp256k1Error if ECDH fails
         */
        std::vector<uint8_t> computeSharedSecret(const std::vector<uint8_t>& privateKey,
                                                  const std::vector<uint8_t>& publicKey) const;

        /**
         * Schnorr signature (BIP340)
         * @param privateKey 32-byte private key
         * @param hash 32-byte message hash
         * @return 64-byte Schnorr signature
         * @throws Secp256k1Error if signing fails
         */
        std::vector<uint8_t> signSchnorr(const std::vector<uint8_t>& privateKey,
                                          const std::vector<uint8_t>& hash) const;

        /**
         * Verify Schnorr signature (BIP340)
         * @param signature 64-byte Schnorr signature
         * @param hash 32-byte message hash
         * @param publicKey 32-byte x-only public key
         * @return true if valid
         */
        bool verifySchnorr(const std::vector<uint8_t>& signature,
                           const std::vector<uint8_t>& hash,
                           const std::vector<uint8_t>& publicKey) const;

        /**
         * Get error message
         * @param error Error code
         * @return Human-readable error message
         */
        static std::string getErrorMessage(Secp256k1Error error);

        /**
         * Get last error
         * @return Last error code
         */
        Secp256k1Error getLastError() const;

        /**
         * Clear last error
         */
        void clearLastError();

        /**
         * Get context flags
         * @return Context flags
         */
        Secp256k1ContextFlag getContextFlags() const;

        /**
         * Randomize context for side-channel protection
         * @param seed 32-byte random seed
         */
        void randomize(const std::vector<uint8_t>& seed);
    };

    /**
     * secp256k1 key pair (private + public)
     */
    class Secp256k1KeyPair {
    private:
        std::vector<uint8_t> privateKey;
        std::vector<uint8_t> publicKeyCompressed;
        std::vector<uint8_t> publicKeyUncompressed;

    public:
        /**
         * Generate new random key pair
         * @param ctx secp256k1 context
         */
        Secp256k1KeyPair(const Secp256k1& ctx);

        /**
         * Create key pair from private key
         * @param ctx secp256k1 context
         * @param privKey 32-byte private key
         * @throws Secp256k1Error if private key invalid
         */
        Secp256k1KeyPair(const Secp256k1& ctx, const std::vector<uint8_t>& privKey);

        /**
         * Get private key
         * @return 32-byte private key
         */
        const std::vector<uint8_t>& getPrivateKey() const { return privateKey; }

        /**
         * Get compressed public key (33 bytes)
         * @return Compressed public key
         */
        const std::vector<uint8_t>& getCompressedPublicKey() const { return publicKeyCompressed; }

        /**
         * Get uncompressed public key (65 bytes)
         * @return Uncompressed public key
         */
        const std::vector<uint8_t>& getUncompressedPublicKey() const { return publicKeyUncompressed; }

        /**
         * Sign message hash
         * @param hash 32-byte message hash
         * @return 64-byte signature
         */
        std::vector<uint8_t> sign(const Secp256k1& ctx, const std::vector<uint8_t>& hash) const;

        /**
         * Verify signature
         * @param signature 64-byte signature
         * @param hash 32-byte message hash
         * @return true if valid
         */
        bool verify(const Secp256k1& ctx, const std::vector<uint8_t>& signature,
                    const std::vector<uint8_t>& hash) const;

        /**
         * Check if key pair is valid
         * @return true if valid
         */
        bool isValid() const { return !privateKey.empty() && !publicKeyCompressed.empty(); }
    };

    /**
     * secp256k1 signature wrapper
     */
    class Secp256k1Signature {
    private:
        std::vector<uint8_t> signature;
        SignatureType type;
        uint8_t recoveryId;

    public:
        /**
         * Create signature from bytes
         * @param sig Signature bytes
         * @param t Signature type
         */
        Secp256k1Signature(const std::vector<uint8_t>& sig, SignatureType t = SignatureType::NORMAL);

        /**
         * Get signature bytes
         * @return Signature bytes
         */
        const std::vector<uint8_t>& getBytes() const { return signature; }

        /**
         * Get signature type
         * @return Signature type
         */
        SignatureType getType() const { return type; }

        /**
         * Get recovery ID (for compact signatures)
         * @return Recovery ID (0-3)
         */
        uint8_t getRecoveryId() const { return recoveryId; }

        /**
         * Check if signature is valid
         * @param ctx secp256k1 context
         * @param hash Message hash
         * @param pubKey Public key
         * @return true if valid
         */
        bool verify(const Secp256k1& ctx, const std::vector<uint8_t>& hash,
                    const std::vector<uint8_t>& pubKey) const;

        /**
         * Convert to DER format
         * @param ctx secp256k1 context
         * @return DER-encoded signature
         */
        std::vector<uint8_t> toDER(const Secp256k1& ctx) const;

        /**
         * Create from DER format
         * @param ctx secp256k1 context
         * @param der DER-encoded signature
         * @return Signature object
         */
        static Secp256k1Signature fromDER(const Secp256k1& ctx, const std::vector<uint8_t>& der);
    };

} // namespace powercoin

#endif // POWERCOIN_SECP256K1_H