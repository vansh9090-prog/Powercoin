#ifndef POWERCOIN_MNEMONIC_H
#define POWERCOIN_MNEMONIC_H

#include <string>
#include <vector>
#include <cstdint>
#include <array>
#include <functional>

namespace powercoin {

    /**
     * Supported mnemonic languages (BIP39)
     */
    enum class MnemonicLanguage {
        ENGLISH,
        CHINESE_SIMPLIFIED,
        CHINESE_TRADITIONAL,
        FRENCH,
        ITALIAN,
        JAPANESE,
        KOREAN,
        SPANISH,
        CZECH,
        PORTUGUESE
    };

    /**
     * Mnemonic strength in bits
     */
    enum class MnemonicStrength : uint16_t {
        BITS_128 = 128,  // 12 words
        BITS_160 = 160,  // 15 words
        BITS_192 = 192,  // 18 words
        BITS_224 = 224,  // 21 words
        BITS_256 = 256   // 24 words
    };

    /**
     * Mnemonic validation result
     */
    struct MnemonicValidationResult {
        bool isValid;
        std::string error;
        MnemonicStrength strength;
        MnemonicLanguage language;
        std::vector<uint8_t> entropy;
        std::vector<uint8_t> seed;
        std::string checksum;
        
        MnemonicValidationResult();
        std::string toString() const;
    };

    /**
     * Word list for BIP39 mnemonics
     */
    class WordList {
    private:
        std::vector<std::string> words;
        std::string language;
        std::map<std::string, uint16_t> wordToIndex;

    public:
        WordList() = default;
        explicit WordList(MnemonicLanguage language);

        bool load(MnemonicLanguage language);
        bool contains(const std::string& word) const;
        uint16_t getIndex(const std::string& word) const;
        std::string getWord(uint16_t index) const;
        size_t size() const { return words.size(); }
        const std::vector<std::string>& getWords() const { return words; }
        std::string getLanguage() const { return language; }

        static std::string languageToString(MnemonicLanguage language);
        static MnemonicLanguage stringToLanguage(const std::string& lang);
    };

    /**
     * Main mnemonic class (BIP39)
     * Handles seed phrase generation and validation
     */
    class Mnemonic {
    private:
        std::vector<std::string> words;
        std::vector<uint8_t> entropy;
        std::vector<uint8_t> seed;
        MnemonicStrength strength;
        MnemonicLanguage language;
        std::string passphrase;

        // Internal methods
        std::vector<uint8_t> generateEntropy(MnemonicStrength strength) const;
        std::vector<uint8_t> calculateChecksum(const std::vector<uint8_t>& entropy) const;
        std::vector<uint16_t> entropyToIndices(const std::vector<uint8_t>& entropy,
                                                const std::vector<uint8_t>& checksum) const;
        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> indicesToEntropy(
            const std::vector<uint16_t>& indices) const;

    public:
        /**
         * Constructor
         */
        Mnemonic();

        /**
         * Constructor with words
         * @param words Mnemonic words
         * @param language Mnemonic language
         */
        explicit Mnemonic(const std::vector<std::string>& words,
                          MnemonicLanguage language = MnemonicLanguage::ENGLISH);

        /**
         * Constructor with entropy
         * @param entropy Entropy bytes
         * @param language Mnemonic language
         */
        explicit Mnemonic(const std::vector<uint8_t>& entropy,
                          MnemonicLanguage language = MnemonicLanguage::ENGLISH);

        /**
         * Copy constructor
         */
        Mnemonic(const Mnemonic& other) = default;

        /**
         * Assignment operator
         */
        Mnemonic& operator=(const Mnemonic& other) = default;

        /**
         * Destructor
         */
        ~Mnemonic() = default;

        /**
         * Generate new mnemonic
         * @param strength Entropy strength
         * @param language Mnemonic language
         * @return Generated mnemonic
         */
        static Mnemonic generate(MnemonicStrength strength = MnemonicStrength::BITS_128,
                                 MnemonicLanguage language = MnemonicLanguage::ENGLISH);

        /**
         * Generate mnemonic from entropy
         * @param entropy Entropy bytes
         * @param language Mnemonic language
         * @return Mnemonic
         */
        static Mnemonic fromEntropy(const std::vector<uint8_t>& entropy,
                                     MnemonicLanguage language = MnemonicLanguage::ENGLISH);

        /**
         * Create mnemonic from words
         * @param words Mnemonic words
         * @param language Mnemonic language
         * @return Mnemonic
         */
        static Mnemonic fromWords(const std::vector<std::string>& words,
                                   MnemonicLanguage language = MnemonicLanguage::ENGLISH);

        /**
         * Create mnemonic from string
         * @param phrase Space-separated words
         * @param language Mnemonic language
         * @return Mnemonic
         */
        static Mnemonic fromString(const std::string& phrase,
                                    MnemonicLanguage language = MnemonicLanguage::ENGLISH);

        /**
         * Validate mnemonic phrase
         * @param phrase Mnemonic phrase
         * @param language Mnemonic language
         * @return Validation result
         */
        static MnemonicValidationResult validate(const std::string& phrase,
                                                 MnemonicLanguage language = MnemonicLanguage::ENGLISH);

        /**
         * Validate mnemonic words
         * @param words Mnemonic words
         * @param language Mnemonic language
         * @return Validation result
         */
        static MnemonicValidationResult validate(const std::vector<std::string>& words,
                                                 MnemonicLanguage language = MnemonicLanguage::ENGLISH);

        /**
         * Generate seed from mnemonic (BIP39)
         * @param passphrase Optional passphrase
         * @return 64-byte seed
         */
        std::vector<uint8_t> generateSeed(const std::string& passphrase = "") const;

        /**
         * Generate seed and store
         * @param passphrase Optional passphrase
         * @return true if successful
         */
        bool generateAndStoreSeed(const std::string& passphrase = "");

        /**
         * Get mnemonic words
         * @return Vector of words
         */
        const std::vector<std::string>& getWords() const { return words; }

        /**
         * Get mnemonic as string
         * @return Space-separated words
         */
        std::string toString() const;

        /**
         * Get entropy bytes
         * @return Entropy bytes
         */
        const std::vector<uint8_t>& getEntropy() const { return entropy; }

        /**
         * Get seed bytes
         * @return Seed bytes
         */
        const std::vector<uint8_t>& getSeed() const { return seed; }

        /**
         * Get mnemonic strength
         * @return Strength in bits
         */
        MnemonicStrength getStrength() const { return strength; }

        /**
         * Get word count
         * @return Number of words
         */
        size_t getWordCount() const { return words.size(); }

        /**
         * Get language
         * @return Mnemonic language
         */
        MnemonicLanguage getLanguage() const { return language; }

        /**
         * Check if mnemonic is valid
         * @return true if valid
         */
        bool isValid() const;

        /**
         * Check if seed is generated
         * @return true if seed exists
         */
        bool hasSeed() const { return !seed.empty(); }

        /**
         * Clear sensitive data
         */
        void clear();

        /**
         * Get word list for language
         * @param language Mnemonic language
         * @return Word list
         */
        static WordList getWordList(MnemonicLanguage language);

        /**
         * Get all supported languages
         * @return Vector of languages
         */
        static std::vector<MnemonicLanguage> getSupportedLanguages();

        /**
         * Get language name
         * @param language Mnemonic language
         * @return Language name string
         */
        static std::string languageToString(MnemonicLanguage language);

        /**
         * Get language from string
         * @param name Language name
         * @return Mnemonic language
         */
        static MnemonicLanguage languageFromString(const std::string& name);

        /**
         * Get strength name
         * @param strength Mnemonic strength
         * @return Strength description
         */
        static std::string strengthToString(MnemonicStrength strength);

        /**
         * Get word count for strength
         * @param strength Mnemonic strength
         * @return Number of words
         */
        static size_t strengthToWordCount(MnemonicStrength strength);

        /**
         * Get strength from word count
         * @param wordCount Number of words
         * @return Mnemonic strength
         */
        static MnemonicStrength wordCountToStrength(size_t wordCount);
    };

    /**
     * BIP39 seed derivation
     */
    class BIP39Seed {
    public:
        /**
         * Derive seed from mnemonic
         * @param mnemonic Mnemonic phrase
         * @param passphrase Optional passphrase
         * @return 64-byte seed
         */
        static std::vector<uint8_t> derive(const std::string& mnemonic,
                                            const std::string& passphrase = "");

        /**
         * Derive seed from words
         * @param words Mnemonic words
         * @param passphrase Optional passphrase
         * @return 64-byte seed
         */
        static std::vector<uint8_t> derive(const std::vector<std::string>& words,
                                            const std::string& passphrase = "");

        /**
         * Derive seed with PBKDF2
         * @param mnemonic Mnemonic bytes
         * @param salt Salt (mnemonic + passphrase)
         * @param iterations PBKDF2 iterations (default 2048)
         * @return 64-byte seed
         */
        static std::vector<uint8_t> pbkdf2(const std::vector<uint8_t>& mnemonic,
                                            const std::vector<uint8_t>& salt,
                                            uint32_t iterations = 2048);
    };

    /**
     * Mnemonic generator with progress callback
     */
    class MnemonicGenerator {
    private:
        MnemonicLanguage language;
        MnemonicStrength strength;
        std::function<void(double)> progressCallback;

    public:
        MnemonicGenerator();
        ~MnemonicGenerator() = default;

        void setLanguage(MnemonicLanguage lang) { language = lang; }
        void setStrength(MnemonicStrength str) { strength = str; }
        void setProgressCallback(std::function<void(double)> callback);

        Mnemonic generate();
        std::string generatePhrase();
    };

} // namespace powercoin

#endif // POWERCOIN_MNEMONIC_H