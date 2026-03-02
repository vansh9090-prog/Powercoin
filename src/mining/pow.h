#ifndef POWERCOIN_POW_H
#define POWERCOIN_POW_H

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <memory>
#include <atomic>
#include <chrono>
#include "../blockchain/block.h"
#include "../crypto/sha256.h"

namespace powercoin {

    /**
     * PoW algorithm types
     */
    enum class PoWAlgorithm {
        SHA256D,        // Double SHA-256 (Bitcoin)
        SCRYPT,         // Scrypt (Litecoin)
        X11,            // X11 (Dash)
        ETHASH,         // Ethash (Ethereum)
        RANDOMX,        // RandomX (Monero)
        CUCKOO_CYCLE,   // Cuckoo Cycle (Grin)
        EQUIHASH,       // Equihash (Zcash)
        CUSTOM          // Custom algorithm
    };

    /**
     * Mining hardware types
     */
    enum class MiningHardware {
        CPU,
        GPU,
        FPGA,
        ASIC,
        HYBRID
    };

    /**
     * PoW configuration
     */
    struct PoWConfig {
        PoWAlgorithm algorithm;
        uint32_t initialDifficulty;
        uint32_t targetBlockTime;
        uint32_t difficultyAdjustmentInterval;
        uint64_t maxNonce;
        bool allowMining;
        MiningHardware preferredHardware;
        uint32_t numThreads;
        bool useSSE;
        bool useAVX;
        bool useCUDA;
        bool useOpenCL;
        std::string deviceId;
        size_t memoryLimit;

        PoWConfig();
    };

    /**
     * PoW solution result
     */
    struct PoWSolution {
        uint32_t nonce;
        std::string hash;
        std::string mixHash;
        uint64_t time;
        uint64_t hashes;
        double hashrate;
        bool valid;

        PoWSolution();
        std::string toString() const;
    };

    /**
     * Mining statistics
     */
    struct MiningStats {
        uint64_t totalHashes;
        uint64_t acceptedShares;
        uint64_t rejectedShares;
        uint64_t blocksFound;
        double currentHashrate;
        double averageHashrate;
        double peakHashrate;
        uint64_t uptime;
        uint32_t difficulty;
        double estimatedTime;
        uint64_t sharesPerMinute;

        MiningStats();
        std::string toString() const;
    };

    /**
     * PoW validator interface
     */
    class IPoWValidator {
    public:
        virtual ~IPoWValidator() = default;
        virtual bool validate(const Block& block, uint32_t difficulty) const = 0;
        virtual bool validate(const std::string& hash, uint32_t difficulty) const = 0;
        virtual uint32_t getDifficulty(const Block& block) const = 0;
    };

    /**
     * SHA-256d PoW validator (Bitcoin-style)
     */
    class SHA256dValidator : public IPoWValidator {
    public:
        bool validate(const Block& block, uint32_t difficulty) const override;
        bool validate(const std::string& hash, uint32_t difficulty) const override;
        uint32_t getDifficulty(const Block& block) const override;

        static std::string hashWithNonce(const std::string& data, uint32_t nonce);
        static uint64_t getWork(const std::string& hash);
    };

    /**
     * Main Proof of Work class
     * Handles mining and validation
     */
    class ProofOfWork {
    private:
        PoWConfig config;
        std::unique_ptr<IPoWValidator> validator;
        
        // Mining state
        std::atomic<bool> isMining;
        std::atomic<uint64_t> totalHashes;
        std::atomic<uint64_t> sharesFound;
        std::atomic<uint32_t> currentDifficulty;
        std::chrono::steady_clock::time_point startTime;

        // Callbacks
        std::function<void(const PoWSolution&)> onSolutionFound;
        std::function<void(const MiningStats&)> onStatsUpdate;
        std::function<void(const std::string&)> onError;

    public:
        /**
         * Constructor
         * @param config PoW configuration
         */
        explicit ProofOfWork(const PoWConfig& config = PoWConfig());

        /**
         * Destructor
         */
        ~ProofOfWork();

        // Disable copy
        ProofOfWork(const ProofOfWork&) = delete;
        ProofOfWork& operator=(const ProofOfWork&) = delete;

        /**
         * Initialize PoW
         * @return true if successful
         */
        bool initialize();

        /**
         * Validate block proof of work
         * @param block Block to validate
         * @return true if valid
         */
        bool validateBlock(const Block& block) const;

        /**
         * Validate hash against difficulty
         * @param hash Block hash
         * @param difficulty Difficulty target
         * @return true if valid
         */
        bool validateHash(const std::string& hash, uint32_t difficulty) const;

        /**
         * Get block difficulty
         * @param block Block
         * @return Difficulty
         */
        uint32_t getDifficulty(const Block& block) const;

        /**
         * Calculate next difficulty
         * @param timestamps Vector of block timestamps
         * @param difficulties Vector of block difficulties
         * @return Next difficulty
         */
        uint32_t calculateNextDifficulty(const std::vector<uint32_t>& timestamps,
                                          const std::vector<uint32_t>& difficulties) const;

        /**
         * Mine a block (single thread)
         * @param block Block to mine
         * @param startNonce Starting nonce
         * @return Solution (nonce, hash) or empty if not found
         */
        PoWSolution mineBlock(const Block& block, uint32_t startNonce = 0);

        /**
         * Mine a block with callback
         * @param block Block to mine
         * @param progressCallback Progress callback
         * @return Solution
         */
        PoWSolution mineBlock(const Block& block,
                              std::function<void(uint64_t, double)> progressCallback);

        /**
         * Start continuous mining
         * @param blockTemplate Block template provider
         */
        void startMining(std::function<Block()> blockTemplate);

        /**
         * Stop continuous mining
         */
        void stopMining();

        /**
         * Check if mining is active
         * @return true if mining
         */
        bool isActive() const { return isMining; }

        /**
         * Get mining statistics
         * @return Mining stats
         */
        MiningStats getStats() const;

        /**
         * Get current difficulty
         * @return Current difficulty
         */
        uint32_t getCurrentDifficulty() const { return currentDifficulty; }

        /**
         * Set current difficulty
         * @param difficulty New difficulty
         */
        void setCurrentDifficulty(uint32_t difficulty) { currentDifficulty = difficulty; }

        /**
         * Get total hashes computed
         * @return Total hashes
         */
        uint64_t getTotalHashes() const { return totalHashes; }

        /**
         * Reset statistics
         */
        void resetStats();

        /**
         * Get algorithm name
         * @return Algorithm name
         */
        std::string getAlgorithmName() const;

        /**
         * Get preferred hardware
         * @return Hardware type
         */
        MiningHardware getPreferredHardware() const { return config.preferredHardware; }

        /**
         * Estimate mining time
         * @param difficulty Target difficulty
         * @param hashrate Hashrate in H/s
         * @return Estimated time in seconds
         */
        static double estimateTime(uint32_t difficulty, double hashrate);

        /**
         * Difficulty to target
         * @param difficulty Difficulty
         * @return Target hex string
         */
        static std::string difficultyToTarget(uint32_t difficulty);

        /**
         * Target to difficulty
         * @param target Target hex string
         * @return Difficulty
         */
        static uint32_t targetToDifficulty(const std::string& target);

        /**
         * Calculate work from hash
         * @param hash Block hash
         * @return Work value
         */
        static uint64_t calculateWork(const std::string& hash);

        // Callbacks
        void setOnSolutionFound(std::function<void(const PoWSolution&)> callback);
        void setOnStatsUpdate(std::function<void(const MiningStats&)> callback);
        void setOnError(std::function<void(const std::string&)> callback);

    private:
        mutable std::mutex mutex;
        std::unique_ptr<std::thread> miningThread;
        std::atomic<bool> shouldStop;
    };

    /**
     * PoW difficulty adjuster
     */
    class DifficultyAdjuster {
    private:
        uint32_t targetBlockTime;
        uint32_t adjustmentInterval;
        uint32_t minDifficulty;
        uint32_t maxDifficulty;
        double adjustmentFactor;

    public:
        DifficultyAdjuster(uint32_t targetTime = 600,
                           uint32_t interval = 2016,
                           uint32_t minDiff = 1,
                           uint32_t maxDiff = UINT32_MAX,
                           double factor = 4.0);

        uint32_t calculateNextDifficulty(const std::vector<uint32_t>& timestamps,
                                          uint32_t currentDifficulty) const;

        uint32_t calculateNextDifficulty(const std::vector<Block>& blocks) const;

        uint32_t clampDifficulty(uint32_t difficulty) const;
    };

    /**
     * PoW hash calculator (optimized)
     */
    class PoWHash {
    public:
        static std::string sha256d(const std::string& data);
        static std::string sha256d(const uint8_t* data, size_t len);
        static std::string sha256dWithNonce(const std::string& data, uint32_t nonce);
        
        static bool checkTarget(const std::string& hash, uint32_t difficulty);
        static bool checkTarget(const uint8_t* hash, uint32_t difficulty);
        
        static uint32_t getDifficultyFromTarget(const std::string& target);
        static std::string getTargetFromDifficulty(uint32_t difficulty);
    };

} // namespace powercoin

#endif // POWERCOIN_POW_H