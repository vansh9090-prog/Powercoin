#ifndef POWERCOIN_DIFFICULTY_H
#define POWERCOIN_DIFFICULTY_H

#include <string>
#include <vector>
#include <cstdint>
#include <functional>
#include <memory>
#include <chrono>

namespace powercoin {

    /**
     * Difficulty adjustment algorithm types
     */
    enum class DifficultyAlgorithm {
        BITCOIN,            // Bitcoin-style (every 2016 blocks)
        DASH,               // Dark Gravity Wave (Dash)
        ETHEREUM,           // Ethereum-style (block time targeting)
        DIGISHIELD,         // DigiShield (rapid adjustment)
        KIMOTO_GRAVITY,     // Kimoto Gravity Well
        LWMA,               // Linear Weighted Moving Average
        SMA,                // Simple Moving Average
        EMA,                // Exponential Moving Average
        CUSTOM              // Custom algorithm
    };

    /**
     * Difficulty adjustment parameters
     */
    struct DifficultyParams {
        uint32_t targetBlockTime;           // Target time between blocks (seconds)
        uint32_t adjustmentInterval;        // Blocks between adjustments
        uint32_t minDifficulty;              // Minimum allowed difficulty
        uint32_t maxDifficulty;              // Maximum allowed difficulty
        double maxAdjustmentUp;              // Maximum upward adjustment factor
        double maxAdjustmentDown;            // Maximum downward adjustment factor
        uint32_t averagingWindow;            // Window size for averaging
        bool useTimeOffset;                   // Use timestamp offsets
        bool allowRetargeting;                 // Allow difficulty changes
        uint64_t genesisDifficulty;           // Starting difficulty

        DifficultyParams();
    };

    /**
     * Difficulty adjustment result
     */
    struct DifficultyResult {
        uint32_t newDifficulty;
        uint32_t previousDifficulty;
        double change;
        uint32_t actualTime;
        uint32_t expectedTime;
        double adjustmentFactor;
        bool valid;

        DifficultyResult();
        std::string toString() const;
    };

    /**
     * Block timestamp information
     */
    struct BlockTimeInfo {
        uint32_t height;
        uint32_t timestamp;
        uint32_t difficulty;
        uint32_t nonce;

        BlockTimeInfo();
    };

    /**
     * Base difficulty adjuster interface
     */
    class IDifficultyAdjuster {
    public:
        virtual ~IDifficultyAdjuster() = default;
        
        /**
         * Calculate next difficulty
         * @param timestamps Vector of block timestamps
         * @param difficulties Vector of block difficulties
         * @param currentHeight Current block height
         * @return New difficulty
         */
        virtual uint32_t calculateNextDifficulty(
            const std::vector<uint32_t>& timestamps,
            const std::vector<uint32_t>& difficulties,
            uint32_t currentHeight) const = 0;

        /**
         * Get algorithm name
         * @return Algorithm name
         */
        virtual std::string getAlgorithmName() const = 0;

        /**
         * Get parameters
         * @return Difficulty parameters
         */
        virtual DifficultyParams getParams() const = 0;

        /**
         * Validate difficulty
         * @param difficulty Difficulty to validate
         * @return true if valid
         */
        virtual bool validateDifficulty(uint32_t difficulty) const = 0;
    };

    /**
     * Bitcoin-style difficulty adjuster
     * Adjusts every 2016 blocks based on time taken
     */
    class BitcoinDifficultyAdjuster : public IDifficultyAdjuster {
    private:
        DifficultyParams params;

    public:
        explicit BitcoinDifficultyAdjuster(const DifficultyParams& p = DifficultyParams());
        
        uint32_t calculateNextDifficulty(
            const std::vector<uint32_t>& timestamps,
            const std::vector<uint32_t>& difficulties,
            uint32_t currentHeight) const override;

        std::string getAlgorithmName() const override { return "Bitcoin"; }
        DifficultyParams getParams() const override { return params; }
        bool validateDifficulty(uint32_t difficulty) const override;
    };

    /**
     * Dark Gravity Wave adjuster (Dash)
     * Uses weighted average of recent blocks
     */
    class DarkGravityWaveAdjuster : public IDifficultyAdjuster {
    private:
        DifficultyParams params;

    public:
        explicit DarkGravityWaveAdjuster(const DifficultyParams& p = DifficultyParams());
        
        uint32_t calculateNextDifficulty(
            const std::vector<uint32_t>& timestamps,
            const std::vector<uint32_t>& difficulties,
            uint32_t currentHeight) const override;

        std::string getAlgorithmName() const override { return "Dark Gravity Wave"; }
        DifficultyParams getParams() const override { return params; }
        bool validateDifficulty(uint32_t difficulty) const override;

    private:
        double calculateAverage(const std::vector<double>& values, size_t start, size_t count) const;
    };

    /**
     * DigiShield adjuster
     * Rapid adjustment for small coins
     */
    class DigiShieldAdjuster : public IDifficultyAdjuster {
    private:
        DifficultyParams params;

    public:
        explicit DigiShieldAdjuster(const DifficultyParams& p = DifficultyParams());
        
        uint32_t calculateNextDifficulty(
            const std::vector<uint32_t>& timestamps,
            const std::vector<uint32_t>& difficulties,
            uint32_t currentHeight) const override;

        std::string getAlgorithmName() const override { return "DigiShield"; }
        DifficultyParams getParams() const override { return params; }
        bool validateDifficulty(uint32_t difficulty) const override;
    };

    /**
     * LWMA (Linear Weighted Moving Average) adjuster
     */
    class LWMADifficultyAdjuster : public IDifficultyAdjuster {
    private:
        DifficultyParams params;

    public:
        explicit LWMADifficultyAdjuster(const DifficultyParams& p = DifficultyParams());
        
        uint32_t calculateNextDifficulty(
            const std::vector<uint32_t>& timestamps,
            const std::vector<uint32_t>& difficulties,
            uint32_t currentHeight) const override;

        std::string getAlgorithmName() const override { return "LWMA"; }
        DifficultyParams getParams() const override { return params; }
        bool validateDifficulty(uint32_t difficulty) const override;
    };

    /**
     * Main difficulty manager
     */
    class DifficultyManager {
    private:
        std::unique_ptr<IDifficultyAdjuster> adjuster;
        DifficultyParams params;
        DifficultyAlgorithm algorithm;
        
        std::vector<BlockTimeInfo> blockHistory;
        uint32_t currentDifficulty;
        uint32_t nextDifficulty;
        uint64_t totalWork;

        mutable std::mutex mutex;

    public:
        /**
         * Constructor
         * @param algorithm Difficulty algorithm
         * @param params Difficulty parameters
         */
        explicit DifficultyManager(
            DifficultyAlgorithm algorithm = DifficultyAlgorithm::BITCOIN,
            const DifficultyParams& params = DifficultyParams());

        /**
         * Destructor
         */
        ~DifficultyManager();

        // Disable copy
        DifficultyManager(const DifficultyManager&) = delete;
        DifficultyManager& operator=(const DifficultyManager&) = delete;

        /**
         * Initialize difficulty manager
         * @param genesisDifficulty Initial difficulty
         * @return true if successful
         */
        bool initialize(uint32_t genesisDifficulty);

        /**
         * Add new block
         * @param timestamp Block timestamp
         * @param difficulty Block difficulty
         * @param nonce Block nonce
         */
        void addBlock(uint32_t timestamp, uint32_t difficulty, uint32_t nonce);

        /**
         * Calculate next difficulty
         * @param currentHeight Current block height
         * @return Next difficulty
         */
        uint32_t calculateNextDifficulty(uint32_t currentHeight);

        /**
         * Get current difficulty
         * @return Current difficulty
         */
        uint32_t getCurrentDifficulty() const { return currentDifficulty; }

        /**
         * Get next difficulty
         * @return Next difficulty
         */
        uint32_t getNextDifficulty() const { return nextDifficulty; }

        /**
         * Get total chain work
         * @return Total work
         */
        uint64_t getTotalWork() const;

        /**
         * Get network hashrate estimate
         * @param blocks Number of blocks to average
         * @return Estimated hashrate in H/s
         */
        double estimateHashrate(uint32_t blocks = 24) const;

        /**
         * Get average block time
         * @param blocks Number of blocks to average
         * @return Average block time in seconds
         */
        double getAverageBlockTime(uint32_t blocks = 24) const;

        /**
         * Check if difficulty should adjust
         * @param currentHeight Current height
         * @return true if adjustment needed
         */
        bool shouldAdjust(uint32_t currentHeight) const;

        /**
         * Validate block difficulty
         * @param blockHash Block hash
         * @param difficulty Block difficulty
         * @return true if valid
         */
        bool validateBlockDifficulty(const std::string& blockHash, uint32_t difficulty) const;

        /**
         * Get difficulty algorithm
         * @return Current algorithm
         */
        DifficultyAlgorithm getAlgorithm() const { return algorithm; }

        /**
         * Set difficulty algorithm
         * @param algo New algorithm
         */
        void setAlgorithm(DifficultyAlgorithm algo);

        /**
         * Get algorithm name
         * @return Algorithm name string
         */
        std::string getAlgorithmName() const;

        /**
         * Get difficulty parameters
         * @return Current parameters
         */
        DifficultyParams getParams() const { return params; }

        /**
         * Update difficulty parameters
         * @param p New parameters
         */
        void updateParams(const DifficultyParams& p);

        /**
         * Reset difficulty manager
         */
        void reset();

        /**
         * Get block history
         * @return Vector of block time info
         */
        std::vector<BlockTimeInfo> getBlockHistory() const;

        /**
         * Get difficulty as target
         * @param difficulty Difficulty
         * @return Target hex string
         */
        static std::string difficultyToTarget(uint32_t difficulty);

        /**
         * Get difficulty from target
         * @param target Target hex string
         * @return Difficulty
         */
        static uint32_t targetToDifficulty(const std::string& target);

        /**
         * Calculate work from difficulty
         * @param difficulty Difficulty
         * @return Work value
         */
        static uint64_t calculateWork(uint32_t difficulty);

        /**
         * Get minimum difficulty
         * @return Minimum allowed difficulty
         */
        uint32_t getMinDifficulty() const { return params.minDifficulty; }

        /**
         * Get maximum difficulty
         * @return Maximum allowed difficulty
         */
        uint32_t getMaxDifficulty() const { return params.maxDifficulty; }

        // Callbacks
        std::function<void(uint32_t, uint32_t, double)> onDifficultyChanged;
        std::function<void(const DifficultyResult&)> onAdjustment;
        std::function<void(const std::string&)> onError;
    };

    /**
     * Difficulty calculator utility
     */
    class DifficultyCalculator {
    public:
        /**
         * Calculate difficulty from hash
         * @param hash Block hash
         * @return Difficulty
         */
        static uint32_t fromHash(const std::string& hash);

        /**
         * Calculate target from difficulty
         * @param difficulty Difficulty
         * @return Target as integer
         */
        static uint64_t targetFromDifficulty(uint32_t difficulty);

        /**
         * Check if hash meets difficulty
         * @param hash Block hash
         * @param difficulty Required difficulty
         * @return true if hash meets difficulty
         */
        static bool meetsDifficulty(const std::string& hash, uint32_t difficulty);

        /**
         * Get required leading zeros
         * @param difficulty Difficulty
         * @return Number of leading zeros needed
         */
        static uint32_t getLeadingZeros(uint32_t difficulty);

        /**
         * Format difficulty as target
         * @param difficulty Difficulty
         * @return Target hex string
         */
        static std::string formatTarget(uint32_t difficulty);
    };

} // namespace powercoin

#endif // POWERCOIN_DIFFICULTY_H