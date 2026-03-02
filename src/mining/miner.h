#ifndef POWERCOIN_MINER_H
#define POWERCOIN_MINER_H

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>
#include <chrono>
#include "pow.h"
#include "../blockchain/blockchain.h"
#include "../wallet/wallet.h"

namespace powercoin {

    /**
     * Miner configuration
     */
    struct MinerConfig {
        std::string minerAddress;
        uint32_t numThreads;
        uint64_t nonceStep;
        uint64_t maxNonce;
        bool cpuMining;
        bool gpuMining;
        std::string gpuDevice;
        uint32_t gpuPlatform;
        uint32_t gpuDeviceId;
        uint64_t memoryLimit;
        bool enableLogging;
        std::string logFile;

        MinerConfig();
    };

    /**
     * Miner status
     */
    enum class MinerStatus {
        STOPPED,
        STARTING,
        RUNNING,
        PAUSED,
        ERROR,
        SHUTDOWN
    };

    /**
     * Block template for mining
     */
    struct BlockTemplate {
        uint32_t version;
        std::string previousBlockHash;
        std::string merkleRoot;
        uint32_t timestamp;
        uint32_t bits;
        uint32_t height;
        std::vector<Transaction> transactions;
        uint64_t reward;
        uint64_t fees;

        BlockTemplate();
        Block toBlock() const;
        std::string toString() const;
    };

    /**
     * Mining share
     */
    struct MiningShare {
        std::string blockHash;
        uint32_t height;
        uint32_t nonce;
        std::string hash;
        uint64_t timestamp;
        uint32_t difficulty;
        std::string minerAddress;
        bool valid;
        bool isBlock;

        MiningShare();
        std::string toString() const;
    };

    /**
     * Miner statistics
     */
    struct MinerStats {
        MinerStatus status;
        uint64_t uptime;
        uint64_t totalHashes;
        uint64_t acceptedShares;
        uint64_t rejectedShares;
        uint64_t blocksFound;
        double currentHashrate;
        double averageHashrate;
        double peakHashrate;
        uint32_t currentDifficulty;
        uint32_t threads;
        uint64_t memoryUsage;
        double temperature;
        double fanSpeed;
        double powerUsage;

        MinerStats();
        std::string toString() const;
    };

    /**
     * Mining thread worker
     */
    class MiningWorker {
    private:
        uint32_t threadId;
        std::unique_ptr<ProofOfWork> pow;
        std::atomic<bool> running;
        std::atomic<bool> paused;
        std::thread workerThread;
        
        uint64_t hashes;
        double hashrate;
        std::chrono::steady_clock::time_point startTime;

    public:
        MiningWorker(uint32_t id, const PoWConfig& config);
        ~MiningWorker();

        bool start(std::function<BlockTemplate()> templateProvider,
                   std::function<void(const MiningShare&)> shareCallback);
        void stop();
        void pause();
        void resume();

        uint64_t getHashes() const { return hashes; }
        double getHashrate() const;
        bool isRunning() const { return running; }
        uint32_t getId() const { return threadId; }
    };

    /**
     * Main miner class
     */
    class Miner {
    private:
        MinerConfig config;
        PoWConfig powConfig;
        std::unique_ptr<ProofOfWork> pow;
        std::vector<std::unique_ptr<MiningWorker>> workers;
        
        std::atomic<MinerStatus> status;
        std::atomic<uint64_t> totalHashes;
        std::atomic<uint64_t> acceptedShares;
        std::atomic<uint64_t> rejectedShares;
        std::atomic<uint64_t> blocksFound;
        
        std::chrono::steady_clock::time_point startTime;
        std::chrono::steady_clock::time_point lastStatsUpdate;
        
        mutable std::mutex statsMutex;
        mutable std::mutex templateMutex;
        
        // Callbacks
        std::function<void(const MiningShare&)> onShareFound;
        std::function<void(const Block&)> onBlockFound;
        std::function<void(const MinerStats&)> onStatsUpdate;
        std::function<void(const std::string&)> onError;

        // Block template management
        std::unique_ptr<BlockTemplate> currentTemplate;
        std::chrono::steady_clock::time_point templateTime;

        void updateStats();
        BlockTemplate generateBlockTemplate();

    public:
        /**
         * Constructor
         * @param config Miner configuration
         * @param powConfig PoW configuration
         */
        Miner(const MinerConfig& config, const PoWConfig& powConfig = PoWConfig());

        /**
         * Destructor
         */
        ~Miner();

        // Disable copy
        Miner(const Miner&) = delete;
        Miner& operator=(const Miner&) = delete;

        /**
         * Initialize miner
         * @param blockchain Blockchain reference
         * @param wallet Wallet reference
         * @return true if successful
         */
        bool initialize(Blockchain* blockchain, Wallet* wallet);

        /**
         * Start mining
         * @return true if started
         */
        bool start();

        /**
         * Stop mining
         */
        void stop();

        /**
         * Pause mining
         */
        void pause();

        /**
         * Resume mining
         */
        void resume();

        /**
         * Check if mining is active
         * @return true if running
         */
        bool isRunning() const { return status == MinerStatus::RUNNING; }

        /**
         * Get miner status
         * @return Current status
         */
        MinerStatus getStatus() const { return status; }

        /**
         * Get miner statistics
         * @return Miner stats
         */
        MinerStats getStats() const;

        /**
         * Reset statistics
         */
        void resetStats();

        /**
         * Set mining address
         * @param address New mining address
         */
        void setMiningAddress(const std::string& address);

        /**
         * Get mining address
         * @return Current mining address
         */
        std::string getMiningAddress() const { return config.minerAddress; }

        /**
         * Submit share (for pool mining)
         * @param share Mining share
         * @return true if accepted
         */
        bool submitShare(const MiningShare& share);

        /**
         * Submit block (for solo mining)
         * @param block Mined block
         * @return true if accepted
         */
        bool submitBlock(const Block& block);

        /**
         * Update block template
         * @param template New block template
         */
        void updateBlockTemplate(const BlockTemplate& bt);

        /**
         * Get current block template
         * @return Current template
         */
        BlockTemplate getCurrentTemplate() const;

        /**
         * Check if block template is stale
         * @return true if stale
         */
        bool isTemplateStale() const;

        /**
         * Get number of active threads
         * @return Thread count
         */
        uint32_t getThreadCount() const { return workers.size(); }

        /**
         * Set number of threads
         * @param count New thread count
         */
        void setThreadCount(uint32_t count);

        // Callbacks
        void setOnShareFound(std::function<void(const MiningShare&)> callback);
        void setOnBlockFound(std::function<void(const Block&)> callback);
        void setOnStatsUpdate(std::function<void(const MinerStats&)> callback);
        void setOnError(std::function<void(const std::string&)> callback);

    private:
        Blockchain* blockchain;
        Wallet* wallet;
    };

    /**
     * CPU miner implementation
     */
    class CPUMiner {
    private:
        PoWConfig config;
        std::vector<std::thread> threads;
        std::atomic<bool> running;
        std::atomic<uint64_t> totalHashes;

    public:
        explicit CPUMiner(const PoWConfig& config);
        ~CPUMiner();

        bool start(const BlockTemplate& tmpl,
                   std::function<void(const MiningShare&)> shareCallback);
        void stop();
        uint64_t getTotalHashes() const { return totalHashes; }
    };

    /**
     * GPU miner implementation (placeholder)
     */
    class GPUMiner {
    private:
        PoWConfig config;

    public:
        explicit GPUMiner(const PoWConfig& config);
        ~GPUMiner();

        bool initialize();
        bool start(const BlockTemplate& tmpl,
                   std::function<void(const MiningShare&)> shareCallback);
        void stop();
        bool isAvailable() const;
        std::string getDeviceInfo() const;
    };

    /**
     * Mining pool client
     */
    class MiningPoolClient {
    private:
        std::string poolUrl;
        uint16_t poolPort;
        std::string username;
        std::string password;
        std::string workerName;

    public:
        MiningPoolClient(const std::string& url, uint16_t port,
                         const std::string& user, const std::string& pass,
                         const std::string& worker = "");

        bool connect();
        void disconnect();
        bool submitShare(const MiningShare& share);
        bool submitBlock(const Block& block);
        BlockTemplate getWork();
        bool isConnected() const;

        // Callbacks
        std::function<void(const BlockTemplate&)> onWorkReceived;
        std::function<void(const std::string&)> onError;
    };

} // namespace powercoin

#endif // POWERCOIN_MINER_H