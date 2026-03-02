#ifndef POWERCOIN_STRATUM_H
#define POWERCOIN_STRATUM_H

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <functional>
#include <atomic>
#include <thread>
#include <mutex>
#include <websocketpp/client.hpp>
#include <websocketpp/config/asio_client.hpp>
#include <nlohmann/json.hpp>

namespace powercoin {

    /**
     * Stratum protocol types
     */
    enum class StratumProtocol {
        STRATUM_V1,      // Original Stratum
        STRATUM_V2,      // Stratum V2 (BetterHash)
        STRATUM_V1_EXT,  // Stratum V1 with extensions
        BTCCOM,          // BTC.com protocol
        F2POOL,          // F2Pool protocol
        ANTMPOOL         // Antpool protocol
    };

    /**
     * Stratum connection state
     */
    enum class StratumState {
        DISCONNECTED,
        CONNECTING,
        CONNECTED,
        SUBSCRIBED,
        AUTHORIZED,
        MINING,
        ERROR,
        RECONNECTING
    };

    /**
     * Stratum job
     */
    struct StratumJob {
        std::string jobId;
        std::string prevHash;
        std::string coinbase1;
        std::string coinbase2;
        std::vector<std::string> merkleBranches;
        std::string version;
        std::string nbits;
        std::string ntime;
        bool cleanJobs;
        uint32_t height;
        uint32_t difficulty;
        uint64_t target;

        StratumJob();
        std::string toString() const;
        bool isValid() const;
    };

    /**
     * Stratum share
     */
    struct StratumShare {
        std::string jobId;
        std::string nonce;
        std::string ntime;
        std::string hash;
        uint32_t difficulty;
        bool isBlock;
        std::string worker;
        uint64_t timestamp;

        StratumShare();
        std::string toString() const;
    };

    /**
     * Stratum configuration
     */
    struct StratumConfig {
        std::string host;
        uint16_t port;
        std::string username;
        std::string password;
        std::string workerName;
        StratumProtocol protocol;
        bool useSSL;
        uint32_t reconnectDelay;
        uint32_t timeout;
        uint32_t maxRetries;
        bool subscribeExtranonce;
        std::string version;

        StratumConfig();
    };

    /**
     * Stratum statistics
     */
    struct StratumStats {
        StratumState state;
        uint64_t uptime;
        uint64_t jobsReceived;
        uint64_t sharesSubmitted;
        uint64_t sharesAccepted;
        uint64_t sharesRejected;
        uint64_t blocksFound;
        double averageLatency;
        uint32_t lastDifficulty;
        uint32_t reconnectCount;
        std::string lastError;

        StratumStats();
        std::string toString() const;
    };

    /**
     * Stratum client for mining pools
     */
    class StratumClient {
    private:
        StratumConfig config;
        StratumStats stats;
        StratumState state;

        // WebSocket connection
        using WebsocketClient = websocketpp::client<websocketpp::config::asio_tls_client>;
        std::unique_ptr<WebsocketClient> wsClient;
        websocketpp::connection_hdl connection;
        std::thread networkThread;
        std::atomic<bool> running;

        // Stratum state
        std::string sessionId;
        uint32_t extranonce1;
        uint32_t extranonce2Size;
        std::map<std::string, StratumJob> jobs;
        StratumJob currentJob;

        // Mining
        std::string workerName;
        uint64_t nonceCounter;

        // Thread safety
        mutable std::mutex mutex;
        mutable std::mutex jobMutex;

        // Callbacks
        std::function<void(const StratumJob&)> onJobReceived;
        std::function<void(const StratumShare&)> onShareAccepted;
        std::function<void(const StratumShare&, const std::string&)> onShareRejected;
        std::function<void(const StratumStats&)> onStatsUpdate;
        std::function<void(const std::string&)> onError;
        std::function<void()> onConnected;
        std::function<void()> onDisconnected;

        // Internal methods
        void connect();
        void disconnect();
        void reconnect();
        void sendMessage(const nlohmann::json& message);
        void handleMessage(const std::string& payload);
        void handleStratumV1(const nlohmann::json& message);
        void handleStratumV2(const nlohmann::json& message);

        // Stratum V1 methods
        void sendSubscribe();
        void sendAuthorize();
        void sendSubmit(const StratumShare& share);
        void parseJob(const nlohmann::json& params);

        // Stratum V2 methods
        void sendSetupConnection();
        void sendSubmitShare(const StratumShare& share);

        // Utility
        std::string generateNonce();
        bool validateShare(const StratumShare& share);

    public:
        /**
         * Constructor
         * @param config Stratum configuration
         */
        explicit StratumClient(const StratumConfig& config);

        /**
         * Destructor
         */
        ~StratumClient();

        // Disable copy
        StratumClient(const StratumClient&) = delete;
        StratumClient& operator=(const StratumClient&) = delete;

        /**
         * Connect to mining pool
         * @return true if connection initiated
         */
        bool connect();

        /**
         * Disconnect from mining pool
         */
        void disconnect();

        /**
         * Check if connected
         * @return true if connected
         */
        bool isConnected() const;

        /**
         * Get current state
         * @return Stratum state
         */
        StratumState getState() const { return state; }

        /**
         * Get statistics
         * @return Stratum stats
         */
        StratumStats getStats() const;

        /**
         * Get current job
         * @return Current job
         */
        StratumJob getCurrentJob() const;

        /**
         * Submit share
         * @param share Share to submit
         * @return true if submitted
         */
        bool submitShare(const StratumShare& share);

        /**
         * Submit block
         * @param block Block data
         * @return true if submitted
         */
        bool submitBlock(const std::string& block);

        /**
         * Reconnect to pool
         */
        void reconnect();

        /**
         * Update configuration
         * @param config New configuration
         */
        void updateConfig(const StratumConfig& config);

        /**
         * Get worker name
         * @return Worker name
         */
        std::string getWorkerName() const { return workerName; }

        /**
         * Set worker name
         * @param name New worker name
         */
        void setWorkerName(const std::string& name);

        // Callbacks
        void setOnJobReceived(std::function<void(const StratumJob&)> callback);
        void setOnShareAccepted(std::function<void(const StratumShare&)> callback);
        void setOnShareRejected(std::function<void(const StratumShare&, const std::string&)> callback);
        void setOnStatsUpdate(std::function<void(const StratumStats&)> callback);
        void setOnError(std::function<void(const std::string&)> callback);
        void setOnConnected(std::function<void()> callback);
        void setOnDisconnected(std::function<void()> callback);
    };

    /**
     * Stratum job builder
     */
    class StratumJobBuilder {
    public:
        static StratumJob fromV1(const nlohmann::json& params);
        static StratumJob fromV2(const nlohmann::json& params);
        static std::string buildCoinbase(const StratumJob& job, const std::string& coinbaseExtra);
        static std::string buildMerkleRoot(const StratumJob& job, const std::string& coinbaseHash);
    };

    /**
     * Stratum share validator
     */
    class StratumShareValidator {
    public:
        static bool validate(const StratumShare& share, const StratumJob& job);
        static bool checkDifficulty(const std::string& hash, uint32_t difficulty);
        static uint32_t getShareDifficulty(const std::string& hash);
    };

    /**
     * Stratum protocol handler
     */
    class StratumProtocolHandler {
    public:
        static nlohmann::json createSubscribe(StratumProtocol protocol);
        static nlohmann::json createAuthorize(const std::string& username, const std::string& password);
        static nlohmann::json createSubmit(const StratumShare& share);
        static nlohmann::json createExtranonceSubscribe();
        static nlohmann::json createConfigure(const std::map<std::string, bool>& extensions);
        
        static bool parseResponse(const nlohmann::json& response, std::string& error);
        static bool parseJob(const nlohmann::json& message, StratumJob& job);
        static bool parseShare(const nlohmann::json& response, bool& accepted, std::string& error);
    };

} // namespace powercoin

#endif // POWERCOIN_STRATUM_H