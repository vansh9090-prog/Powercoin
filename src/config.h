#ifndef POWERCOIN_CONFIG_H
#define POWERCOIN_CONFIG_H

#include <string>
#include <cstdint>
#include <vector>
#include <map>

namespace powercoin {

    /**
     * Network configuration constants
     */
    struct NetworkConfig {
        static constexpr uint32_t MAGIC_MAINNET = 0x5057524F;  // "PWRO"
        static constexpr uint32_t MAGIC_TESTNET = 0x50575254;  // "PWRT"
        static constexpr uint32_t MAGIC_REGTEST = 0x50575252;  // "PWRR"
        
        static constexpr uint16_t DEFAULT_PORT_MAINNET = 8333;
        static constexpr uint16_t DEFAULT_PORT_TESTNET = 18333;
        static constexpr uint16_t DEFAULT_PORT_REGTEST = 18444;
        
        static constexpr uint32_t PROTOCOL_VERSION = 70015;
        static constexpr uint32_t MIN_PROTOCOL_VERSION = 70001;
        
        static constexpr const char* SEED_NODES_MAINNET[] = {
            "seed.powercoin.net",
            "seed1.powercoin.net",
            "seed2.powercoin.net",
            "seed3.powercoin.net"
        };
        
        static constexpr const char* SEED_NODES_TESTNET[] = {
            "testnet-seed.powercoin.net",
            "testnet-seed1.powercoin.net"
        };
    };

    /**
     * Blockchain configuration constants
     */
    struct BlockchainConfig {
        static constexpr uint32_t TARGET_BLOCK_TIME = 600;           // 10 minutes
        static constexpr uint32_t DIFFICULTY_ADJUSTMENT_INTERVAL = 2016;
        static constexpr uint32_t HALVING_INTERVAL = 210000;
        static constexpr uint64_t INITIAL_BLOCK_REWARD = 50 * 100000000ULL; // 50 PWR
        static constexpr uint64_t TOTAL_SUPPLY = 21000000 * 100000000ULL;  // 21M PWR
        static constexpr uint32_t COINBASE_MATURITY = 100;
        static constexpr uint32_t MAX_BLOCK_SIZE = 4 * 1024 * 1024;  // 4 MB
        static constexpr uint32_t MAX_TRANSACTIONS_PER_BLOCK = 5000;
        static constexpr uint64_t MIN_RELAY_FEE = 1000;              // 0.00001000 PWR
        static constexpr uint64_t MIN_DUST_AMOUNT = 546;             // Dust limit
        static constexpr uint32_t MAX_MONEY = 21000000 * 100000000;  // 21M PWR
        static constexpr uint32_t COIN = 100000000;                  // 1 PWR = 10^8 satoshis
    };

    /**
     * Mining configuration constants
     */
    struct MiningConfig {
        static constexpr uint32_t DEFAULT_DIFFICULTY = 4;
        static constexpr uint32_t MAX_NONCE = UINT32_MAX;
        static constexpr uint32_t NUM_CPU_THREADS = 4;
        static constexpr bool ENABLE_GPU_MINING = false;
        static constexpr uint32_t MINING_STATS_INTERVAL = 60;        // seconds
        static constexpr uint32_t POW_RETARGET_TIMESPAN = 14 * 24 * 60 * 60; // 2 weeks
        static constexpr uint32_t POW_TARGET_TIMESPAN = 14 * 24 * 60 * 60;   // 2 weeks
        static constexpr uint32_t POW_TARGET_SPACING = 10 * 60;      // 10 minutes
        static constexpr uint32_t POW_INTERVAL = 2016;               // 2 weeks of blocks
    };

    /**
     * Wallet configuration constants
     */
    struct WalletConfig {
        static constexpr const char* DEFAULT_WALLET_DIR = "wallets";
        static constexpr const char* DEFAULT_WALLET_FILE = "wallet.dat";
        static constexpr uint32_t DEFAULT_MIN_CONFIRMATIONS = 6;
        static constexpr bool ENABLE_HD_WALLET = true;
        static constexpr uint32_t KEY_DERIVATION_ITERATIONS = 100000;
        static constexpr uint32_t DEFAULT_ACCOUNT_INDEX = 0;
        static constexpr uint32_t DEFAULT_ADDRESS_INDEX = 0;
        static constexpr const char* DEFAULT_ADDRESS_TYPE = "p2pkh";
    };

    /**
     * Database configuration constants
     */
    struct DatabaseConfig {
        static constexpr const char* CHAIN_FILE = "blockchain.dat";
        static constexpr const char* UTXO_FILE = "utxo.dat";
        static constexpr const char* MEMPOOL_FILE = "mempool.dat";
        static constexpr const char* PEERS_FILE = "peers.dat";
        static constexpr const char* LOG_FILE = "powercoin.log";
        static constexpr bool ENABLE_COMPRESSION = true;
        static constexpr uint32_t CACHE_SIZE = 500;                  // MB
        static constexpr uint32_t WRITE_BUFFER_SIZE = 64;            // MB
    };

    /**
     * Logging configuration constants
     */
    struct LoggingConfig {
        static constexpr const char* LOG_FORMAT = "[%Y-%m-%d %H:%M:%S] [%l] %v";
        static constexpr bool LOG_TO_FILE = true;
        static constexpr bool LOG_TO_CONSOLE = true;
        static constexpr uint32_t LOG_MAX_SIZE = 10 * 1024 * 1024;   // 10 MB
        static constexpr uint32_t LOG_MAX_FILES = 5;
        static constexpr const char* LOG_LEVEL = "info";              // debug, info, warn, error
        static constexpr bool LOG_TIMESTAMPS = true;
        static constexpr bool LOG_THREAD_ID = true;
    };

    /**
     * RPC configuration constants
     */
    struct RPCConfig {
        static constexpr uint16_t RPC_PORT = 8332;
        static constexpr const char* RPC_BIND = "127.0.0.1";
        static constexpr bool RPC_ENABLE_AUTH = true;
        static constexpr uint32_t RPC_THREADS = 4;
        static constexpr uint32_t RPC_TIMEOUT = 30;                  // seconds
        static constexpr uint32_t RPC_MAX_CONNECTIONS = 10;
        static constexpr const char* RPC_USER = "powercoinrpc";
        static constexpr const char* RPC_PASSWORD = "";              // Must be set
    };

    /**
     * Advanced features configuration
     */
    struct AdvancedConfig {
        static constexpr bool ENABLE_SMART_CONTRACTS = true;
        static constexpr bool ENABLE_PRIVACY = true;
        static constexpr bool ENABLE_GOVERNANCE = true;
        static constexpr bool ENABLE_CROSS_CHAIN = true;
        static constexpr bool ENABLE_LIGHTNING = true;
        static constexpr bool ENABLE_MASTERNODES = true;
        static constexpr bool ENABLE_QUANTUM_RESISTANT = false;      // Future feature
        static constexpr uint32_t SMART_CONTRACT_GAS_LIMIT = 1000000;
        static constexpr uint32_t GOVERNANCE_VOTING_PERIOD = 7 * 24 * 60 * 60; // 7 days
        static constexpr uint32_t MASTERNODE_COLLATERAL = 10000 * 100000000ULL; // 10,000 PWR
    };

    /**
     * Paths configuration
     */
    struct PathConfig {
        static constexpr const char* DATA_DIR_DEFAULT = "~/.powercoin";
        static constexpr const char* CONFIG_FILE = "powercoin.conf";
        static constexpr const char* PID_FILE = "powercoind.pid";
    };

    /**
     * Version information
     */
    struct VersionConfig {
        static constexpr uint32_t MAJOR_VERSION = 1;
        static constexpr uint32_t MINOR_VERSION = 0;
        static constexpr uint32_t PATCH_VERSION = 0;
        static constexpr const char* VERSION_STRING = "1.0.0";
        static constexpr const char* CLIENT_NAME = "PowerCoin Core";
        static constexpr const char* USER_AGENT = "/PowerCoin:1.0.0/";
    };

    /**
     * Global configuration class
     * Manages all runtime configuration
     */
    class Config {
    private:
        // Network settings
        std::string network;
        uint32_t magic;
        uint16_t port;
        std::vector<std::string> seedNodes;
        
        // Paths
        std::string dataDir;
        std::string configFile;
        std::string pidFile;
        
        // Runtime settings
        bool daemonMode;
        uint32_t verbosity;
        bool testnet;
        bool regtest;
        
        // RPC settings
        std::string rpcBind;
        uint16_t rpcPort;
        std::string rpcUser;
        std::string rpcPassword;
        bool rpcEnabled;
        
        // Feature flags
        bool enableSmartContracts;
        bool enablePrivacy;
        bool enableGovernance;
        bool enableCrossChain;
        bool enableLightning;
        bool enableMasternodes;
        
        // Mining settings
        bool enableMining;
        std::string miningAddress;
        uint32_t miningThreads;
        
        // Wallet settings
        std::string walletFile;
        std::string walletPassword;
        bool walletUnlocked;
        
        // Peer settings
        uint32_t maxConnections;
        uint32_t maxUploadTarget;
        
        // Internal
        bool initialized;
        
    public:
        Config();
        ~Config() = default;
        
        /**
         * Load configuration from command line and config file
         * @param argc Argument count
         * @param argv Argument values
         * @return true if successful
         */
        bool load(int argc, char** argv);
        
        /**
         * Save configuration to file
         * @return true if successful
         */
        bool save() const;
        
        /**
         * Print configuration
         */
        void print() const;
        
        /**
         * Validate configuration
         * @return true if valid
         */
        bool validate() const;
        
        /**
         * Get default config path
         * @return Default config file path
         */
        static std::string getDefaultConfigPath();
        
        /**
         * Get default data directory
         * @return Default data directory path
         */
        static std::string getDefaultDataDir();
        
        // Getters
        const std::string& getNetwork() const { return network; }
        uint32_t getMagic() const { return magic; }
        uint16_t getPort() const { return port; }
        const std::vector<std::string>& getSeedNodes() const { return seedNodes; }
        const std::string& getDataDir() const { return dataDir; }
        const std::string& getConfigFile() const { return configFile; }
        const std::string& getPidFile() const { return pidFile; }
        bool isDaemon() const { return daemonMode; }
        uint32_t getVerbosity() const { return verbosity; }
        bool isTestnet() const { return testnet; }
        bool isRegtest() const { return regtest; }
        
        const std::string& getRpcBind() const { return rpcBind; }
        uint16_t getRpcPort() const { return rpcPort; }
        const std::string& getRpcUser() const { return rpcUser; }
        const std::string& getRpcPassword() const { return rpcPassword; }
        bool isRpcEnabled() const { return rpcEnabled; }
        
        bool isSmartContractsEnabled() const { return enableSmartContracts; }
        bool isPrivacyEnabled() const { return enablePrivacy; }
        bool isGovernanceEnabled() const { return enableGovernance; }
        bool isCrossChainEnabled() const { return enableCrossChain; }
        bool isLightningEnabled() const { return enableLightning; }
        bool isMasternodesEnabled() const { return enableMasternodes; }
        
        bool isMiningEnabled() const { return enableMining; }
        const std::string& getMiningAddress() const { return miningAddress; }
        uint32_t getMiningThreads() const { return miningThreads; }
        
        const std::string& getWalletFile() const { return walletFile; }
        const std::string& getWalletPassword() const { return walletPassword; }
        bool isWalletUnlocked() const { return walletUnlocked; }
        
        uint32_t getMaxConnections() const { return maxConnections; }
        uint32_t getMaxUploadTarget() const { return maxUploadTarget; }
        
        // Setters
        void setNetwork(const std::string& net);
        void setDataDir(const std::string& dir);
        void setDaemon(bool daemon) { daemonMode = daemon; }
        void setVerbosity(uint32_t level) { verbosity = level; }
        void setTestnet(bool enable) { testnet = enable; }
        void setRegtest(bool enable) { regtest = enable; }
        
        void setRpcCredentials(const std::string& user, const std::string& pass);
        void setRpcBind(const std::string& bind) { rpcBind = bind; }
        void setRpcPort(uint16_t p) { rpcPort = p; }
        void setRpcEnabled(bool enable) { rpcEnabled = enable; }
        
        void setMiningEnabled(bool enable) { enableMining = enable; }
        void setMiningAddress(const std::string& addr) { miningAddress = addr; }
        void setMiningThreads(uint32_t threads) { miningThreads = threads; }
        
        void setWalletFile(const std::string& file) { walletFile = file; }
        void setWalletPassword(const std::string& pass) { walletPassword = pass; }
        void setWalletUnlocked(bool unlocked) { walletUnlocked = unlocked; }
        
        // Utility
        std::string getChainFile() const { return dataDir + "/" + DatabaseConfig::CHAIN_FILE; }
        std::string getUtxoFile() const { return dataDir + "/" + DatabaseConfig::UTXO_FILE; }
        std::string getMempoolFile() const { return dataDir + "/" + DatabaseConfig::MEMPOOL_FILE; }
        std::string getPeersFile() const { return dataDir + "/" + DatabaseConfig::PEERS_FILE; }
        std::string getLogFile() const { return dataDir + "/" + DatabaseConfig::LOG_FILE; }
        std::string getWalletDir() const { return dataDir + "/" + WalletConfig::DEFAULT_WALLET_DIR; }
        
        // Constants access
        static const NetworkConfig& Network() { static NetworkConfig nc; return nc; }
        static const BlockchainConfig& Blockchain() { static BlockchainConfig bc; return bc; }
        static const MiningConfig& Mining() { static MiningConfig mc; return mc; }
        static const WalletConfig& Wallet() { static WalletConfig wc; return wc; }
        static const DatabaseConfig& Database() { static DatabaseConfig dc; return dc; }
        static const LoggingConfig& Logging() { static LoggingConfig lc; return lc; }
        static const RPCConfig& RPC() { static RPCConfig rc; return rc; }
        static const AdvancedConfig& Advanced() { static AdvancedConfig ac; return ac; }
        static const PathConfig& Paths() { static PathConfig pc; return pc; }
        static const VersionConfig& Version() { static VersionConfig vc; return vc; }
        
    private:
        void setDefaults();
        bool parseConfigFile(const std::string& path);
        bool parseCommandLine(int argc, char** argv);
        void updateFromNetwork();
    };

    /**
     * Global config instance
     */
    extern Config gConfig;

} // namespace powercoin

#endif // POWERCOIN_CONFIG_H