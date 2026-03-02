#ifndef POWERCOIN_CONSENSUS_H
#define POWERCOIN_CONSENSUS_H

#include <cstdint>
#include <vector>
#include <string>
#include <memory>
#include <functional>
#include "block.h"
#include "transaction.h"

namespace powercoin {

    /**
     * Consensus rules version
     */
    enum class ConsensusVersion : uint32_t {
        V0_GENESIS = 0,
        V1_BASIC = 1,
        V2_POW = 2,
        V3_POS = 3,
        V4_HYBRID = 4,
        V5_SMART_CONTRACTS = 5,
        V6_PRIVACY = 6,
        V7_GOVERNANCE = 7,
        V8_CROSS_CHAIN = 8,
        CURRENT = 8
    };

    /**
     * Consensus type
     */
    enum class ConsensusType {
        PROOF_OF_WORK,      // Bitcoin-style PoW
        PROOF_OF_STAKE,     // Ethereum-style PoS
        PROOF_OF_AUTHORITY, // Private chains
        HYBRID_POW_POS,     // Combined consensus
        DELEGATED_POS,      // DPoS
        PRACTICAL_BFT       // PBFT for sidechains
    };

    /**
     * Fork types
     */
    enum class ForkType {
        NONE,
        SOFT_FORK,
        HARD_FORK,
        CHAIN_SPLIT
    };

    /**
     * Consensus parameters for a specific block height
     */
    struct ConsensusParams {
        uint32_t height;
        uint32_t version;
        uint64_t blockReward;
        uint32_t difficulty;
        uint32_t targetBlockTime;
        uint32_t difficultyAdjustmentInterval;
        uint32_t halvingInterval;
        uint64_t maxBlockSize;
        uint32_t maxTransactionsPerBlock;
        uint32_t coinbaseMaturity;
        uint32_t minStakeAge;
        uint32_t maxStakeAge;
        uint64_t minStakeAmount;
        uint64_t maxMoney;
        bool allowSmartContracts;
        bool allowPrivacy;
        bool allowGovernance;
        std::string forkId;
        
        ConsensusParams();
        bool validate() const;
    };

    /**
     * Consensus rule set for a specific era
     */
    struct ConsensusRuleSet {
        uint32_t startHeight;
        uint32_t endHeight;
        ConsensusVersion version;
        ConsensusType type;
        
        // PoW parameters
        uint32_t powTargetSpacing;
        uint32_t powDifficultyAdjustmentInterval;
        std::string powAlgorithm; // "sha256", "scrypt", "x11", etc.
        
        // PoS parameters
        uint32_t posTargetSpacing;
        uint32_t posMinimumStake;
        uint32_t posMaximumStake;
        uint32_t posMinimumAge;
        uint32_t posMaximumAge;
        
        // Block limits
        uint32_t maxBlockWeight;
        uint32_t maxBlockSigops;
        uint64_t maxBlockGas;
        
        // Fee parameters
        uint64_t minRelayFee;
        uint64_t minTxFee;
        
        // Validation rules
        bool requireStandardTransactions;
        bool allowAnyoneCanSpend;
        bool enforceBlockHeight;
        bool enforceTimeLock;
        
        // Fork activation
        bool isActive;
        ForkType forkType;
        uint32_t activationHeight;
        std::string activationHash;
        
        ConsensusRuleSet();
        bool isEnabled(uint32_t height) const;
    };

    /**
     * Chain work information
     */
    struct ChainWork {
        uint64_t totalWork;
        std::string bestBlockHash;
        uint32_t bestHeight;
        double networkHashrate;
        uint64_t totalTransactions;
        uint64_t totalOutput;
        
        ChainWork();
        std::string toString() const;
        bool operator<(const ChainWork& other) const;
        bool operator>(const ChainWork& other) const;
    };

    /**
     * Fork description
     */
    struct ForkDescription {
        ForkType type;
        uint32_t activationHeight;
        std::string name;
        std::string description;
        std::string activationHash;
        std::vector<uint32_t> affectedHeights;
        std::vector<std::string> newRules;
        std::vector<std::string> deprecatedRules;
        
        ForkDescription();
        bool isActivated(uint32_t height) const;
    };

    /**
     * Main consensus class
     * Implements all consensus rules and validation
     */
    class Consensus {
    private:
        std::vector<ConsensusRuleSet> ruleSets;
        std::vector<ForkDescription> forks;
        ConsensusParams currentParams;
        ConsensusVersion activeVersion;
        ConsensusType activeType;
        
        // Validation caches
        mutable std::map<uint32_t, bool> blockValidationCache;
        mutable std::map<std::string, bool> txValidationCache;
        
        // Callbacks
        std::function<void(uint32_t, const ForkDescription&)> onForkActivated;
        std::function<void(uint32_t, uint32_t)> onDifficultyChanged;
        std::function<void(uint64_t, uint64_t)> onRewardChanged;
        
        // Internal methods
        bool validateProofOfWork(const Block& block, uint32_t difficulty) const;
        bool validateProofOfStake(const Block& block, const std::vector<Transaction>& stakes) const;
        bool validateHybridConsensus(const Block& block) const;
        bool validateBlockVersion(const Block& block) const;
        bool validateBlockSize(const Block& block) const;
        bool validateBlockTimestamp(const Block& block, uint32_t prevTimestamp) const;
        bool validateTransactions(const Block& block, const std::vector<Transaction>& mempool) const;
        bool validateCoinbase(const Transaction& tx, uint64_t expectedReward) const;
        bool validateStakeTransaction(const Transaction& tx) const;
        bool validateGovernanceTransaction(const Transaction& tx) const;
        bool validateSmartContract(const std::vector<uint8_t>& contract) const;
        
        uint32_t calculateNextPoWDifficulty(const std::vector<uint32_t>& timestamps,
                                           const std::vector<uint32_t>& difficulties) const;
        uint32_t calculateNextPoSDifficulty(const std::vector<uint64_t>& stakes,
                                           const std::vector<uint32_t>& ages) const;
        
        uint64_t calculateBlockReward(uint32_t height, uint64_t fees, uint64_t stakes) const;
        uint64_t calculateStakeReward(uint64_t amount, uint32_t age) const;
        
        ConsensusRuleSet getActiveRuleSet(uint32_t height) const;
        bool isForkActive(uint32_t height, const std::string& forkName) const;
        
    public:
        Consensus();
        ~Consensus();
        
        // Disable copy
        Consensus(const Consensus&) = delete;
        Consensus& operator=(const Consensus&) = delete;
        
        // Initialization
        bool initialize();
        bool loadRuleSets(const std::string& configFile);
        bool addRuleSet(const ConsensusRuleSet& rules);
        bool addFork(const ForkDescription& fork);
        
        // Block validation
        bool validateBlock(const Block& block, 
                          const Block& previousBlock,
                          const std::vector<Transaction>& mempool) const;
        bool validateBlockHeader(const BlockHeader& header,
                                const BlockHeader& previousHeader) const;
        bool validateProofOfWork(const Block& block) const;
        bool validateProofOfStake(const Block& block) const;
        
        // Transaction validation
        bool validateTransaction(const Transaction& tx,
                                const std::vector<UTXO>& utxos,
                                uint32_t currentHeight,
                                uint32_t currentTime) const;
        bool validateCoinbaseTransaction(const Transaction& tx, uint64_t expectedReward) const;
        bool validateStakeTransaction(const Transaction& tx, uint64_t stakeAmount) const;
        
        // Difficulty calculation
        uint32_t getNextDifficulty(const std::vector<Block>& lastBlocks) const;
        uint32_t getNextProofOfWorkDifficulty(const std::vector<Block>& lastBlocks) const;
        uint32_t getNextProofOfStakeDifficulty(const std::vector<Block>& lastBlocks) const;
        
        // Reward calculation
        uint64_t getBlockReward(uint32_t height) const;
        uint64_t getStakeReward(uint64_t amount, uint32_t age) const;
        uint64_t getMinerReward(uint32_t height, uint64_t fees) const;
        
        // Chain work
        ChainWork calculateChainWork(const std::vector<Block>& chain) const;
        bool isChainBetter(const ChainWork& current, const ChainWork& candidate) const;
        
        // Fork management
        bool isForkActivated(uint32_t height, ForkType type) const;
        std::vector<ForkDescription> getActiveForks(uint32_t height) const;
        bool handleFork(const Block& block, std::vector<Block>& orphanedBlocks) const;
        
        // Version management
        ConsensusVersion getVersion(uint32_t height) const;
        bool isVersionActive(ConsensusVersion version, uint32_t height) const;
        
        // Parameter access
        const ConsensusParams& getCurrentParams() const { return currentParams; }
        uint32_t getTargetBlockTime() const;
        uint32_t getDifficultyAdjustmentInterval() const;
        uint32_t getHalvingInterval() const;
        uint64_t getMaxMoney() const;
        
        // Consensus rules
        bool isStandardTransaction(const Transaction& tx) const;
        bool isAllowedScript(const std::vector<uint8_t>& script) const;
        bool isAllowedOpcode(OpCode op, uint32_t height) const;
        
        // Utility
        std::string getConsensusName() const;
        std::string getVersionName(ConsensusVersion version) const;
        void printConsensusInfo() const;
        
        // Callback registration
        void setOnForkActivated(std::function<void(uint32_t, const ForkDescription&)> callback);
        void setOnDifficultyChanged(std::function<void(uint32_t, uint32_t)> callback);
        void setOnRewardChanged(std::function<void(uint64_t, uint64_t)> callback);
        
        // Static constants
        static constexpr uint32_t MAX_BLOCK_SIGOPS = 20000;
        static constexpr uint32_t MAX_TX_SIGOPS = 4000;
        static constexpr uint32_t MAX_PUBKEYS_PER_MULTISIG = 20;
        static constexpr uint32_t MAX_SCRIPT_ELEMENT_SIZE = 520;
        static constexpr uint32_t MAX_SCRIPT_SIZE = 10000;
        static constexpr uint32_t MAX_STACK_SIZE = 1000;
        static constexpr uint32_t MAX_OP_COUNT = 201;
        static constexpr uint64_t MIN_DUST_AMOUNT = 546;
        static constexpr uint32_t COINBASE_MATURITY = 100;
        static constexpr uint32_t STAKE_MIN_AGE = 8 * 60 * 60; // 8 hours
        static constexpr uint32_t STAKE_MAX_AGE = 90 * 24 * 60 * 60; // 90 days
    };

    /**
     * Consensus factory for creating rule sets
     */
    class ConsensusFactory {
    public:
        static ConsensusRuleSet createBitcoinLikeRules();
        static ConsensusRuleSet createEthereumLikeRules();
        static ConsensusRuleSet createPowerCoinMainNet();
        static ConsensusRuleSet createPowerCoinTestNet();
        static ConsensusRuleSet createPowerCoinRegTest();
        
        static ForkDescription createSegWitFork();
        static ForkDescription createTaprootFork();
        static ForkDescription createSmartContractFork();
        static ForkDescription createPrivacyFork();
        static ForkDescription createGovernanceFork();
    };

} // namespace powercoin

#endif // POWERCOIN_CONSENSUS_H