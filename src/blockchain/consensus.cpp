#include "consensus.h"
#include "../crypto/sha256.h"
#include <cmath>
#include <algorithm>
#include <sstream>
#include <iomanip>

namespace powercoin {

    // ============== ConsensusParams Implementation ==============

    ConsensusParams::ConsensusParams()
        : height(0),
          version(0),
          blockReward(50 * 100000000ULL),
          difficulty(1),
          targetBlockTime(600),
          difficultyAdjustmentInterval(2016),
          halvingInterval(210000),
          maxBlockSize(4 * 1024 * 1024),
          maxTransactionsPerBlock(5000),
          coinbaseMaturity(100),
          minStakeAge(8 * 60 * 60),
          maxStakeAge(90 * 24 * 60 * 60),
          minStakeAmount(1000 * 100000000ULL),
          maxMoney(21000000 * 100000000ULL),
          allowSmartContracts(false),
          allowPrivacy(false),
          allowGovernance(false) {}

    bool ConsensusParams::validate() const {
        if (blockReward == 0) return false;
        if (targetBlockTime < 30) return false;
        if (difficultyAdjustmentInterval < 10) return false;
        if (maxBlockSize < 1024) return false;
        if (maxTransactionsPerBlock < 1) return false;
        if (coinbaseMaturity < 1) return false;
        if (minStakeAmount > maxMoney) return false;
        return true;
    }

    // ============== ConsensusRuleSet Implementation ==============

    ConsensusRuleSet::ConsensusRuleSet()
        : startHeight(0),
          endHeight(UINT32_MAX),
          version(ConsensusVersion::CURRENT),
          type(ConsensusType::PROOF_OF_WORK),
          powTargetSpacing(600),
          powDifficultyAdjustmentInterval(2016),
          powAlgorithm("sha256"),
          posTargetSpacing(600),
          posMinimumStake(1000),
          posMaximumStake(1000000),
          posMinimumAge(8 * 60 * 60),
          posMaximumAge(90 * 24 * 60 * 60),
          maxBlockWeight(4 * 1024 * 1024),
          maxBlockSigops(20000),
          maxBlockGas(10000000),
          minRelayFee(1000),
          minTxFee(1000),
          requireStandardTransactions(true),
          allowAnyoneCanSpend(false),
          enforceBlockHeight(true),
          enforceTimeLock(true),
          isActive(true),
          forkType(ForkType::NONE),
          activationHeight(0) {}

    bool ConsensusRuleSet::isEnabled(uint32_t height) const {
        return isActive && height >= startHeight && height <= endHeight;
    }

    // ============== ChainWork Implementation ==============

    ChainWork::ChainWork()
        : totalWork(0), bestHeight(0), networkHashrate(0),
          totalTransactions(0), totalOutput(0) {}

    std::string ChainWork::toString() const {
        std::stringstream ss;
        ss << "Chain Work: " << totalWork << "\n";
        ss << "Best Block: " << bestBlockHash.substr(0, 16) << "...\n";
        ss << "Height: " << bestHeight << "\n";
        ss << "Hashrate: " << networkHashrate << " H/s\n";
        ss << "Total Transactions: " << totalTransactions << "\n";
        ss << "Total Output: " << totalOutput / 100000000.0 << " PWR\n";
        return ss.str();
    }

    bool ChainWork::operator<(const ChainWork& other) const {
        return totalWork < other.totalWork;
    }

    bool ChainWork::operator>(const ChainWork& other) const {
        return totalWork > other.totalWork;
    }

    // ============== ForkDescription Implementation ==============

    ForkDescription::ForkDescription()
        : type(ForkType::NONE), activationHeight(0) {}

    bool ForkDescription::isActivated(uint32_t height) const {
        return height >= activationHeight;
    }

    // ============== Consensus Implementation ==============

    Consensus::Consensus() 
        : activeVersion(ConsensusVersion::CURRENT),
          activeType(ConsensusType::PROOF_OF_WORK) {}

    Consensus::~Consensus() = default;

    bool Consensus::initialize() {
        // Add default rule sets
        ruleSets.push_back(ConsensusFactory::createPowerCoinMainNet());
        currentParams.height = 0;
        currentParams.version = static_cast<uint32_t>(ConsensusVersion::CURRENT);
        return true;
    }

    bool Consensus::loadRuleSets(const std::string& configFile) {
        // TODO: Load rule sets from configuration file
        return true;
    }

    bool Consensus::addRuleSet(const ConsensusRuleSet& rules) {
        ruleSets.push_back(rules);
        std::sort(ruleSets.begin(), ruleSets.end(),
                 [](const ConsensusRuleSet& a, const ConsensusRuleSet& b) {
                     return a.startHeight < b.startHeight;
                 });
        return true;
    }

    bool Consensus::addFork(const ForkDescription& fork) {
        forks.push_back(fork);
        return true;
    }

    bool Consensus::validateBlock(const Block& block,
                                  const Block& previousBlock,
                                  const std::vector<Transaction>& mempool) const {
        // Validate block header
        if (!validateBlockHeader(block.getHeader(), previousBlock.getHeader())) {
            return false;
        }

        // Validate block version
        if (!validateBlockVersion(block)) {
            return false;
        }

        // Validate block size
        if (!validateBlockSize(block)) {
            return false;
        }

        // Validate consensus type
        auto rules = getActiveRuleSet(block.getHeight());
        switch (rules.type) {
            case ConsensusType::PROOF_OF_WORK:
                if (!validateProofOfWork(block)) {
                    return false;
                }
                break;
            case ConsensusType::PROOF_OF_STAKE:
                if (!validateProofOfStake(block)) {
                    return false;
                }
                break;
            case ConsensusType::HYBRID_POW_POS:
                if (!validateHybridConsensus(block)) {
                    return false;
                }
                break;
            default:
                break;
        }

        // Validate transactions
        if (!validateTransactions(block, mempool)) {
            return false;
        }

        return true;
    }

    bool Consensus::validateBlockHeader(const BlockHeader& header,
                                        const BlockHeader& previousHeader) const {
        // Check previous hash
        if (header.previousBlockHash != previousHeader.calculateHash()) {
            return false;
        }

        // Check timestamp
        if (!validateBlockTimestamp(header, previousHeader.timestamp)) {
            return false;
        }

        // Check version
        if (header.version > static_cast<uint32_t>(ConsensusVersion::CURRENT)) {
            return false;
        }

        return true;
    }

    bool Consensus::validateProofOfWork(const Block& block) const {
        return validateProofOfWork(block, block.getBits());
    }

    bool Consensus::validateProofOfWork(const Block& block, uint32_t difficulty) const {
        // Check if hash meets difficulty target
        std::string target(difficulty >> 24, '0');
        return block.getHash().substr(0, difficulty >> 24) == target;
    }

    bool Consensus::validateProofOfStake(const Block& block) const {
        // TODO: Implement PoS validation
        return true;
    }

    bool Consensus::validateProofOfStake(const Block& block, const std::vector<Transaction>& stakes) const {
        // TODO: Implement PoS validation with stakes
        return true;
    }

    bool Consensus::validateHybridConsensus(const Block& block) const {
        // Validate both PoW and PoS components
        if (!validateProofOfWork(block)) {
            return false;
        }
        if (!validateProofOfStake(block)) {
            return false;
        }
        return true;
    }

    bool Consensus::validateBlockVersion(const Block& block) const {
        auto rules = getActiveRuleSet(block.getHeight());
        return block.getVersion() >= static_cast<uint32_t>(rules.version);
    }

    bool Consensus::validateBlockSize(const Block& block) const {
        auto rules = getActiveRuleSet(block.getHeight());
        return block.getSize() <= rules.maxBlockWeight;
    }

    bool Consensus::validateBlockTimestamp(const Block& block, uint32_t prevTimestamp) const {
        auto rules = getActiveRuleSet(block.getHeight());
        
        // Check timestamp not too far in future
        uint32_t now = static_cast<uint32_t>(std::time(nullptr));
        if (block.getTimestamp() > now + 7200) { // 2 hours future limit
            return false;
        }

        // Check timestamp after previous block
        if (block.getTimestamp() <= prevTimestamp) {
            return false;
        }

        return true;
    }

    bool Consensus::validateTransactions(const Block& block,
                                         const std::vector<Transaction>& mempool) const {
        auto rules = getActiveRuleSet(block.getHeight());

        // Check transaction count
        if (block.getTransactions().empty() || 
            block.getTransactions().size() > rules.maxBlockWeight / 100) {
            return false;
        }

        uint64_t totalFees = 0;
        uint32_t totalSigops = 0;

        for (size_t i = 0; i < block.getTransactions().size(); i++) {
            const auto& tx = block.getTransactions()[i];

            if (i == 0) {
                // Coinbase transaction
                if (!validateCoinbase(tx, getBlockReward(block.getHeight()) + totalFees)) {
                    return false;
                }
            } else {
                // Regular transaction
                // TODO: Validate with UTXO set
                totalFees += tx.getFee();
            }

            // Check sigops
            totalSigops += tx.getSize() / 100; // Approximate
            if (totalSigops > rules.maxBlockSigops) {
                return false;
            }
        }

        return true;
    }

    bool Consensus::validateCoinbase(const Transaction& tx, uint64_t expectedReward) const {
        if (tx.getType() != TransactionType::COINBASE) {
            return false;
        }

        if (tx.getInputs().size() != 1) {
            return false;
        }

        if (tx.getOutputs().empty()) {
            return false;
        }

        // Check total output equals expected reward
        uint64_t totalOutput = tx.getTotalOutput();
        if (totalOutput > expectedReward + 10000) { // Allow small variance
            return false;
        }

        return true;
    }

    bool Consensus::validateCoinbaseTransaction(const Transaction& tx, uint64_t expectedReward) const {
        return validateCoinbase(tx, expectedReward);
    }

    bool Consensus::validateStakeTransaction(const Transaction& tx) const {
        // TODO: Implement stake transaction validation
        return true;
    }

    bool Consensus::validateStakeTransaction(const Transaction& tx, uint64_t stakeAmount) const {
        // TODO: Implement stake transaction validation with amount
        return true;
    }

    bool Consensus::validateGovernanceTransaction(const Transaction& tx) const {
        // TODO: Implement governance transaction validation
        return true;
    }

    bool Consensus::validateSmartContract(const std::vector<uint8_t>& contract) const {
        // TODO: Implement smart contract validation
        return true;
    }

    bool Consensus::validateTransaction(const Transaction& tx,
                                        const std::vector<UTXO>& utxos,
                                        uint32_t currentHeight,
                                        uint32_t currentTime) const {
        auto rules = getActiveRuleSet(currentHeight);

        // Check basic structure
        if (tx.getInputs().empty() || tx.getOutputs().empty()) {
            return false;
        }

        // Check lock time
        if (rules.enforceTimeLock) {
            if (!validateLockTime(tx.getLockTime(), currentHeight, currentTime)) {
                return false;
            }
        }

        // Check outputs
        uint64_t totalOutput = 0;
        for (const auto& output : tx.getOutputs()) {
            if (output.amount < MIN_DUST_AMOUNT) {
                return false;
            }
            totalOutput += output.amount;
        }

        if (totalOutput > getMaxMoney()) {
            return false;
        }

        // Check fee
        uint64_t totalInput = 0;
        for (const auto& utxo : utxos) {
            totalInput += utxo.amount;
        }

        uint64_t fee = totalInput - totalOutput;
        if (fee < rules.minTxFee) {
            return false;
        }

        return true;
    }

    uint32_t Consensus::getNextDifficulty(const std::vector<Block>& lastBlocks) const {
        auto rules = getActiveRuleSet(lastBlocks.back().getHeight() + 1);
        
        switch (rules.type) {
            case ConsensusType::PROOF_OF_WORK:
                return getNextProofOfWorkDifficulty(lastBlocks);
            case ConsensusType::PROOF_OF_STAKE:
                return getNextProofOfStakeDifficulty(lastBlocks);
            default:
                return getNextProofOfWorkDifficulty(lastBlocks);
        }
    }

    uint32_t Consensus::getNextProofOfWorkDifficulty(const std::vector<Block>& lastBlocks) const {
        if (lastBlocks.size() < 2) {
            return lastBlocks.empty() ? 1 : lastBlocks.back().getBits();
        }

        std::vector<uint32_t> timestamps;
        std::vector<uint32_t> difficulties;

        for (const auto& block : lastBlocks) {
            timestamps.push_back(block.getTimestamp());
            difficulties.push_back(block.getBits());
        }

        return calculateNextPoWDifficulty(timestamps, difficulties);
    }

    uint32_t Consensus::getNextProofOfStakeDifficulty(const std::vector<Block>& lastBlocks) const {
        // TODO: Implement PoS difficulty calculation
        return 1;
    }

    uint32_t Consensus::calculateNextPoWDifficulty(const std::vector<uint32_t>& timestamps,
                                                   const std::vector<uint32_t>& difficulties) const {
        if (timestamps.size() < 2) {
            return difficulties.empty() ? 1 : difficulties.back();
        }

        auto rules = getActiveRuleSet(0); // TODO: Use actual height

        uint32_t timeSpan = timestamps.back() - timestamps.front();
        uint32_t targetTimeSpan = rules.powTargetSpacing * 
                                  (timestamps.size() - 1);

        // Limit adjustment factor
        if (timeSpan < targetTimeSpan / 4) {
            timeSpan = targetTimeSpan / 4;
        }
        if (timeSpan > targetTimeSpan * 4) {
            timeSpan = targetTimeSpan * 4;
        }

        // Calculate new difficulty
        uint64_t newDifficulty = static_cast<uint64_t>(difficulties.back()) * 
                                 targetTimeSpan / timeSpan;

        // Ensure difficulty doesn't go below minimum
        if (newDifficulty < 1) {
            newDifficulty = 1;
        }

        return static_cast<uint32_t>(newDifficulty);
    }

    uint32_t Consensus::calculateNextPoSDifficulty(const std::vector<uint64_t>& stakes,
                                                   const std::vector<uint32_t>& ages) const {
        // TODO: Implement PoS difficulty calculation
        return 1;
    }

    uint64_t Consensus::getBlockReward(uint32_t height) const {
        auto rules = getActiveRuleSet(height);
        return calculateBlockReward(height, 0, 0);
    }

    uint64_t Consensus::getStakeReward(uint64_t amount, uint32_t age) const {
        return calculateStakeReward(amount, age);
    }

    uint64_t Consensus::getMinerReward(uint32_t height, uint64_t fees) const {
        return calculateBlockReward(height, fees, 0);
    }

    uint64_t Consensus::calculateBlockReward(uint32_t height, uint64_t fees, uint64_t stakes) const {
        uint32_t halvings = height / 210000;
        if (halvings >= 64) {
            return fees; // No block reward after 64 halvings
        }

        uint64_t baseReward = 50 * 100000000ULL;
        baseReward >>= halvings;

        return baseReward + fees + stakes;
    }

    uint64_t Consensus::calculateStakeReward(uint64_t amount, uint32_t age) const {
        // Simple PoS reward: amount * age / (365 days)
        double years = static_cast<double>(age) / (365 * 24 * 60 * 60);
        double rate = 0.05; // 5% annual interest
        return static_cast<uint64_t>(amount * rate * years);
    }

    ChainWork Consensus::calculateChainWork(const std::vector<Block>& chain) const {
        ChainWork work;
        work.bestHeight = chain.size() - 1;
        work.bestBlockHash = chain.back().getHash();
        
        work.totalWork = 0;
        work.totalTransactions = 0;
        work.totalOutput = 0;

        for (const auto& block : chain) {
            work.totalWork += block.getWork();
            work.totalTransactions += block.getTransactions().size();
            
            for (const auto& tx : block.getTransactions()) {
                work.totalOutput += tx.getTotalOutput();
            }
        }

        // Calculate network hashrate (simplified)
        if (chain.size() > 1) {
            uint32_t timeDiff = chain.back().getTimestamp() - chain.front().getTimestamp();
            if (timeDiff > 0) {
                work.networkHashrate = static_cast<double>(work.totalWork) / timeDiff;
            }
        }

        return work;
    }

    bool Consensus::isChainBetter(const ChainWork& current, const ChainWork& candidate) const {
        return candidate > current;
    }

    bool Consensus::isForkActivated(uint32_t height, ForkType type) const {
        for (const auto& fork : forks) {
            if (fork.type == type && fork.isActivated(height)) {
                return true;
            }
        }
        return false;
    }

    std::vector<ForkDescription> Consensus::getActiveForks(uint32_t height) const {
        std::vector<ForkDescription> active;
        for (const auto& fork : forks) {
            if (fork.isActivated(height)) {
                active.push_back(fork);
            }
        }
        return active;
    }

    bool Consensus::handleFork(const Block& block, std::vector<Block>& orphanedBlocks) const {
        // TODO: Implement fork handling logic
        return true;
    }

    ConsensusVersion Consensus::getVersion(uint32_t height) const {
        return getActiveRuleSet(height).version;
    }

    bool Consensus::isVersionActive(ConsensusVersion version, uint32_t height) const {
        return getVersion(height) >= version;
    }

    uint32_t Consensus::getTargetBlockTime() const {
        return getActiveRuleSet(currentParams.height).powTargetSpacing;
    }

    uint32_t Consensus::getDifficultyAdjustmentInterval() const {
        return getActiveRuleSet(currentParams.height).powDifficultyAdjustmentInterval;
    }

    uint32_t Consensus::getHalvingInterval() const {
        return 210000; // Bitcoin-style halving interval
    }

    uint64_t Consensus::getMaxMoney() const {
        return 21000000 * 100000000ULL; // 21 million PWR
    }

    bool Consensus::isStandardTransaction(const Transaction& tx) const {
        if (!tx.validate()) {
            return false;
        }

        // Check output scripts
        for (const auto& output : tx.getOutputs()) {
            if (!isAllowedScript(std::vector<uint8_t>(output.scriptPubKey.begin(),
                                                       output.scriptPubKey.end()))) {
                return false;
            }
        }

        return true;
    }

    bool Consensus::isAllowedScript(const std::vector<uint8_t>& script) const {
        // Check for non-standard opcodes
        for (auto byte : script) {
            OpCode op = static_cast<OpCode>(byte);
            if (op == OpCode::OP_CAT || op == OpCode::OP_SUBSTR ||
                op == OpCode::OP_LEFT || op == OpCode::OP_RIGHT ||
                op == OpCode::OP_INVERT || op == OpCode::OP_AND ||
                op == OpCode::OP_OR || op == OpCode::OP_XOR ||
                op == OpCode::OP_2MUL || op == OpCode::OP_2DIV) {
                return false;
            }
        }
        return true;
    }

    bool Consensus::isAllowedOpcode(OpCode op, uint32_t height) const {
        // Disabled opcodes
        if (op == OpCode::OP_CAT || op == OpCode::OP_SUBSTR ||
            op == OpCode::OP_LEFT || op == OpCode::OP_RIGHT ||
            op == OpCode::OP_INVERT || op == OpCode::OP_AND ||
            op == OpCode::OP_OR || op == OpCode::OP_XOR ||
            op == OpCode::OP_2MUL || op == OpCode::OP_2DIV) {
            return false;
        }

        // Check fork activation for new opcodes
        if (op == OpCode::OP_SMARTCONTRACT && !isForkActivated(height, ForkType::SOFT_FORK)) {
            return false;
        }

        return true;
    }

    ConsensusRuleSet Consensus::getActiveRuleSet(uint32_t height) const {
        for (const auto& rules : ruleSets) {
            if (rules.isEnabled(height)) {
                return rules;
            }
        }
        return ruleSets.empty() ? ConsensusRuleSet() : ruleSets.back();
    }

    bool Consensus::isForkActive(uint32_t height, const std::string& forkName) const {
        for (const auto& fork : forks) {
            if (fork.name == forkName && fork.isActivated(height)) {
                return true;
            }
        }
        return false;
    }

    std::string Consensus::getConsensusName() const {
        switch (activeType) {
            case ConsensusType::PROOF_OF_WORK:
                return "Proof of Work (SHA-256)";
            case ConsensusType::PROOF_OF_STAKE:
                return "Proof of Stake";
            case ConsensusType::PROOF_OF_AUTHORITY:
                return "Proof of Authority";
            case ConsensusType::HYBRID_POW_POS:
                return "Hybrid PoW/PoS";
            case ConsensusType::DELEGATED_POS:
                return "Delegated Proof of Stake";
            case ConsensusType::PRACTICAL_BFT:
                return "Practical Byzantine Fault Tolerance";
            default:
                return "Unknown";
        }
    }

    std::string Consensus::getVersionName(ConsensusVersion version) const {
        switch (version) {
            case ConsensusVersion::V0_GENESIS:
                return "Genesis";
            case ConsensusVersion::V1_BASIC:
                return "Basic";
            case ConsensusVersion::V2_POW:
                return "Proof of Work";
            case ConsensusVersion::V3_POS:
                return "Proof of Stake";
            case ConsensusVersion::V4_HYBRID:
                return "Hybrid";
            case ConsensusVersion::V5_SMART_CONTRACTS:
                return "Smart Contracts";
            case ConsensusVersion::V6_PRIVACY:
                return "Privacy";
            case ConsensusVersion::V7_GOVERNANCE:
                return "Governance";
            case ConsensusVersion::V8_CROSS_CHAIN:
                return "Cross Chain";
            default:
                return "Unknown";
        }
    }

    void Consensus::printConsensusInfo() const {
        std::cout << "\n=== Consensus Information ===\n";
        std::cout << "Type: " << getConsensusName() << "\n";
        std::cout << "Version: " << getVersionName(activeVersion) << "\n";
        std::cout << "Block Time: " << getTargetBlockTime() << " seconds\n";
        std::cout << "Difficulty Adjustment: " << getDifficultyAdjustmentInterval() << " blocks\n";
        std::cout << "Halving Interval: " << getHalvingInterval() << " blocks\n";
        std::cout << "Max Money: " << getMaxMoney() / 100000000.0 << " PWR\n";
        std::cout << "Rule Sets: " << ruleSets.size() << "\n";
        std::cout << "Forks: " << forks.size() << "\n";
    }

    void Consensus::setOnForkActivated(std::function<void(uint32_t, const ForkDescription&)> callback) {
        onForkActivated = callback;
    }

    void Consensus::setOnDifficultyChanged(std::function<void(uint32_t, uint32_t)> callback) {
        onDifficultyChanged = callback;
    }

    void Consensus::setOnRewardChanged(std::function<void(uint64_t, uint64_t)> callback) {
        onRewardChanged = callback;
    }

    // ============== ConsensusFactory Implementation ==============

    ConsensusRuleSet ConsensusFactory::createBitcoinLikeRules() {
        ConsensusRuleSet rules;
        rules.startHeight = 0;
        rules.endHeight = UINT32_MAX;
        rules.version = ConsensusVersion::V2_POW;
        rules.type = ConsensusType::PROOF_OF_WORK;
        rules.powAlgorithm = "sha256";
        rules.powTargetSpacing = 600;
        rules.powDifficultyAdjustmentInterval = 2016;
        rules.maxBlockWeight = 1000000;
        rules.maxBlockSigops = 20000;
        rules.minRelayFee = 1000;
        rules.minTxFee = 1000;
        rules.requireStandardTransactions = true;
        return rules;
    }

    ConsensusRuleSet ConsensusFactory::createEthereumLikeRules() {
        ConsensusRuleSet rules;
        rules.startHeight = 0;
        rules.endHeight = UINT32_MAX;
        rules.version = ConsensusVersion::V3_POS;
        rules.type = ConsensusType::PROOF_OF_STAKE;
        rules.powAlgorithm = "ethash";
        rules.posTargetSpacing = 12;
        rules.posMinimumStake = 32;
        rules.maxBlockWeight = 30000000;
        rules.maxBlockGas = 30000000;
        rules.minRelayFee = 0;
        rules.minTxFee = 0;
        rules.requireStandardTransactions = false;
        return rules;
    }

    ConsensusRuleSet ConsensusFactory::createPowerCoinMainNet() {
        ConsensusRuleSet rules;
        rules.startHeight = 0;
        rules.endHeight = UINT32_MAX;
        rules.version = ConsensusVersion::CURRENT;
        rules.type = ConsensusType::HYBRID_POW_POS;
        rules.powAlgorithm = "sha256";
        rules.powTargetSpacing = 600;
        rules.powDifficultyAdjustmentInterval = 2016;
        rules.posTargetSpacing = 600;
        rules.posMinimumStake = 1000;
        rules.posMaximumStake = 1000000;
        rules.posMinimumAge = 8 * 60 * 60;
        rules.posMaximumAge = 90 * 24 * 60 * 60;
        rules.maxBlockWeight = 4 * 1024 * 1024;
        rules.maxBlockSigops = 20000;
        rules.maxBlockGas = 10000000;
        rules.minRelayFee = 1000;
        rules.minTxFee = 1000;
        rules.requireStandardTransactions = true;
        rules.allowAnyoneCanSpend = false;
        rules.enforceBlockHeight = true;
        rules.enforceTimeLock = true;
        return rules;
    }

    ConsensusRuleSet ConsensusFactory::createPowerCoinTestNet() {
        auto rules = createPowerCoinMainNet();
        rules.startHeight = 0;
        rules.endHeight = UINT32_MAX;
        rules.powTargetSpacing = 60; // Faster blocks for testing
        rules.powDifficultyAdjustmentInterval = 100;
        rules.posMinimumStake = 100; // Lower stake for testing
        rules.minRelayFee = 100;
        rules.minTxFee = 100;
        return rules;
    }

    ConsensusRuleSet ConsensusFactory::createPowerCoinRegTest() {
        auto rules = createPowerCoinTestNet();
        rules.powTargetSpacing = 10; // Very fast blocks
        rules.posMinimumStake = 10;
        rules.minRelayFee = 0;
        rules.minTxFee = 0;
        rules.requireStandardTransactions = false;
        return rules;
    }

    ForkDescription ConsensusFactory::createSegWitFork() {
        ForkDescription fork;
        fork.type = ForkType::SOFT_FORK;
        fork.activationHeight = 481824; // Bitcoin SegWit activation
        fork.name = "SegWit";
        fork.description = "Segregated Witness";
        fork.newRules = {"Witness commitment", "New signature hash"};
        return fork;
    }

    ForkDescription ConsensusFactory::createTaprootFork() {
        ForkDescription fork;
        fork.type = ForkType::SOFT_FORK;
        fork.activationHeight = 709632; // Bitcoin Taproot activation
        fork.name = "Taproot";
        fork.description = "Schnorr signatures and Tapscript";
        fork.newRules = {"Schnorr signatures", "Taproot outputs", "Tapscript"};
        return fork;
    }

    ForkDescription ConsensusFactory::createSmartContractFork() {
        ForkDescription fork;
        fork.type = ForkType::HARD_FORK;
        fork.activationHeight = 1000000;
        fork.name = "Smart Contracts";
        fork.description = "EVM-compatible smart contracts";
        fork.newRules = {"Smart contract deployment", "Contract execution", "Gas accounting"};
        return fork;
    }

    ForkDescription ConsensusFactory::createPrivacyFork() {
        ForkDescription fork;
        fork.type = ForkType::HARD_FORK;
        fork.activationHeight = 2000000;
        fork.name = "Privacy";
        fork.description = "Stealth addresses and RingCT";
        fork.newRules = {"Stealth addresses", "Ring signatures", "Confidential transactions"};
        return fork;
    }

    ForkDescription ConsensusFactory::createGovernanceFork() {
        ForkDescription fork;
        fork.type = ForkType::HARD_FORK;
        fork.activationHeight = 3000000;
        fork.name = "Governance";
        fork.description = "On-chain governance";
        fork.newRules = {"Proposals", "Voting", "Treasury"};
        return fork;
    }

} // namespace powercoin