#include "difficulty.h"
#include "../crypto/sha256.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <numeric>

namespace powercoin {

    // ============== DifficultyParams Implementation ==============

    DifficultyParams::DifficultyParams()
        : targetBlockTime(600),
          adjustmentInterval(2016),
          minDifficulty(1),
          maxDifficulty(UINT32_MAX),
          maxAdjustmentUp(4.0),
          maxAdjustmentDown(4.0),
          averagingWindow(24),
          useTimeOffset(true),
          allowRetargeting(true),
          genesisDifficulty(1) {}

    // ============== DifficultyResult Implementation ==============

    DifficultyResult::DifficultyResult()
        : newDifficulty(0), previousDifficulty(0), change(0.0),
          actualTime(0), expectedTime(0), adjustmentFactor(1.0), valid(false) {}

    std::string DifficultyResult::toString() const {
        std::stringstream ss;
        ss << "Difficulty Adjustment Result:\n";
        ss << "  Previous Difficulty: " << previousDifficulty << "\n";
        ss << "  New Difficulty: " << newDifficulty << "\n";
        ss << "  Change: " << (change * 100) << "%\n";
        ss << "  Actual Time: " << actualTime << " seconds\n";
        ss << "  Expected Time: " << expectedTime << " seconds\n";
        ss << "  Adjustment Factor: " << adjustmentFactor << "\n";
        ss << "  Valid: " << (valid ? "yes" : "no") << "\n";
        return ss.str();
    }

    // ============== BlockTimeInfo Implementation ==============

    BlockTimeInfo::BlockTimeInfo() : height(0), timestamp(0), difficulty(0), nonce(0) {}

    // ============== BitcoinDifficultyAdjuster Implementation ==============

    BitcoinDifficultyAdjuster::BitcoinDifficultyAdjuster(const DifficultyParams& p) : params(p) {}

    uint32_t BitcoinDifficultyAdjuster::calculateNextDifficulty(
        const std::vector<uint32_t>& timestamps,
        const std::vector<uint32_t>& difficulties,
        uint32_t currentHeight) const {

        if (timestamps.size() < params.adjustmentInterval || 
            difficulties.size() < params.adjustmentInterval) {
            return difficulties.empty() ? params.genesisDifficulty : difficulties.back();
        }

        // Get timestamps for the adjustment window
        uint32_t firstTimestamp = timestamps[timestamps.size() - params.adjustmentInterval];
        uint32_t lastTimestamp = timestamps.back();
        uint32_t actualTimeSpan = lastTimestamp - firstTimestamp;

        // Ensure time span is within bounds
        uint32_t targetTimeSpan = params.targetBlockTime * params.adjustmentInterval;
        
        if (actualTimeSpan < targetTimeSpan / params.maxAdjustmentDown) {
            actualTimeSpan = targetTimeSpan / params.maxAdjustmentDown;
        }
        if (actualTimeSpan > targetTimeSpan * params.maxAdjustmentUp) {
            actualTimeSpan = targetTimeSpan * params.maxAdjustmentUp;
        }

        // Calculate new difficulty
        uint64_t newDifficulty = static_cast<uint64_t>(difficulties.back()) * 
                                 targetTimeSpan / actualTimeSpan;

        // Apply limits
        if (newDifficulty < params.minDifficulty) {
            newDifficulty = params.minDifficulty;
        }
        if (newDifficulty > params.maxDifficulty) {
            newDifficulty = params.maxDifficulty;
        }

        return static_cast<uint32_t>(newDifficulty);
    }

    bool BitcoinDifficultyAdjuster::validateDifficulty(uint32_t difficulty) const {
        return difficulty >= params.minDifficulty && difficulty <= params.maxDifficulty;
    }

    // ============== DarkGravityWaveAdjuster Implementation ==============

    DarkGravityWaveAdjuster::DarkGravityWaveAdjuster(const DifficultyParams& p) : params(p) {}

    uint32_t DarkGravityWaveAdjuster::calculateNextDifficulty(
        const std::vector<uint32_t>& timestamps,
        const std::vector<uint32_t>& difficulties,
        uint32_t currentHeight) const {

        if (timestamps.size() < 3) {
            return difficulties.empty() ? params.genesisDifficulty : difficulties.back();
        }

        const size_t n = 24; // Dark Gravity Wave uses 24 blocks
        size_t start = (timestamps.size() > n) ? timestamps.size() - n : 0;
        size_t count = timestamps.size() - start;

        if (count < 3) {
            return difficulties.back();
        }

        std::vector<double> timeDeltas;
        std::vector<double> difficulties_d;

        for (size_t i = start + 1; i < timestamps.size(); i++) {
            timeDeltas.push_back(static_cast<double>(timestamps[i] - timestamps[i-1]));
            difficulties_d.push_back(static_cast<double>(difficulties[i-1]));
        }

        // Calculate weighted average
        double totalWeight = 0;
        double weightedSum = 0;

        for (size_t i = 0; i < timeDeltas.size(); i++) {
            double weight = static_cast<double>(i + 1) / timeDeltas.size();
            double expectedTime = static_cast<double>(params.targetBlockTime);
            double ratio = expectedTime / timeDeltas[i];
            
            weightedSum += difficulties_d[i] * ratio * weight;
            totalWeight += weight;
        }

        double newDifficulty = weightedSum / totalWeight;

        // Apply limits
        if (newDifficulty < params.minDifficulty) {
            newDifficulty = params.minDifficulty;
        }
        if (newDifficulty > params.maxDifficulty) {
            newDifficulty = params.maxDifficulty;
        }

        return static_cast<uint32_t>(std::round(newDifficulty));
    }

    double DarkGravityWaveAdjuster::calculateAverage(
        const std::vector<double>& values, size_t start, size_t count) const {

        if (values.empty() || count == 0) return 0.0;

        double sum = 0;
        size_t end = std::min(start + count, values.size());
        
        for (size_t i = start; i < end; i++) {
            sum += values[i];
        }
        
        return sum / (end - start);
    }

    bool DarkGravityWaveAdjuster::validateDifficulty(uint32_t difficulty) const {
        return difficulty >= params.minDifficulty && difficulty <= params.maxDifficulty;
    }

    // ============== DigiShieldAdjuster Implementation ==============

    DigiShieldAdjuster::DigiShieldAdjuster(const DifficultyParams& p) : params(p) {}

    uint32_t DigiShieldAdjuster::calculateNextDifficulty(
        const std::vector<uint32_t>& timestamps,
        const std::vector<uint32_t>& difficulties,
        uint32_t currentHeight) const {

        if (timestamps.size() < 3) {
            return difficulties.empty() ? params.genesisDifficulty : difficulties.back();
        }

        // DigiShield uses the last 3 blocks for rapid adjustment
        uint32_t timeSpan = timestamps.back() - timestamps[timestamps.size() - 3];
        uint32_t targetSpan = params.targetBlockTime * 3;

        double adjustmentFactor = static_cast<double>(targetSpan) / timeSpan;

        // Limit adjustment factor
        if (adjustmentFactor > params.maxAdjustmentUp) {
            adjustmentFactor = params.maxAdjustmentUp;
        }
        if (adjustmentFactor < 1.0 / params.maxAdjustmentDown) {
            adjustmentFactor = 1.0 / params.maxAdjustmentDown;
        }

        double newDifficulty = difficulties.back() * adjustmentFactor;

        // Apply limits
        if (newDifficulty < params.minDifficulty) {
            newDifficulty = params.minDifficulty;
        }
        if (newDifficulty > params.maxDifficulty) {
            newDifficulty = params.maxDifficulty;
        }

        return static_cast<uint32_t>(std::round(newDifficulty));
    }

    bool DigiShieldAdjuster::validateDifficulty(uint32_t difficulty) const {
        return difficulty >= params.minDifficulty && difficulty <= params.maxDifficulty;
    }

    // ============== LWMADifficultyAdjuster Implementation ==============

    LWMADifficultyAdjuster::LWMADifficultyAdjuster(const DifficultyParams& p) : params(p) {}

    uint32_t LWMADifficultyAdjuster::calculateNextDifficulty(
        const std::vector<uint32_t>& timestamps,
        const std::vector<uint32_t>& difficulties,
        uint32_t currentHeight) const {

        const size_t N = 60; // LWMA typically uses 60 blocks
        if (timestamps.size() < N) {
            return difficulties.empty() ? params.genesisDifficulty : difficulties.back();
        }

        size_t start = timestamps.size() - N;
        double totalWeight = 0;
        double weightedSum = 0;

        for (size_t i = start + 1; i < timestamps.size(); i++) {
            size_t idx = i - start;
            double weight = static_cast<double>(idx);
            double timeDelta = static_cast<double>(timestamps[i] - timestamps[i-1]);
            double targetDelta = static_cast<double>(params.targetBlockTime);
            
            weightedSum += weight * difficulties[i-1] * targetDelta / timeDelta;
            totalWeight += weight;
        }

        double newDifficulty = weightedSum * (N + 1) / (2 * totalWeight);

        // Apply limits
        if (newDifficulty < params.minDifficulty) {
            newDifficulty = params.minDifficulty;
        }
        if (newDifficulty > params.maxDifficulty) {
            newDifficulty = params.maxDifficulty;
        }

        return static_cast<uint32_t>(std::round(newDifficulty));
    }

    bool LWMADifficultyAdjuster::validateDifficulty(uint32_t difficulty) const {
        return difficulty >= params.minDifficulty && difficulty <= params.maxDifficulty;
    }

    // ============== DifficultyManager Implementation ==============

    DifficultyManager::DifficultyManager(DifficultyAlgorithm algo, const DifficultyParams& p)
        : algorithm(algo), params(p), currentDifficulty(p.genesisDifficulty),
          nextDifficulty(p.genesisDifficulty), totalWork(0) {

        setAlgorithm(algo);
    }

    DifficultyManager::~DifficultyManager() = default;

    bool DifficultyManager::initialize(uint32_t genesisDifficulty) {
        std::lock_guard<std::mutex> lock(mutex);
        
        currentDifficulty = genesisDifficulty;
        nextDifficulty = genesisDifficulty;
        totalWork = calculateWork(genesisDifficulty);
        blockHistory.clear();
        
        return true;
    }

    void DifficultyManager::addBlock(uint32_t timestamp, uint32_t difficulty, uint32_t nonce) {
        std::lock_guard<std::mutex> lock(mutex);

        BlockTimeInfo info;
        info.height = blockHistory.size();
        info.timestamp = timestamp;
        info.difficulty = difficulty;
        info.nonce = nonce;
        
        blockHistory.push_back(info);
        totalWork += calculateWork(difficulty);
        currentDifficulty = difficulty;
    }

    uint32_t DifficultyManager::calculateNextDifficulty(uint32_t currentHeight) {
        std::lock_guard<std::mutex> lock(mutex);

        if (!shouldAdjust(currentHeight)) {
            return currentDifficulty;
        }

        if (blockHistory.size() < params.adjustmentInterval) {
            return currentDifficulty;
        }

        std::vector<uint32_t> timestamps;
        std::vector<uint32_t> difficulties;

        for (const auto& block : blockHistory) {
            timestamps.push_back(block.timestamp);
            difficulties.push_back(block.difficulty);
        }

        uint32_t oldDifficulty = currentDifficulty;
        uint32_t newDifficulty = adjuster->calculateNextDifficulty(timestamps, difficulties, currentHeight);

        // Calculate adjustment details
        DifficultyResult result;
        result.previousDifficulty = oldDifficulty;
        result.newDifficulty = newDifficulty;
        result.change = static_cast<double>(newDifficulty - oldDifficulty) / oldDifficulty;
        
        if (timestamps.size() >= params.adjustmentInterval) {
            size_t start = timestamps.size() - params.adjustmentInterval;
            result.actualTime = timestamps.back() - timestamps[start];
            result.expectedTime = params.targetBlockTime * params.adjustmentInterval;
            result.adjustmentFactor = static_cast<double>(result.actualTime) / result.expectedTime;
        }
        
        result.valid = true;

        nextDifficulty = newDifficulty;

        if (onDifficultyChanged) {
            onDifficultyChanged(oldDifficulty, newDifficulty, result.change);
        }

        if (onAdjustment) {
            onAdjustment(result);
        }

        return newDifficulty;
    }

    uint64_t DifficultyManager::getTotalWork() const {
        std::lock_guard<std::mutex> lock(mutex);
        return totalWork;
    }

    double DifficultyManager::estimateHashrate(uint32_t blocks) const {
        std::lock_guard<std::mutex> lock(mutex);

        if (blockHistory.size() < 2) {
            return 0.0;
        }

        blocks = std::min(blocks, static_cast<uint32_t>(blockHistory.size() - 1));
        size_t start = blockHistory.size() - blocks - 1;
        
        uint32_t timeSpan = blockHistory.back().timestamp - blockHistory[start].timestamp;
        if (timeSpan == 0) return 0.0;

        uint64_t work = 0;
        for (size_t i = start + 1; i < blockHistory.size(); i++) {
            work += calculateWork(blockHistory[i].difficulty);
        }

        return static_cast<double>(work) / timeSpan;
    }

    double DifficultyManager::getAverageBlockTime(uint32_t blocks) const {
        std::lock_guard<std::mutex> lock(mutex);

        if (blockHistory.size() < 2) {
            return 0.0;
        }

        blocks = std::min(blocks, static_cast<uint32_t>(blockHistory.size() - 1));
        size_t start = blockHistory.size() - blocks - 1;
        
        uint32_t timeSpan = blockHistory.back().timestamp - blockHistory[start].timestamp;
        return static_cast<double>(timeSpan) / blocks;
    }

    bool DifficultyManager::shouldAdjust(uint32_t currentHeight) const {
        if (!params.allowRetargeting) return false;
        if (currentHeight == 0) return false;
        return (currentHeight % params.adjustmentInterval) == 0;
    }

    bool DifficultyManager::validateBlockDifficulty(const std::string& blockHash, 
                                                    uint32_t difficulty) const {
        return DifficultyCalculator::meetsDifficulty(blockHash, difficulty);
    }

    void DifficultyManager::setAlgorithm(DifficultyAlgorithm algo) {
        std::lock_guard<std::mutex> lock(mutex);

        algorithm = algo;
        
        switch (algo) {
            case DifficultyAlgorithm::BITCOIN:
                adjuster = std::make_unique<BitcoinDifficultyAdjuster>(params);
                break;
            case DifficultyAlgorithm::DASH:
                adjuster = std::make_unique<DarkGravityWaveAdjuster>(params);
                break;
            case DifficultyAlgorithm::DIGISHIELD:
                adjuster = std::make_unique<DigiShieldAdjuster>(params);
                break;
            case DifficultyAlgorithm::LWMA:
                adjuster = std::make_unique<LWMADifficultyAdjuster>(params);
                break;
            default:
                adjuster = std::make_unique<BitcoinDifficultyAdjuster>(params);
                break;
        }
    }

    std::string DifficultyManager::getAlgorithmName() const {
        if (!adjuster) return "Unknown";
        return adjuster->getAlgorithmName();
    }

    void DifficultyManager::updateParams(const DifficultyParams& p) {
        std::lock_guard<std::mutex> lock(mutex);
        params = p;
        
        // Recreate adjuster with new params
        setAlgorithm(algorithm);
    }

    void DifficultyManager::reset() {
        std::lock_guard<std::mutex> lock(mutex);
        
        blockHistory.clear();
        currentDifficulty = params.genesisDifficulty;
        nextDifficulty = params.genesisDifficulty;
        totalWork = calculateWork(params.genesisDifficulty);
    }

    std::vector<BlockTimeInfo> DifficultyManager::getBlockHistory() const {
        std::lock_guard<std::mutex> lock(mutex);
        return blockHistory;
    }

    std::string DifficultyManager::difficultyToTarget(uint32_t difficulty) {
        uint32_t leadingZeros = difficulty >> 24;
        std::string target(leadingZeros, '0');
        target.resize(64, 'f');
        return target;
    }

    uint32_t DifficultyManager::targetToDifficulty(const std::string& target) {
        uint32_t leadingZeros = 0;
        for (char c : target) {
            if (c == '0') leadingZeros++;
            else break;
        }
        return leadingZeros << 24;
    }

    uint64_t DifficultyManager::calculateWork(uint32_t difficulty) {
        uint32_t leadingZeros = difficulty >> 24;
        return 1ULL << (leadingZeros * 8);
    }

    // ============== DifficultyCalculator Implementation ==============

    uint32_t DifficultyCalculator::fromHash(const std::string& hash) {
        uint32_t leadingZeros = 0;
        for (char c : hash) {
            if (c == '0') leadingZeros++;
            else break;
        }
        return leadingZeros << 24;
    }

    uint64_t DifficultyCalculator::targetFromDifficulty(uint32_t difficulty) {
        uint32_t leadingZeros = difficulty >> 24;
        return 1ULL << (256 - leadingZeros * 4);
    }

    bool DifficultyCalculator::meetsDifficulty(const std::string& hash, uint32_t difficulty) {
        uint32_t requiredZeros = difficulty >> 24;
        
        // Check if hash has enough leading zeros
        for (uint32_t i = 0; i < requiredZeros; i++) {
            if (i >= hash.length()) return false;
            if (hash[i] != '0') return false;
        }
        return true;
    }

    uint32_t DifficultyCalculator::getLeadingZeros(uint32_t difficulty) {
        return difficulty >> 24;
    }

    std::string DifficultyCalculator::formatTarget(uint32_t difficulty) {
        return DifficultyManager::difficultyToTarget(difficulty);
    }

} // namespace powercoin