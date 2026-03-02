#include "pow.h"
#include "../crypto/sha256.h"
#include "../crypto/random.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <thread>
#include <chrono>

namespace powercoin {

    // ============== PoWConfig Implementation ==============

    PoWConfig::PoWConfig()
        : algorithm(PoWAlgorithm::SHA256D),
          initialDifficulty(4),
          targetBlockTime(600),
          difficultyAdjustmentInterval(2016),
          maxNonce(UINT32_MAX),
          allowMining(true),
          preferredHardware(MiningHardware::CPU),
          numThreads(std::thread::hardware_concurrency()),
          useSSE(true),
          useAVX(false),
          useCUDA(false),
          useOpenCL(false),
          memoryLimit(1024 * 1024 * 1024) {} // 1GB

    // ============== PoWSolution Implementation ==============

    PoWSolution::PoWSolution()
        : nonce(0), time(0), hashes(0), hashrate(0), valid(false) {}

    std::string PoWSolution::toString() const {
        std::stringstream ss;
        ss << "PoW Solution:\n";
        ss << "  Nonce: " << nonce << "\n";
        ss << "  Hash: " << hash.substr(0, 32) << "...\n";
        if (!mixHash.empty()) {
            ss << "  Mix Hash: " << mixHash.substr(0, 32) << "...\n";
        }
        ss << "  Time: " << time << " ms\n";
        ss << "  Hashes: " << hashes << "\n";
        ss << "  Hashrate: " << hashrate << " H/s\n";
        ss << "  Valid: " << (valid ? "yes" : "no") << "\n";
        return ss.str();
    }

    // ============== MiningStats Implementation ==============

    MiningStats::MiningStats()
        : totalHashes(0), acceptedShares(0), rejectedShares(0), blocksFound(0),
          currentHashrate(0), averageHashrate(0), peakHashrate(0), uptime(0),
          difficulty(0), estimatedTime(0), sharesPerMinute(0) {}

    std::string MiningStats::toString() const {
        std::stringstream ss;
        ss << "Mining Statistics:\n";
        ss << "  Total Hashes: " << totalHashes << "\n";
        ss << "  Current Hashrate: " << (currentHashrate / 1000000) << " MH/s\n";
        ss << "  Average Hashrate: " << (averageHashrate / 1000000) << " MH/s\n";
        ss << "  Peak Hashrate: " << (peakHashrate / 1000000) << " MH/s\n";
        ss << "  Accepted Shares: " << acceptedShares << "\n";
        ss << "  Rejected Shares: " << rejectedShares << "\n";
        ss << "  Blocks Found: " << blocksFound << "\n";
        ss << "  Current Difficulty: " << difficulty << "\n";
        ss << "  Shares/Minute: " << sharesPerMinute << "\n";
        ss << "  Uptime: " << uptime << " seconds\n";
        return ss.str();
    }

    // ============== SHA256dValidator Implementation ==============

    bool SHA256dValidator::validate(const Block& block, uint32_t difficulty) const {
        auto hash = block.getHash();
        return validate(hash, difficulty);
    }

    bool SHA256dValidator::validate(const std::string& hash, uint32_t difficulty) const {
        // Convert difficulty bits to target
        std::string target(difficulty >> 24, '0');
        return hash.substr(0, difficulty >> 24) == target;
    }

    uint32_t SHA256dValidator::getDifficulty(const Block& block) const {
        return block.getBits();
    }

    std::string SHA256dValidator::hashWithNonce(const std::string& data, uint32_t nonce) {
        std::stringstream ss;
        ss << data << nonce;
        return SHA256::doubleHash(ss.str());
    }

    uint64_t SHA256dValidator::getWork(const std::string& hash) {
        // Work is 2^256 / (target + 1)
        // Simplified for demo
        uint64_t work = 0;
        for (char c : hash) {
            if (c != '0') break;
            work++;
        }
        return 1ULL << (work * 8);
    }

    // ============== ProofOfWork Implementation ==============

    ProofOfWork::ProofOfWork(const PoWConfig& cfg) 
        : config(cfg), isMining(false), totalHashes(0), sharesFound(0),
          currentDifficulty(cfg.initialDifficulty), shouldStop(false) {
        
        switch (config.algorithm) {
            case PoWAlgorithm::SHA256D:
                validator = std::make_unique<SHA256dValidator>();
                break;
            default:
                validator = std::make_unique<SHA256dValidator>();
                break;
        }
    }

    ProofOfWork::~ProofOfWork() {
        stopMining();
    }

    bool ProofOfWork::initialize() {
        resetStats();
        startTime = std::chrono::steady_clock::now();
        return true;
    }

    bool ProofOfWork::validateBlock(const Block& block) const {
        return validator->validate(block, currentDifficulty);
    }

    bool ProofOfWork::validateHash(const std::string& hash, uint32_t difficulty) const {
        return validator->validate(hash, difficulty);
    }

    uint32_t ProofOfWork::getDifficulty(const Block& block) const {
        return validator->getDifficulty(block);
    }

    uint32_t ProofOfWork::calculateNextDifficulty(const std::vector<uint32_t>& timestamps,
                                                   const std::vector<uint32_t>& difficulties) const {
        if (timestamps.size() < 2) {
            return currentDifficulty;
        }

        uint32_t timeSpan = timestamps.back() - timestamps.front();
        uint32_t targetTimeSpan = config.targetBlockTime * (timestamps.size() - 1);

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

    PoWSolution ProofOfWork::mineBlock(const Block& block, uint32_t startNonce) {
        PoWSolution solution;
        solution.valid = false;

        auto header = block.serialize(); // Simplified - would use block header
        uint32_t nonce = startNonce;
        uint64_t hashes = 0;
        
        auto startTime = std::chrono::high_resolution_clock::now();

        while (nonce < config.maxNonce && !shouldStop) {
            std::string data = header + std::to_string(nonce);
            std::string hash = SHA256::doubleHash(data);

            hashes++;
            totalHashes++;

            if (validator->validate(hash, currentDifficulty)) {
                auto endTime = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    endTime - startTime);

                solution.nonce = nonce;
                solution.hash = hash;
                solution.time = duration.count();
                solution.hashes = hashes;
                solution.hashrate = static_cast<double>(hashes) * 1000 / duration.count();
                solution.valid = true;

                if (onSolutionFound) {
                    onSolutionFound(solution);
                }

                break;
            }

            nonce++;
        }

        return solution;
    }

    PoWSolution ProofOfWork::mineBlock(const Block& block,
                                       std::function<void(uint64_t, double)> progressCallback) {
        PoWSolution solution;
        solution.valid = false;

        auto header = block.serialize();
        uint32_t nonce = 0;
        uint64_t hashes = 0;
        const uint64_t progressInterval = 100000;

        auto startTime = std::chrono::high_resolution_clock::now();

        while (nonce < config.maxNonce && !shouldStop) {
            std::string data = header + std::to_string(nonce);
            std::string hash = SHA256::doubleHash(data);

            hashes++;
            totalHashes++;

            if (hashes % progressInterval == 0 && progressCallback) {
                auto now = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - startTime);
                double hashrate = static_cast<double>(hashes) * 1000 / duration.count();
                progressCallback(hashes, hashrate);
            }

            if (validator->validate(hash, currentDifficulty)) {
                auto endTime = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    endTime - startTime);

                solution.nonce = nonce;
                solution.hash = hash;
                solution.time = duration.count();
                solution.hashes = hashes;
                solution.hashrate = static_cast<double>(hashes) * 1000 / duration.count();
                solution.valid = true;

                if (onSolutionFound) {
                    onSolutionFound(solution);
                }

                break;
            }

            nonce++;
        }

        return solution;
    }

    void ProofOfWork::startMining(std::function<Block()> blockTemplate) {
        if (isMining || !config.allowMining) return;

        isMining = true;
        shouldStop = false;

        miningThread = std::make_unique<std::thread>([this, blockTemplate]() {
            MiningStats stats;
            auto lastUpdate = std::chrono::steady_clock::now();
            uint64_t lastHashes = 0;

            while (!shouldStop) {
                auto block = blockTemplate();
                
                auto solution = mineBlock(block, 0);
                
                if (solution.valid) {
                    sharesFound++;
                    
                    // Check if it's a full block (not just a share)
                    if (solution.hash.substr(0, currentDifficulty >> 24) == 
                        std::string(currentDifficulty >> 24, '0')) {
                        // Found a block
                        if (onSolutionFound) {
                            onSolutionFound(solution);
                        }
                    }
                }

                // Update statistics
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - lastUpdate).count();

                if (elapsed >= 1000) { // Update every second
                    uint64_t hashesSinceLast = totalHashes - lastHashes;
                    stats.currentHashrate = hashesSinceLast * 1000.0 / elapsed;
                    
                    if (stats.currentHashrate > stats.peakHashrate) {
                        stats.peakHashrate = stats.currentHashrate;
                    }

                    lastHashes = totalHashes;
                    lastUpdate = now;

                    if (onStatsUpdate) {
                        onStatsUpdate(stats);
                    }
                }
            }

            isMining = false;
        });
    }

    void ProofOfWork::stopMining() {
        shouldStop = true;
        if (miningThread && miningThread->joinable()) {
            miningThread->join();
        }
        miningThread.reset();
        isMining = false;
    }

    MiningStats ProofOfWork::getStats() const {
        MiningStats stats;
        stats.totalHashes = totalHashes;
        stats.acceptedShares = sharesFound;
        stats.blocksFound = 0; // Would need to track
        stats.currentDifficulty = currentDifficulty;

        auto now = std::chrono::steady_clock::now();
        stats.uptime = std::chrono::duration_cast<std::chrono::seconds>(
            now - startTime).count();

        if (stats.uptime > 0) {
            stats.averageHashrate = static_cast<double>(totalHashes) / stats.uptime;
        }

        if (stats.uptime > 60) {
            stats.sharesPerMinute = sharesFound * 60 / stats.uptime;
        }

        return stats;
    }

    void ProofOfWork::resetStats() {
        totalHashes = 0;
        sharesFound = 0;
        startTime = std::chrono::steady_clock::now();
    }

    std::string ProofOfWork::getAlgorithmName() const {
        switch (config.algorithm) {
            case PoWAlgorithm::SHA256D: return "SHA-256d";
            case PoWAlgorithm::SCRYPT: return "Scrypt";
            case PoWAlgorithm::X11: return "X11";
            case PoWAlgorithm::ETHASH: return "Ethash";
            case PoWAlgorithm::RANDOMX: return "RandomX";
            case PoWAlgorithm::CUCKOO_CYCLE: return "Cuckoo Cycle";
            case PoWAlgorithm::EQUIHASH: return "Equihash";
            default: return "Custom";
        }
    }

    double ProofOfWork::estimateTime(uint32_t difficulty, double hashrate) {
        if (hashrate == 0) return 0;
        uint64_t target = 1ULL << difficulty;
        return static_cast<double>(target) / hashrate;
    }

    std::string ProofOfWork::difficultyToTarget(uint32_t difficulty) {
        std::string target(difficulty >> 24, '0');
        target.resize(64, 'f');
        return target;
    }

    uint32_t ProofOfWork::targetToDifficulty(const std::string& target) {
        uint32_t leadingZeros = 0;
        for (char c : target) {
            if (c == '0') leadingZeros++;
            else break;
        }
        return leadingZeros << 24;
    }

    uint64_t ProofOfWork::calculateWork(const std::string& hash) {
        return SHA256dValidator::getWork(hash);
    }

    void ProofOfWork::setOnSolutionFound(std::function<void(const PoWSolution&)> callback) {
        onSolutionFound = callback;
    }

    void ProofOfWork::setOnStatsUpdate(std::function<void(const MiningStats&)> callback) {
        onStatsUpdate = callback;
    }

    void ProofOfWork::setOnError(std::function<void(const std::string&)> callback) {
        onError = callback;
    }

    // ============== DifficultyAdjuster Implementation ==============

    DifficultyAdjuster::DifficultyAdjuster(uint32_t targetTime, uint32_t interval,
                                           uint32_t minDiff, uint32_t maxDiff, double factor)
        : targetBlockTime(targetTime), adjustmentInterval(interval),
          minDifficulty(minDiff), maxDifficulty(maxDiff), adjustmentFactor(factor) {}

    uint32_t DifficultyAdjuster::calculateNextDifficulty(const std::vector<uint32_t>& timestamps,
                                                          uint32_t currentDifficulty) const {
        if (timestamps.size() < adjustmentInterval) {
            return currentDifficulty;
        }

        uint32_t timeSpan = timestamps.back() - timestamps[timestamps.size() - adjustmentInterval];
        uint32_t targetTimeSpan = targetBlockTime * adjustmentInterval;

        // Limit adjustment factor
        if (timeSpan < targetTimeSpan / adjustmentFactor) {
            timeSpan = targetTimeSpan / adjustmentFactor;
        }
        if (timeSpan > targetTimeSpan * adjustmentFactor) {
            timeSpan = targetTimeSpan * adjustmentFactor;
        }

        uint64_t newDifficulty = static_cast<uint64_t>(currentDifficulty) * 
                                 targetTimeSpan / timeSpan;

        return clampDifficulty(static_cast<uint32_t>(newDifficulty));
    }

    uint32_t DifficultyAdjuster::calculateNextDifficulty(const std::vector<Block>& blocks) const {
        if (blocks.size() < adjustmentInterval) {
            return blocks.empty() ? 1 : blocks.back().getBits();
        }

        std::vector<uint32_t> timestamps;
        for (size_t i = blocks.size() - adjustmentInterval; i < blocks.size(); i++) {
            timestamps.push_back(blocks[i].getTimestamp());
        }

        return calculateNextDifficulty(timestamps, blocks.back().getBits());
    }

    uint32_t DifficultyAdjuster::clampDifficulty(uint32_t difficulty) const {
        if (difficulty < minDifficulty) return minDifficulty;
        if (difficulty > maxDifficulty) return maxDifficulty;
        return difficulty;
    }

    // ============== PoWHash Implementation ==============

    std::string PoWHash::sha256d(const std::string& data) {
        return SHA256::doubleHash(data);
    }

    std::string PoWHash::sha256d(const uint8_t* data, size_t len) {
        auto hash = SHA256::doubleHash(data, len);
        return SHA256::bytesToHash(
            *reinterpret_cast<std::array<uint8_t, 32>*>(hash.data()));
    }

    std::string PoWHash::sha256dWithNonce(const std::string& data, uint32_t nonce) {
        std::stringstream ss;
        ss << data << nonce;
        return sha256d(ss.str());
    }

    bool PoWHash::checkTarget(const std::string& hash, uint32_t difficulty) {
        std::string target(difficulty >> 24, '0');
        return hash.substr(0, difficulty >> 24) == target;
    }

    bool PoWHash::checkTarget(const uint8_t* hash, uint32_t difficulty) {
        std::string hashStr = SHA256::bytesToHash(
            *reinterpret_cast<const std::array<uint8_t, 32>*>(hash));
        return checkTarget(hashStr, difficulty);
    }

    uint32_t PoWHash::getDifficultyFromTarget(const std::string& target) {
        uint32_t leadingZeros = 0;
        for (char c : target) {
            if (c == '0') leadingZeros++;
            else break;
        }
        return leadingZeros << 24;
    }

    std::string PoWHash::getTargetFromDifficulty(uint32_t difficulty) {
        return ProofOfWork::difficultyToTarget(difficulty);
    }

} // namespace powercoin