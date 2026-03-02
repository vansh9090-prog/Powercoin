#include "sync.h"
#include "../crypto/sha256.h"
#include "../blockchain/block.h"
#include "../blockchain/validation.h"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>

namespace powercoin {

    // ============== BlockLocator Implementation ==============

    BlockLocator::BlockLocator() : startHeight(0), stopHeight(0) {}

    BlockLocator::BlockLocator(const std::vector<std::string>& locator) 
        : hashes(locator), startHeight(0), stopHeight(0) {}

    bool BlockLocator::isValid() const {
        return !hashes.empty() && hashes.size() <= 32;
    }

    std::string BlockLocator::toString() const {
        std::stringstream ss;
        ss << "BlockLocator: " << hashes.size() << " hashes";
        if (!hashes.empty()) {
            ss << " (first: " << hashes[0].substr(0, 16) << "...)";
        }
        return ss.str();
    }

    std::vector<uint8_t> BlockLocator::serialize() const {
        std::vector<uint8_t> data;

        // Version (4 bytes)
        uint32_t version = 1;
        uint32_t version_le = htole32(version);
        data.insert(data.end(), (uint8_t*)&version_le, (uint8_t*)&version_le + 4);

        // Hash count (variable)
        if (hashes.size() < 0xFD) {
            data.push_back(hashes.size());
        } else if (hashes.size() <= 0xFFFF) {
            data.push_back(0xFD);
            uint16_t count_le = htole16(hashes.size());
            data.insert(data.end(), (uint8_t*)&count_le, (uint8_t*)&count_le + 2);
        } else {
            data.push_back(0xFE);
            uint32_t count_le = htole32(hashes.size());
            data.insert(data.end(), (uint8_t*)&count_le, (uint8_t*)&count_le + 4);
        }

        // Hashes (32 bytes each)
        for (const auto& hash : hashes) {
            auto hashBytes = SHA256::hashToBytes(hash);
            data.insert(data.end(), hashBytes.begin(), hashBytes.end());
        }

        // Stop hash (32 bytes)
        auto stopBytes = SHA256::hashToBytes(hashStop);
        data.insert(data.end(), stopBytes.begin(), stopBytes.end());

        return data;
    }

    bool BlockLocator::deserialize(const std::vector<uint8_t>& data) {
        size_t pos = 0;

        if (pos + 4 > data.size()) return false;
        uint32_t version;
        memcpy(&version, data.data() + pos, 4);
        version = le32toh(version);
        pos += 4;

        if (pos >= data.size()) return false;

        uint64_t count = 0;
        uint8_t first = data[pos++];

        if (first < 0xFD) {
            count = first;
        } else if (first == 0xFD) {
            if (pos + 2 > data.size()) return false;
            uint16_t count_le;
            memcpy(&count_le, data.data() + pos, 2);
            count = le16toh(count_le);
            pos += 2;
        } else if (first == 0xFE) {
            if (pos + 4 > data.size()) return false;
            uint32_t count_le;
            memcpy(&count_le, data.data() + pos, 4);
            count = le32toh(count_le);
            pos += 4;
        } else {
            return false;
        }

        hashes.clear();
        for (uint64_t i = 0; i < count; i++) {
            if (pos + 32 > data.size()) return false;
            std::array<uint8_t, 32> hashBytes;
            memcpy(hashBytes.data(), data.data() + pos, 32);
            hashes.push_back(SHA256::bytesToHash(hashBytes));
            pos += 32;
        }

        if (pos + 32 > data.size()) return false;
        std::array<uint8_t, 32> stopBytes;
        memcpy(stopBytes.data(), data.data() + pos, 32);
        hashStop = SHA256::bytesToHash(stopBytes);

        return true;
    }

    BlockLocator BlockLocator::createFromChain(const std::vector<Block>& chain) {
        BlockLocator locator;
        
        // Add recent blocks exponentially
        if (chain.empty()) {
            return locator;
        }

        uint32_t height = chain.size() - 1;
        uint32_t step = 1;
        
        while (height > 0 && locator.hashes.size() < 10) {
            locator.hashes.push_back(chain[height].getHash());
            
            if (locator.hashes.size() > 10) {
                break;
            }
            
            height = (height > step) ? height - step : 0;
            step *= 2;
        }

        // Always include genesis
        if (locator.hashes.empty() || locator.hashes.back() != chain[0].getHash()) {
            locator.hashes.push_back(chain[0].getHash());
        }

        locator.hashStop = "0";
        return locator;
    }

    BlockLocator BlockLocator::createFromHeight(uint32_t height, const std::string& genesisHash) {
        BlockLocator locator;
        locator.hashes.push_back(genesisHash);
        locator.hashStop = "0";
        return locator;
    }

    // ============== SyncProgress Implementation ==============

    SyncProgress::SyncProgress()
        : state(SyncState::IDLE),
          mode(SyncMode::HEADERS_FIRST),
          targetHeight(0),
          currentHeight(0),
          headersReceived(0),
          blocksReceived(0),
          blocksQueued(0),
          blocksFailed(0),
          progress(0.0),
          bytesDownloaded(0),
          bytesPerSecond(0),
          estimatedTimeRemaining(0),
          elapsedTime(0) {}

    std::string SyncProgress::toString() const {
        std::stringstream ss;
        ss << "Sync Progress:\n";
        ss << "  State: " << static_cast<int>(state) << "\n";
        ss << "  Progress: " << std::fixed << std::setprecision(2) << progress << "%\n";
        ss << "  Height: " << currentHeight << " / " << targetHeight << "\n";
        ss << "  Headers: " << headersReceived << "\n";
        ss << "  Blocks: " << blocksReceived << "\n";
        ss << "  Queued: " << blocksQueued << "\n";
        ss << "  Failed: " << blocksFailed << "\n";
        ss << "  Speed: " << (bytesPerSecond / 1024) << " KB/s\n";
        ss << "  Elapsed: " << elapsedTime.count() / 1000 << "s\n";
        ss << "  Remaining: " << estimatedTimeRemaining.count() / 1000 << "s\n";
        return ss.str();
    }

    // ============== SyncConfig Implementation ==============

    SyncConfig::SyncConfig()
        : mode(SyncMode::HEADERS_FIRST),
          maxParallelDownloads(5),
          maxQueuedBlocks(100),
          blockTimeout(30000),    // 30 seconds
          headerTimeout(10000),    // 10 seconds
          maxRetries(3),
          validateBlocks(true),
          validateTransactions(true),
          storeBlocks(true),
          pruneBlocks(false),
          pruneAfterHeight(1000),
          blockDirectory("blocks"),
          headerDirectory("headers") {}

    // ============== BlockRequest Implementation ==============

    BlockRequest::BlockRequest() : height(0), retryCount(0), isUrgent(false) {}

    bool BlockRequest::isExpired(std::chrono::milliseconds timeout) const {
        auto now = std::chrono::steady_clock::now();
        return (now - requestTime) > timeout;
    }

    // ============== HeaderRequest Implementation ==============

    HeaderRequest::HeaderRequest() : retryCount(0) {}

    bool HeaderRequest::isExpired(std::chrono::milliseconds timeout) const {
        auto now = std::chrono::steady_clock::now();
        return (now - requestTime) > timeout;
    }

    // ============== SyncStats Implementation ==============

    SyncStats::SyncStats()
        : totalHeaders(0),
          totalBlocks(0),
          totalBytes(0),
          failedHeaders(0),
          failedBlocks(0),
          orphanBlocks(0),
          duplicateBlocks(0),
          invalidBlocks(0),
          averageBlockTime(0),
          averageHeaderTime(0) {}

    void SyncStats::reset() {
        totalHeaders = 0;
        totalBlocks = 0;
        totalBytes = 0;
        failedHeaders = 0;
        failedBlocks = 0;
        orphanBlocks = 0;
        duplicateBlocks = 0;
        invalidBlocks = 0;
        averageBlockTime = std::chrono::milliseconds(0);
        averageHeaderTime = std::chrono::milliseconds(0);
        peerContributions.clear();
    }

    // ============== Synchronizer Implementation ==============

    struct Synchronizer::Impl {
        SyncState state;
        SyncConfig config;
        SyncProgress progress;
        SyncStats stats;
        
        uint32_t targetHeight;
        uint32_t currentHeight;
        std::string targetHash;
        std::string bestBlockHash;
        
        std::map<std::string, uint32_t> peerHeights;
        std::map<std::string, std::vector<BlockRequest>> pendingRequests;
        std::map<std::string, HeaderRequest> headerRequests;
        std::map<std::string, Block> receivedBlocks;
        std::set<std::string> requestedHashes;
        std::set<std::string> receivedHashes;
        
        std::vector<HeadersMessage::BlockHeader> headers;
        std::map<uint32_t, std::string> heightToHash;
        std::map<std::string, uint32_t> hashToHeight;
        
        std::chrono::steady_clock::time_point startTime;
        std::chrono::steady_clock::time_point lastActivity;
        uint64_t bytesDownloaded;
        
        std::function<void(const Block&, const std::string&)> onBlockReceived;
        std::function<void(const HeadersMessage::BlockHeader&, const std::string&)> onHeaderReceived;
        std::function<void(const SyncProgress&)> onProgress;
        std::function<void()> onComplete;
        std::function<void(const std::string&)> onError;

        Impl() : state(SyncState::IDLE), targetHeight(0), currentHeight(0),
                 bytesDownloaded(0) {}
    };

    Synchronizer::Synchronizer(const SyncConfig& config) {
        impl = std::make_unique<Impl>();
        impl->config = config;
    }

    Synchronizer::~Synchronizer() = default;

    void Synchronizer::start(uint32_t height) {
        impl->targetHeight = height;
        impl->state = SyncState::HEADER_SYNC;
        impl->startTime = std::chrono::steady_clock::now();
        impl->lastActivity = impl->startTime;
    }

    void Synchronizer::start(const std::string& hash) {
        impl->targetHash = hash;
        impl->state = SyncState::HEADER_SYNC;
        impl->startTime = std::chrono::steady_clock::now();
        impl->lastActivity = impl->startTime;
    }

    void Synchronizer::stop() {
        impl->state = SyncState::IDLE;
    }

    void Synchronizer::pause() {
        if (impl->state == SyncState::HEADER_SYNC || impl->state == SyncState::BLOCK_SYNC) {
            impl->state = SyncState::PAUSED;
        }
    }

    void Synchronizer::resume() {
        if (impl->state == SyncState::PAUSED) {
            impl->state = impl->targetHeight > impl->currentHeight ? 
                         SyncState::BLOCK_SYNC : SyncState::HEADER_SYNC;
        }
    }

    void Synchronizer::cancel() {
        impl->state = SyncState::CANCELLED;
        impl->pendingRequests.clear();
        impl->headerRequests.clear();
        impl->requestedHashes.clear();
    }

    void Synchronizer::reset() {
        impl->state = SyncState::IDLE;
        impl->targetHeight = 0;
        impl->currentHeight = 0;
        impl->targetHash.clear();
        impl->bestBlockHash.clear();
        impl->pendingRequests.clear();
        impl->headerRequests.clear();
        impl->receivedBlocks.clear();
        impl->requestedHashes.clear();
        impl->receivedHashes.clear();
        impl->headers.clear();
        impl->heightToHash.clear();
        impl->hashToHeight.clear();
        impl->bytesDownloaded = 0;
        impl->progress = SyncProgress();
        impl->stats.reset();
    }

    bool Synchronizer::isSyncing() const {
        return impl->state == SyncState::HEADER_SYNC || 
               impl->state == SyncState::BLOCK_SYNC;
    }

    SyncState Synchronizer::getState() const {
        return impl->state;
    }

    SyncProgress Synchronizer::getProgress() const {
        impl->progress.state = impl->state;
        impl->progress.mode = impl->config.mode;
        impl->progress.targetHeight = impl->targetHeight;
        impl->progress.currentHeight = impl->currentHeight;
        impl->progress.headersReceived = impl->headers.size();
        impl->progress.blocksReceived = impl->receivedBlocks.size();
        impl->progress.blocksQueued = impl->pendingRequests.size();
        impl->progress.bytesDownloaded = impl->bytesDownloaded;
        
        auto now = std::chrono::steady_clock::now();
        impl->progress.elapsedTime = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - impl->startTime);
        
        if (impl->targetHeight > 0 && impl->currentHeight > 0) {
            impl->progress.progress = (static_cast<double>(impl->currentHeight) / 
                                       impl->targetHeight) * 100.0;
        }

        if (impl->bytesDownloaded > 0 && impl->progress.elapsedTime.count() > 0) {
            impl->progress.bytesPerSecond = impl->bytesDownloaded * 1000 / 
                                           impl->progress.elapsedTime.count();
        }

        return impl->progress;
    }

    SyncStats Synchronizer::getStats() const {
        return impl->stats;
    }

    void Synchronizer::setTargetHeight(uint32_t height) {
        impl->targetHeight = height;
    }

    void Synchronizer::setTargetHash(const std::string& hash) {
        impl->targetHash = hash;
    }

    uint32_t Synchronizer::getTargetHeight() const {
        return impl->targetHeight;
    }

    uint32_t Synchronizer::getCurrentHeight() const {
        return impl->currentHeight;
    }

    void Synchronizer::addPeer(const std::string& peerId, uint32_t height) {
        impl->peerHeights[peerId] = height;
    }

    void Synchronizer::removePeer(const std::string& peerId) {
        impl->peerHeights.erase(peerId);
        impl->pendingRequests.erase(peerId);
    }

    void Synchronizer::updatePeerHeight(const std::string& peerId, uint32_t height) {
        impl->peerHeights[peerId] = height;
    }

    std::string Synchronizer::getBestPeer() const {
        std::string bestPeer;
        uint32_t bestHeight = 0;

        for (const auto& [peerId, height] : impl->peerHeights) {
            if (height > bestHeight) {
                bestHeight = height;
                bestPeer = peerId;
            }
        }

        return bestPeer;
    }

    std::vector<std::string> Synchronizer::getSyncingPeers() const {
        std::vector<std::string> peers;
        for (const auto& [peerId, _] : impl->peerHeights) {
            peers.push_back(peerId);
        }
        return peers;
    }

    bool Synchronizer::processHeaders(const std::string& peerId, const HeadersMessage& headers) {
        if (headers.headers.empty()) {
            return false;
        }

        impl->lastActivity = std::chrono::steady_clock::now();
        impl->stats.totalHeaders += headers.headers.size();

        // Validate header chain
        for (size_t i = 0; i < headers.headers.size(); i++) {
            const auto& header = headers.headers[i];
            
            // Check if we already have this header
            if (impl->hashToHeight.find(header.previousBlockHash) == impl->hashToHeight.end()) {
                if (i > 0) {
                    // Orphan header
                    impl->stats.orphanBlocks++;
                    continue;
                }
            }

            // Validate header
            if (impl->config.validateBlocks) {
                if (i > 0) {
                    if (!validateHeader(header, headers.headers[i-1])) {
                        impl->stats.invalidBlocks++;
                        continue;
                    }
                }
            }

            // Store header
            impl->headers.push_back(header);
            uint32_t height = impl->headers.size() - 1;
            impl->heightToHash[height] = header.previousBlockHash;
            impl->hashToHeight[header.previousBlockHash] = height;

            if (impl->onHeaderReceived) {
                impl->onHeaderReceived(header, peerId);
            }
        }

        // Update progress
        if (!impl->headers.empty()) {
            impl->currentHeight = impl->headers.size() - 1;
        }

        return true;
    }

    bool Synchronizer::processBlock(const std::string& peerId, const std::vector<uint8_t>& blockData) {
        Block block;
        if (!block.deserialize(std::string(blockData.begin(), blockData.end()))) {
            impl->stats.invalidBlocks++;
            return false;
        }

        return processBlock(peerId, block);
    }

    bool Synchronizer::processBlock(const std::string& peerId, const Block& block) {
        impl->lastActivity = std::chrono::steady_clock::now();
        impl->stats.totalBlocks++;
        impl->bytesDownloaded += block.getSize();

        // Check if we need this block
        if (!isBlockNeeded(block.getHash(), block.getHeight())) {
            impl->stats.duplicateBlocks++;
            return false;
        }

        // Validate block
        if (impl->config.validateBlocks) {
            // Get previous block
            auto prevBlock = getBlockByHash(block.getPreviousHash());
            if (!prevBlock && block.getHeight() > 0) {
                impl->stats.orphanBlocks++;
                return false;
            }

            // TODO: Full block validation
        }

        // Store block
        impl->receivedBlocks[block.getHash()] = block;
        impl->receivedHashes.insert(block.getHash());
        impl->stats.peerContributions[peerId]++;

        // Remove from pending requests
        auto& peerRequests = impl->pendingRequests[peerId];
        peerRequests.erase(
            std::remove_if(peerRequests.begin(), peerRequests.end(),
                [&](const BlockRequest& req) { return req.hash == block.getHash(); }),
            peerRequests.end());

        if (impl->onBlockReceived) {
            impl->onBlockReceived(block, peerId);
        }

        // Update current height
        if (block.getHeight() > impl->currentHeight) {
            impl->currentHeight = block.getHeight();
            impl->bestBlockHash = block.getHash();
        }

        // Check if sync complete
        if (impl->targetHeight > 0 && impl->currentHeight >= impl->targetHeight) {
            impl->state = SyncState::COMPLETED;
            if (impl->onComplete) {
                impl->onComplete();
            }
        }

        return true;
    }

    void Synchronizer::processNotFound(const std::string& peerId, const NotFoundMessage& notFound) {
        for (const auto& inv : notFound.inventories) {
            auto& peerRequests = impl->pendingRequests[peerId];
            peerRequests.erase(
                std::remove_if(peerRequests.begin(), peerRequests.end(),
                    [&](const BlockRequest& req) { return req.hash == inv.hash; }),
                peerRequests.end());
            impl->requestedHashes.erase(inv.hash);
            impl->stats.failedBlocks++;
        }
    }

    std::map<std::string, std::vector<InventoryVector>> Synchronizer::getNextRequests(uint32_t maxRequests) {
        std::map<std::string, std::vector<InventoryVector>> requests;
        uint32_t requestCount = 0;

        for (const auto& [peerId, height] : impl->peerHeights) {
            if (requestCount >= maxRequests) break;

            auto& peerRequests = impl->pendingRequests[peerId];
            uint32_t peerRequestCount = 0;

            // Calculate how many blocks we need from this peer
            uint32_t blocksNeeded = std::min(
                impl->config.maxParallelDownloads - peerRequests.size(),
                maxRequests - requestCount
            );

            for (uint32_t i = 0; i < blocksNeeded; i++) {
                // Find next needed block
                for (uint32_t h = impl->currentHeight + 1; h <= impl->targetHeight; h++) {
                    auto it = impl->heightToHash.find(h);
                    if (it != impl->heightToHash.end()) {
                        std::string hash = it->second;
                        if (impl->receivedHashes.find(hash) == impl->receivedHashes.end() &&
                            impl->requestedHashes.find(hash) == impl->requestedHashes.end()) {
                            
                            requests[peerId].emplace_back(InventoryType::MSG_BLOCK, hash);
                            
                            BlockRequest req;
                            req.hash = hash;
                            req.height = h;
                            req.peerId = peerId;
                            req.requestTime = std::chrono::steady_clock::now();
                            peerRequests.push_back(req);
                            
                            impl->requestedHashes.insert(hash);
                            requestCount++;
                            peerRequestCount++;
                            break;
                        }
                    }
                }
            }
        }

        return requests;
    }

    std::unique_ptr<HeaderRequest> Synchronizer::getNextHeaderRequest() {
        if (impl->state != SyncState::HEADER_SYNC) {
            return nullptr;
        }

        auto request = std::make_unique<HeaderRequest>();
        request->locator = getBlockLocator().hashes;
        request->hashStop = impl->targetHash.empty() ? "0" : impl->targetHash;
        request->requestTime = std::chrono::steady_clock::now();

        return request;
    }

    BlockLocator Synchronizer::getBlockLocator() const {
        std::vector<std::string> hashes;

        // Add recent blocks exponentially
        uint32_t height = impl->currentHeight;
        uint32_t step = 1;

        while (height > 0 && hashes.size() < 10) {
            auto it = impl->heightToHash.find(height);
            if (it != impl->heightToHash.end()) {
                hashes.push_back(it->second);
            }
            
            height = (height > step) ? height - step : 0;
            step *= 2;
        }

        // Always include genesis if we have it
        auto genesisIt = impl->heightToHash.find(0);
        if (genesisIt != impl->heightToHash.end()) {
            if (hashes.empty() || hashes.back() != genesisIt->second) {
                hashes.push_back(genesisIt->second);
            }
        }

        return BlockLocator(hashes);
    }

    bool Synchronizer::isBlockNeeded(const std::string& blockHash, uint32_t blockHeight) const {
        // Check if we already have this block
        if (impl->receivedHashes.find(blockHash) != impl->receivedHashes.end()) {
            return false;
        }

        // Check if block height is within target range
        if (impl->targetHeight > 0 && blockHeight > impl->targetHeight) {
            return false;
        }

        // Check if we already requested this block
        if (impl->requestedHashes.find(blockHash) != impl->requestedHashes.end()) {
            return false;
        }

        return true;
    }

    bool Synchronizer::isHeaderNeeded(const std::string& headerHash, uint32_t headerHeight) const {
        return impl->hashToHeight.find(headerHash) == impl->hashToHeight.end();
    }

    bool Synchronizer::validateBlock(const Block& block) const {
        // TODO: Implement full block validation
        return true;
    }

    bool Synchronizer::validateHeader(const HeadersMessage::BlockHeader& header,
                                      const HeadersMessage::BlockHeader& previousHeader) const {
        // Check previous hash
        if (header.previousBlockHash != previousHeader.previousBlockHash) {
            return false;
        }

        // Check timestamp
        if (header.timestamp <= previousHeader.timestamp) {
            return false;
        }

        // TODO: Check proof of work

        return true;
    }

    bool Synchronizer::storeBlock(const Block& block) {
        // TODO: Implement block storage to disk
        return true;
    }

    bool Synchronizer::storeHeader(const HeadersMessage::BlockHeader& header) {
        // TODO: Implement header storage to disk
        return true;
    }

    std::unique_ptr<Block> Synchronizer::getBlockAtHeight(uint32_t height) const {
        auto it = impl->heightToHash.find(height);
        if (it != impl->heightToHash.end()) {
            return getBlockByHash(it->second);
        }
        return nullptr;
    }

    std::unique_ptr<Block> Synchronizer::getBlockByHash(const std::string& hash) const {
        auto it = impl->receivedBlocks.find(hash);
        if (it != impl->receivedBlocks.end()) {
            return std::make_unique<Block>(it->second);
        }
        return nullptr;
    }

    std::unique_ptr<HeadersMessage::BlockHeader> Synchronizer::getHeaderAtHeight(uint32_t height) const {
        if (height < impl->headers.size()) {
            return std::make_unique<HeadersMessage::BlockHeader>(impl->headers[height]);
        }
        return nullptr;
    }

    std::unique_ptr<HeadersMessage::BlockHeader> Synchronizer::getHeaderByHash(const std::string& hash) const {
        auto it = impl->hashToHeight.find(hash);
        if (it != impl->hashToHeight.end() && it->second < impl->headers.size()) {
            return std::make_unique<HeadersMessage::BlockHeader>(impl->headers[it->second]);
        }
        return nullptr;
    }

    std::vector<HeadersMessage::BlockHeader> Synchronizer::getHeaderChain(uint32_t fromHeight,
                                                                          uint32_t toHeight) const {
        std::vector<HeadersMessage::BlockHeader> result;
        fromHeight = std::max(fromHeight, 0u);
        toHeight = std::min(toHeight, static_cast<uint32_t>(impl->headers.size() - 1));

        for (uint32_t i = fromHeight; i <= toHeight; i++) {
            result.push_back(impl->headers[i]);
        }

        return result;
    }

    bool Synchronizer::isSynced() const {
        if (impl->targetHeight == 0) return false;
        return impl->currentHeight >= impl->targetHeight;
    }

    double Synchronizer::getSyncPercentage() const {
        if (impl->targetHeight == 0) return 0.0;
        return (static_cast<double>(impl->currentHeight) / impl->targetHeight) * 100.0;
    }

    std::chrono::milliseconds Synchronizer::getEstimatedTimeRemaining() const {
        if (impl->bytesPerSecond == 0) return std::chrono::milliseconds(0);

        uint64_t bytesRemaining = 0;
        for (uint32_t h = impl->currentHeight + 1; h <= impl->targetHeight; h++) {
            // Estimate block size (average 1MB)
            bytesRemaining += 1024 * 1024;
        }

        uint64_t secondsRemaining = bytesRemaining / impl->bytesPerSecond;
        return std::chrono::milliseconds(secondsRemaining * 1000);
    }

    void Synchronizer::setOnBlockReceived(std::function<void(const Block&, const std::string&)> callback) {
        impl->onBlockReceived = callback;
    }

    void Synchronizer::setOnHeaderReceived(std::function<void(const HeadersMessage::BlockHeader&, 
                                                              const std::string&)> callback) {
        impl->onHeaderReceived = callback;
    }

    void Synchronizer::setOnProgress(std::function<void(const SyncProgress&)> callback) {
        impl->onProgress = callback;
    }

    void Synchronizer::setOnComplete(std::function<void()> callback) {
        impl->onComplete = callback;
    }

    void Synchronizer::setOnError(std::function<void(const std::string&)> callback) {
        impl->onError = callback;
    }

} // namespace powercoin