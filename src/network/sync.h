#ifndef POWERCOIN_SYNC_H
#define POWERCOIN_SYNC_H

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <functional>
#include <chrono>
#include <mutex>
#include <atomic>
#include "messages.h"
#include "../blockchain/block.h"
#include "../blockchain/transaction.h"

namespace powercoin {

    /**
     * Synchronization mode
     */
    enum class SyncMode {
        HEADERS_FIRST,      // Download headers first, then blocks
        BLOCKS_STREAMING,   // Stream blocks as they come
        PARALLEL,           // Parallel download from multiple peers
        LIGHT_CLIENT,       // Only download headers and merkle proofs
        PRUNED              // Download blocks but prune old ones
    };

    /**
     * Synchronization state
     */
    enum class SyncState {
        IDLE,               // Not syncing
        HEADER_SYNC,        // Downloading headers
        BLOCK_SYNC,         // Downloading blocks
        COMPLETED,          // Sync completed
        PAUSED,             // Sync paused
        FAILED,             // Sync failed
        CANCELLED           // Sync cancelled
    };

    /**
     * Block locator for efficient sync
     */
    struct BlockLocator {
        std::vector<std::string> hashes;
        uint32_t startHeight;
        uint32_t stopHeight;

        BlockLocator();
        explicit BlockLocator(const std::vector<std::string>& locator);
        
        bool isValid() const;
        std::string toString() const;
        std::vector<uint8_t> serialize() const;
        bool deserialize(const std::vector<uint8_t>& data);
        
        static BlockLocator createFromChain(const std::vector<Block>& chain);
        static BlockLocator createFromHeight(uint32_t height, const std::string& genesisHash);
    };

    /**
     * Sync progress information
     */
    struct SyncProgress {
        SyncState state;
        SyncMode mode;
        uint32_t targetHeight;
        uint32_t currentHeight;
        uint32_t headersReceived;
        uint32_t blocksReceived;
        uint32_t blocksQueued;
        uint32_t blocksFailed;
        double progress;
        uint64_t bytesDownloaded;
        uint64_t bytesPerSecond;
        std::chrono::milliseconds estimatedTimeRemaining;
        std::chrono::milliseconds elapsedTime;
        std::string currentPeer;
        std::string bestBlockHash;

        SyncProgress();
        std::string toString() const;
    };

    /**
     * Sync configuration
     */
    struct SyncConfig {
        SyncMode mode;
        uint32_t maxParallelDownloads;
        uint32_t maxQueuedBlocks;
        std::chrono::milliseconds blockTimeout;
        std::chrono::milliseconds headerTimeout;
        uint32_t maxRetries;
        bool validateBlocks;
        bool validateTransactions;
        bool storeBlocks;
        bool pruneBlocks;
        uint32_t pruneAfterHeight;
        std::string blockDirectory;
        std::string headerDirectory;

        SyncConfig();
    };

    /**
     * Block download request
     */
    struct BlockRequest {
        std::string hash;
        uint32_t height;
        std::string peerId;
        std::chrono::steady_clock::time_point requestTime;
        uint32_t retryCount;
        bool isUrgent;

        BlockRequest();
        bool isExpired(std::chrono::milliseconds timeout) const;
    };

    /**
     * Header download request
     */
    struct HeaderRequest {
        std::vector<std::string> locator;
        std::string hashStop;
        std::string peerId;
        std::chrono::steady_clock::time_point requestTime;
        uint32_t retryCount;

        HeaderRequest();
        bool isExpired(std::chrono::milliseconds timeout) const;
    };

    /**
     * Sync statistics
     */
    struct SyncStats {
        uint64_t totalHeaders;
        uint64_t totalBlocks;
        uint64_t totalBytes;
        uint64_t failedHeaders;
        uint64_t failedBlocks;
        uint64_t orphanBlocks;
        uint64_t duplicateBlocks;
        uint64_t invalidBlocks;
        std::chrono::milliseconds averageBlockTime;
        std::chrono::milliseconds averageHeaderTime;
        std::map<std::string, uint64_t> peerContributions;

        SyncStats();
        void reset();
    };

    /**
     * Main synchronization class
     * Manages blockchain synchronization with peers
     */
    class Synchronizer {
    private:
        struct Impl;
        std::unique_ptr<Impl> impl;

    public:
        /**
         * Constructor
         * @param config Sync configuration
         */
        explicit Synchronizer(const SyncConfig& config = SyncConfig());

        /**
         * Destructor
         */
        ~Synchronizer();

        // Disable copy
        Synchronizer(const Synchronizer&) = delete;
        Synchronizer& operator=(const Synchronizer&) = delete;

        /**
         * Start synchronization
         * @param targetHeight Target height to sync to
         */
        void start(uint32_t targetHeight);

        /**
         * Start synchronization with target hash
         * @param targetHash Target block hash
         */
        void start(const std::string& targetHash);

        /**
         * Stop synchronization
         */
        void stop();

        /**
         * Pause synchronization
         */
        void pause();

        /**
         * Resume synchronization
         */
        void resume();

        /**
         * Cancel synchronization
         */
        void cancel();

        /**
         * Reset synchronizer state
         */
        void reset();

        /**
         * Check if syncing is active
         * @return true if syncing
         */
        bool isSyncing() const;

        /**
         * Get current sync state
         * @return Sync state
         */
        SyncState getState() const;

        /**
         * Get sync progress
         * @return Progress information
         */
        SyncProgress getProgress() const;

        /**
         * Get sync statistics
         * @return Sync statistics
         */
        SyncStats getStats() const;

        /**
         * Set target height
         * @param height Target height
         */
        void setTargetHeight(uint32_t height);

        /**
         * Set target hash
         * @param hash Target block hash
         */
        void setTargetHash(const std::string& hash);

        /**
         * Get target height
         * @return Target height
         */
        uint32_t getTargetHeight() const;

        /**
         * Get current height
         * @return Current synced height
         */
        uint32_t getCurrentHeight() const;

        /**
         * Add peer for synchronization
         * @param peerId Peer identifier
         * @param height Peer's blockchain height
         */
        void addPeer(const std::string& peerId, uint32_t height);

        /**
         * Remove peer from synchronization
         * @param peerId Peer identifier
         */
        void removePeer(const std::string& peerId);

        /**
         * Update peer height
         * @param peerId Peer identifier
         * @param height New height
         */
        void updatePeerHeight(const std::string& peerId, uint32_t height);

        /**
         * Get best peer for sync
         * @return Best peer ID
         */
        std::string getBestPeer() const;

        /**
         * Get all syncing peers
         * @return Vector of peer IDs
         */
        std::vector<std::string> getSyncingPeers() const;

        /**
         * Process headers message from peer
         * @param peerId Peer identifier
         * @param headers Headers message
         * @return true if processed successfully
         */
        bool processHeaders(const std::string& peerId, const HeadersMessage& headers);

        /**
         * Process block message from peer
         * @param peerId Peer identifier
         * @param block Block data
         * @return true if processed successfully
         */
        bool processBlock(const std::string& peerId, const std::vector<uint8_t>& block);

        /**
         * Process block message from peer
         * @param peerId Peer identifier
         * @param block Block object
         * @return true if processed successfully
         */
        bool processBlock(const std::string& peerId, const Block& block);

        /**
         * Process not found message
         * @param peerId Peer identifier
         * @param notFound Not found message
         */
        void processNotFound(const std::string& peerId, const NotFoundMessage& notFound);

        /**
         * Get next block requests
         * @param maxRequests Maximum number of requests
         * @return Map of peer ID to inventory vectors
         */
        std::map<std::string, std::vector<InventoryVector>> getNextRequests(uint32_t maxRequests);

        /**
         * Get next header request
         * @return Header request or nullptr if none
         */
        std::unique_ptr<HeaderRequest> getNextHeaderRequest();

        /**
         * Get block locator for current chain
         * @return Block locator
         */
        BlockLocator getBlockLocator() const;

        /**
         * Check if block is needed
         * @param blockHash Block hash
         * @param blockHeight Block height
         * @return true if block is needed
         */
        bool isBlockNeeded(const std::string& blockHash, uint32_t blockHeight) const;

        /**
         * Check if header is needed
         * @param headerHash Header hash
         * @param headerHeight Header height
         * @return true if header is needed
         */
        bool isHeaderNeeded(const std::string& headerHash, uint32_t headerHeight) const;

        /**
         * Validate block
         * @param block Block to validate
         * @return true if valid
         */
        bool validateBlock(const Block& block) const;

        /**
         * Validate header
         * @param header Header to validate
         * @param previousHeader Previous header
         * @return true if valid
         */
        bool validateHeader(const HeadersMessage::BlockHeader& header,
                           const HeadersMessage::BlockHeader& previousHeader) const;

        /**
         * Store block
         * @param block Block to store
         * @return true if stored successfully
         */
        bool storeBlock(const Block& block);

        /**
         * Store header
         * @param header Header to store
         * @return true if stored successfully
         */
        bool storeHeader(const HeadersMessage::BlockHeader& header);

        /**
         * Get block at height
         * @param height Block height
         * @return Block if found
         */
        std::unique_ptr<Block> getBlockAtHeight(uint32_t height) const;

        /**
         * Get block by hash
         * @param hash Block hash
         * @return Block if found
         */
        std::unique_ptr<Block> getBlockByHash(const std::string& hash) const;

        /**
         * Get header at height
         * @param height Header height
         * @return Header if found
         */
        std::unique_ptr<HeadersMessage::BlockHeader> getHeaderAtHeight(uint32_t height) const;

        /**
         * Get header by hash
         * @param hash Header hash
         * @return Header if found
         */
        std::unique_ptr<HeadersMessage::BlockHeader> getHeaderByHash(const std::string& hash) const;

        /**
         * Get chain of headers
         * @param fromHeight Starting height
         * @param toHeight Ending height
         * @return Vector of headers
         */
        std::vector<HeadersMessage::BlockHeader> getHeaderChain(uint32_t fromHeight, 
                                                                uint32_t toHeight) const;

        /**
         * Check if blockchain is synced
         * @return true if synced
         */
        bool isSynced() const;

        /**
         * Get sync percentage
         * @return Sync percentage (0-100)
         */
        double getSyncPercentage() const;

        /**
         * Get estimated time remaining
         * @return Estimated time
         */
        std::chrono::milliseconds getEstimatedTimeRemaining() const;

        /**
         * Set callback for block received
         * @param callback Callback function
         */
        void setOnBlockReceived(std::function<void(const Block&, const std::string&)> callback);

        /**
         * Set callback for header received
         * @param callback Callback function
         */
        void setOnHeaderReceived(std::function<void(const HeadersMessage::BlockHeader&, 
                                                    const std::string&)> callback);

        /**
         * Set callback for sync progress
         * @param callback Callback function
         */
        void setOnProgress(std::function<void(const SyncProgress&)> callback);

        /**
         * Set callback for sync complete
         * @param callback Callback function
         */
        void setOnComplete(std::function<void()> callback);

        /**
         * Set callback for sync error
         * @param callback Callback function
         */
        void setOnError(std::function<void(const std::string&)> callback);
    };

    /**
     * Header downloader for light clients
     */
    class HeaderDownloader {
    private:
        std::unique_ptr<class HeaderDownloaderImpl> impl;

    public:
        HeaderDownloader();
        ~HeaderDownloader();

        bool start(const std::string& startHash, uint32_t startHeight);
        bool stop();
        bool processHeaders(const std::vector<HeadersMessage::BlockHeader>& headers);
        bool verifyHeaderChain() const;
        std::vector<HeadersMessage::BlockHeader> getHeaders(uint32_t from, uint32_t to) const;
        uint32_t getBestHeight() const;
        std::string getBestHash() const;
    };

    /**
     * Block downloader for parallel downloads
     */
    class BlockDownloader {
    private:
        std::unique_ptr<class BlockDownloaderImpl> impl;

    public:
        explicit BlockDownloader(uint32_t maxParallel);
        ~BlockDownloader();

        void addRequest(const std::string& hash, uint32_t height);
        void removeRequest(const std::string& hash);
        std::vector<InventoryVector> getNextRequests(uint32_t maxCount);
        bool processBlock(const Block& block);
        bool hasPending() const;
        uint32_t getPendingCount() const;
        void clear();
    };

} // namespace powercoin

#endif // POWERCOIN_SYNC_H