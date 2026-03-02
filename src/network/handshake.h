#ifndef POWERCOIN_HANDSHAKE_H
#define POWERCOIN_HANDSHAKE_H

#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include "messages.h"
#include "../crypto/random.h"

namespace powercoin {

    /**
     * Handshake state machine states
     */
    enum class HandshakeState {
        INIT,           // Initial state
        SENT_VERSION,   // Version message sent
        SENT_VERACK,    // Verack message sent
        RECEIVED_VERSION, // Version message received
        RECEIVED_VERACK,  // Verack message received
        COMPLETE,       // Handshake complete
        FAILED,         // Handshake failed
        TIMEOUT         // Handshake timeout
    };

    /**
     * Handshake result
     */
    struct HandshakeResult {
        bool success;
        HandshakeState finalState;
        std::string errorMessage;
        uint32_t peerVersion;
        uint64_t peerServices;
        std::string peerUserAgent;
        uint32_t peerHeight;
        uint64_t pingTime;
        std::chrono::milliseconds duration;

        HandshakeResult();
        std::string toString() const;
    };

    /**
     * Handshake configuration
     */
    struct HandshakeConfig {
        uint32_t protocolVersion;
        uint64_t localServices;
        std::string localUserAgent;
        uint32_t localHeight;
        uint16_t localPort;
        std::chrono::milliseconds handshakeTimeout;
        std::chrono::milliseconds pingTimeout;
        bool requireVerack;
        bool requireWitness;
        bool requireBloom;
        bool sendPingAfterHandshake;

        HandshakeConfig();
    };

    /**
     * Handshake statistics
     */
    struct HandshakeStats {
        uint64_t totalHandshakes;
        uint64_t successfulHandshakes;
        uint64_t failedHandshakes;
        uint64_t timeouts;
        std::chrono::milliseconds averageDuration;
        std::chrono::milliseconds minDuration;
        std::chrono::milliseconds maxDuration;
        std::map<HandshakeState, uint64_t> stateCounts;

        HandshakeStats();
        void update(const HandshakeResult& result);
        void reset();
    };

    /**
     * Main handshake class
     * Manages the peer connection handshake process
     */
    class Handshake {
    private:
        HandshakeState state;
        HandshakeConfig config;
        HandshakeStats stats;
        
        // Handshake data
        uint64_t localNonce;
        uint64_t remoteNonce;
        VersionMessage localVersion;
        VersionMessage remoteVersion;
        
        // Timing
        std::chrono::steady_clock::time_point startTime;
        std::chrono::steady_clock::time_point lastActivity;
        
        // Callbacks
        std::function<void(HandshakeState, const std::string&)> onStateChange;
        std::function<void(const HandshakeResult&)> onComplete;
        std::function<void(const std::string&)> onError;

        // Internal methods
        bool validateVersion(const VersionMessage& version) const;
        bool validateNonce(uint64_t nonce) const;
        void transitionTo(HandshakeState newState, const std::string& reason = "");
        void setError(const std::string& message);

    public:
        /**
         * Constructor
         * @param config Handshake configuration
         */
        explicit Handshake(const HandshakeConfig& config = HandshakeConfig());

        /**
         * Destructor
         */
        ~Handshake();

        // Disable copy
        Handshake(const Handshake&) = delete;
        Handshake& operator=(const Handshake&) = delete;

        /**
         * Reset handshake to initial state
         */
        void reset();

        /**
         * Start handshake process
         * @return Version message to send to peer
         */
        VersionMessage start();

        /**
         * Process incoming message
         * @param message Received message
         * @return Message to send in response (empty if none)
         */
        std::unique_ptr<NetworkMessage> processMessage(const NetworkMessage& message);

        /**
         * Process incoming raw data
         * @param data Raw message data
         * @return Message to send in response (empty if none)
         */
        std::unique_ptr<NetworkMessage> processData(const std::vector<uint8_t>& data);

        /**
         * Check if handshake is complete
         * @return true if handshake is complete
         */
        bool isComplete() const { return state == HandshakeState::COMPLETE; }

        /**
         * Check if handshake has failed
         * @return true if handshake failed
         */
        bool hasFailed() const { return state == HandshakeState::FAILED; }

        /**
         * Get current state
         * @return Current handshake state
         */
        HandshakeState getState() const { return state; }

        /**
         * Get handshake result
         * @return Handshake result (only valid if complete or failed)
         */
        HandshakeResult getResult() const;

        /**
         * Get remote peer information
         * @return Remote version message
         */
        const VersionMessage& getRemoteVersion() const { return remoteVersion; }

        /**
         * Get local version message
         * @return Local version message
         */
        const VersionMessage& getLocalVersion() const { return localVersion; }

        /**
         * Check if timeout occurred
         * @return true if handshake has timed out
         */
        bool hasTimedOut() const;

        /**
         * Get time since last activity
         * @return Milliseconds since last activity
         */
        std::chrono::milliseconds getIdleTime() const;

        /**
         * Get handshake duration
         * @return Duration so far (or total if complete)
         */
        std::chrono::milliseconds getDuration() const;

        /**
         * Get handshake statistics
         * @return Handshake statistics
         */
        const HandshakeStats& getStats() const { return stats; }

        /**
         * Reset statistics
         */
        void resetStats();

        /**
         * Set state change callback
         * @param callback Function to call on state change
         */
        void setOnStateChange(std::function<void(HandshakeState, const std::string&)> callback);

        /**
         * Set completion callback
         * @param callback Function to call on handshake complete
         */
        void setOnComplete(std::function<void(const HandshakeResult&)> callback);

        /**
         * Set error callback
         * @param callback Function to call on error
         */
        void setOnError(std::function<void(const std::string&)> callback);

        /**
         * Get state name
         * @param state Handshake state
         * @return String representation
         */
        static std::string stateToString(HandshakeState state);
    };

    /**
     * Handshake manager for multiple peers
     */
    class HandshakeManager {
    private:
        struct PeerHandshake {
            std::string peerId;
            std::unique_ptr<Handshake> handshake;
            std::chrono::steady_clock::time_point startTime;
        };

        std::map<std::string, std::unique_ptr<PeerHandshake>> handshakes;
        HandshakeConfig defaultConfig;
        HandshakeStats globalStats;
        mutable std::mutex mutex;

    public:
        /**
         * Constructor
         * @param config Default handshake configuration
         */
        explicit HandshakeManager(const HandshakeConfig& config = HandshakeConfig());

        /**
         * Destructor
         */
        ~HandshakeManager();

        /**
         * Start handshake for a peer
         * @param peerId Peer identifier
         * @return Version message to send
         */
        VersionMessage startHandshake(const std::string& peerId);

        /**
         * Process message for a peer
         * @param peerId Peer identifier
         * @param message Received message
         * @return Message to send back (empty if none)
         */
        std::unique_ptr<NetworkMessage> processMessage(const std::string& peerId,
                                                       const NetworkMessage& message);

        /**
         * Process raw data for a peer
         * @param peerId Peer identifier
         * @param data Raw message data
         * @return Message to send back (empty if none)
         */
        std::unique_ptr<NetworkMessage> processData(const std::string& peerId,
                                                    const std::vector<uint8_t>& data);

        /**
         * Check if peer handshake is complete
         * @param peerId Peer identifier
         * @return true if handshake complete
         */
        bool isHandshakeComplete(const std::string& peerId) const;

        /**
         * Get handshake result for peer
         * @param peerId Peer identifier
         * @return Handshake result
         */
        HandshakeResult getHandshakeResult(const std::string& peerId) const;

        /**
         * Remove peer handshake
         * @param peerId Peer identifier
         */
        void removeHandshake(const std::string& peerId);

        /**
         * Clean up timed out handshakes
         */
        void cleanup();

        /**
         * Get number of active handshakes
         * @return Active handshake count
         */
        size_t getActiveCount() const;

        /**
         * Get global statistics
         * @return Global handshake statistics
         */
        const HandshakeStats& getGlobalStats() const { return globalStats; }

        /**
         * Reset global statistics
         */
        void resetGlobalStats();
    };

    /**
     * Handshake builder for creating handshake configurations
     */
    class HandshakeBuilder {
    private:
        HandshakeConfig config;

    public:
        HandshakeBuilder();

        HandshakeBuilder& withProtocolVersion(uint32_t version);
        HandshakeBuilder& withServices(uint64_t services);
        HandshakeBuilder& withUserAgent(const std::string& userAgent);
        HandshakeBuilder& withHeight(uint32_t height);
        HandshakeBuilder& withPort(uint16_t port);
        HandshakeBuilder& withHandshakeTimeout(std::chrono::milliseconds timeout);
        HandshakeBuilder& withPingTimeout(std::chrono::milliseconds timeout);
        HandshakeBuilder& withRequireVerack(bool require);
        HandshakeBuilder& withRequireWitness(bool require);
        HandshakeBuilder& withRequireBloom(bool require);
        HandshakeBuilder& withSendPing(bool send);

        HandshakeConfig build() const;
    };

    /**
     * Handshake validator for checking handshake results
     */
    class HandshakeValidator {
    public:
        /**
         * Validate handshake result
         * @param result Handshake result
         * @param expectedConfig Expected configuration
         * @return true if valid
         */
        static bool validate(const HandshakeResult& result,
                            const HandshakeConfig& expectedConfig);

        /**
         * Validate peer version
         * @param version Peer version
         * @param minVersion Minimum required version
         * @return true if version is acceptable
         */
        static bool validateVersion(uint32_t version, uint32_t minVersion);

        /**
         * Validate peer services
         * @param services Peer services
         * @param requiredServices Required services mask
         * @return true if all required services are present
         */
        static bool validateServices(uint64_t services, uint64_t requiredServices);

        /**
         * Validate peer user agent
         * @param userAgent Peer user agent
         * @return true if user agent is acceptable
         */
        static bool validateUserAgent(const std::string& userAgent);

        /**
         * Validate peer height
         * @param height Peer height
         * @param maxHeight Maximum acceptable height
         * @return true if height is acceptable
         */
        static bool validateHeight(uint32_t height, uint32_t maxHeight);
    };

} // namespace powercoin

#endif // POWERCOIN_HANDSHAKE_H