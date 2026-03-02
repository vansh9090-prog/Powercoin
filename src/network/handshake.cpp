#include "handshake.h"
#include "../crypto/random.h"
#include <sstream>
#include <iomanip>

namespace powercoin {

    // ============== HandshakeResult Implementation ==============

    HandshakeResult::HandshakeResult()
        : success(false),
          finalState(HandshakeState::INIT),
          peerVersion(0),
          peerServices(0),
          peerHeight(0),
          pingTime(0),
          duration(0) {}

    std::string HandshakeResult::toString() const {
        std::stringstream ss;
        ss << "HandshakeResult:\n";
        ss << "  Success: " << (success ? "yes" : "no") << "\n";
        ss << "  State: " << Handshake::stateToString(finalState) << "\n";
        if (!errorMessage.empty()) {
            ss << "  Error: " << errorMessage << "\n";
        }
        ss << "  Peer Version: " << peerVersion << "\n";
        ss << "  Peer Services: " << peerServices << "\n";
        ss << "  Peer User Agent: " << peerUserAgent << "\n";
        ss << "  Peer Height: " << peerHeight << "\n";
        ss << "  Ping Time: " << pingTime << " ms\n";
        ss << "  Duration: " << duration.count() << " ms\n";
        return ss.str();
    }

    // ============== HandshakeConfig Implementation ==============

    HandshakeConfig::HandshakeConfig()
        : protocolVersion(70015),
          localServices(SERVICE_NODE_NETWORK | SERVICE_NODE_WITNESS),
          localUserAgent("/PowerCoin:1.0.0/"),
          localHeight(0),
          localPort(8333),
          handshakeTimeout(30000), // 30 seconds
          pingTimeout(5000),       // 5 seconds
          requireVerack(true),
          requireWitness(true),
          requireBloom(false),
          sendPingAfterHandshake(true) {}

    // ============== HandshakeStats Implementation ==============

    HandshakeStats::HandshakeStats()
        : totalHandshakes(0),
          successfulHandshakes(0),
          failedHandshakes(0),
          timeouts(0),
          averageDuration(0),
          minDuration(0),
          maxDuration(0) {}

    void HandshakeStats::update(const HandshakeResult& result) {
        totalHandshakes++;
        stateCounts[result.finalState]++;

        if (result.success) {
            successfulHandshakes++;
        } else {
            failedHandshakes++;
            if (result.finalState == HandshakeState::TIMEOUT) {
                timeouts++;
            }
        }

        auto duration = result.duration;
        if (averageDuration.count() == 0) {
            averageDuration = duration;
            minDuration = duration;
            maxDuration = duration;
        } else {
            averageDuration = (averageDuration * (totalHandshakes - 1) + duration) / totalHandshakes;
            if (duration < minDuration) minDuration = duration;
            if (duration > maxDuration) maxDuration = duration;
        }
    }

    void HandshakeStats::reset() {
        totalHandshakes = 0;
        successfulHandshakes = 0;
        failedHandshakes = 0;
        timeouts = 0;
        averageDuration = std::chrono::milliseconds(0);
        minDuration = std::chrono::milliseconds(0);
        maxDuration = std::chrono::milliseconds(0);
        stateCounts.clear();
    }

    // ============== Handshake Implementation ==============

    Handshake::Handshake(const HandshakeConfig& cfg) 
        : state(HandshakeState::INIT), config(cfg), localNonce(0), remoteNonce(0) {
        reset();
    }

    Handshake::~Handshake() = default;

    void Handshake::reset() {
        state = HandshakeState::INIT;
        localNonce = Random::getUint64();
        remoteNonce = 0;
        startTime = std::chrono::steady_clock::now();
        lastActivity = startTime;

        // Initialize local version message
        localVersion.version = config.protocolVersion;
        localVersion.services = config.localServices;
        localVersion.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        localVersion.addrRecvServices = 0;
        localVersion.addrRecvIp = "::";
        localVersion.addrRecvPort = 0;
        localVersion.addrFromServices = config.localServices;
        localVersion.addrFromIp = "::1";
        localVersion.addrFromPort = config.localPort;
        localVersion.nonce = localNonce;
        localVersion.userAgent = config.localUserAgent;
        localVersion.startHeight = config.localHeight;
        localVersion.relay = true;
    }

    VersionMessage Handshake::start() {
        transitionTo(HandshakeState::SENT_VERSION, "Starting handshake");
        return localVersion;
    }

    bool Handshake::validateVersion(const VersionMessage& version) const {
        // Check minimum protocol version
        if (version.version < 70001) {
            return false;
        }

        // Check nonce is not zero
        if (version.nonce == 0) {
            return false;
        }

        // Check nonce is not our own
        if (version.nonce == localNonce) {
            return false;
        }

        // Check user agent is valid
        if (version.userAgent.empty() || version.userAgent.length() > 256) {
            return false;
        }

        // Check timestamp is reasonable (within 2 hours)
        auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        if (std::abs(version.timestamp - now) > 7200) {
            return false;
        }

        return true;
    }

    bool Handshake::validateNonce(uint64_t nonce) const {
        return nonce != 0 && nonce != localNonce;
    }

    std::unique_ptr<NetworkMessage> Handshake::processMessage(const NetworkMessage& message) {
        lastActivity = std::chrono::steady_clock::now();

        // Handle version message
        if (message.getCommand() == MSG_VERSION && 
            (state == HandshakeState::INIT || state == HandshakeState::SENT_VERSION)) {
            
            auto versionMsg = dynamic_cast<const VersionMessage*>(&message);
            if (!versionMsg) {
                setError("Invalid version message");
                return nullptr;
            }

            remoteVersion = *versionMsg;

            if (!validateVersion(remoteVersion)) {
                setError("Invalid version data");
                return nullptr;
            }

            remoteNonce = remoteVersion.nonce;

            // Send verack if we haven't already
            if (state == HandshakeState::INIT) {
                transitionTo(HandshakeState::RECEIVED_VERSION, "Received version");
                
                // Send our version first
                VersionMessage ourVersion = localVersion;
                // But also schedule verack
                auto verack = std::make_unique<VerackMessage>();
                return std::make_unique<VerackMessage>(*verack);
            } else {
                transitionTo(HandshakeState::RECEIVED_VERSION, "Received version");
                
                // Send verack
                auto verack = std::make_unique<VerackMessage>();
                return std::make_unique<VerackMessage>(*verack);
            }
        }

        // Handle verack message
        if (message.getCommand() == MSG_VERACK) {
            if (state == HandshakeState::SENT_VERSION) {
                transitionTo(HandshakeState::RECEIVED_VERACK, "Received verack");
                
                // If we've also received version, handshake is complete
                if (remoteNonce != 0) {
                    transitionTo(HandshakeState::COMPLETE, "Handshake complete");
                }
            } else if (state == HandshakeState::RECEIVED_VERSION) {
                transitionTo(HandshakeState::COMPLETE, "Handshake complete");
            } else {
                setError("Unexpected verack");
            }
        }

        return nullptr;
    }

    std::unique_ptr<NetworkMessage> Handshake::processData(const std::vector<uint8_t>& data) {
        auto msg = MessageFactory::createMessage(data);
        if (!msg) {
            setError("Failed to parse message");
            return nullptr;
        }
        return processMessage(*msg);
    }

    void Handshake::transitionTo(HandshakeState newState, const std::string& reason) {
        HandshakeState oldState = state;
        state = newState;

        if (onStateChange) {
            onStateChange(newState, reason);
        }

        if (newState == HandshakeState::COMPLETE) {
            if (onComplete) {
                onComplete(getResult());
            }
        } else if (newState == HandshakeState::FAILED) {
            if (onError) {
                onError(reason);
            }
        }
    }

    void Handshake::setError(const std::string& message) {
        transitionTo(HandshakeState::FAILED, message);
    }

    HandshakeResult Handshake::getResult() const {
        HandshakeResult result;
        result.success = (state == HandshakeState::COMPLETE);
        result.finalState = state;
        result.errorMessage = (state == HandshakeState::FAILED) ? "Handshake failed" : "";

        if (remoteVersion.version > 0) {
            result.peerVersion = remoteVersion.version;
            result.peerServices = remoteVersion.services;
            result.peerUserAgent = remoteVersion.userAgent;
            result.peerHeight = remoteVersion.startHeight;
        }

        result.pingTime = 0; // Will be set by ping/pong
        result.duration = getDuration();

        return result;
    }

    bool Handshake::hasTimedOut() const {
        if (state == HandshakeState::COMPLETE || state == HandshakeState::FAILED) {
            return false;
        }

        auto now = std::chrono::steady_clock::now();
        return (now - startTime) > config.handshakeTimeout;
    }

    std::chrono::milliseconds Handshake::getIdleTime() const {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now - lastActivity);
    }

    std::chrono::milliseconds Handshake::getDuration() const {
        auto now = std::chrono::steady_clock::now();
        return std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime);
    }

    void Handshake::resetStats() {
        stats.reset();
    }

    void Handshake::setOnStateChange(std::function<void(HandshakeState, const std::string&)> callback) {
        onStateChange = callback;
    }

    void Handshake::setOnComplete(std::function<void(const HandshakeResult&)> callback) {
        onComplete = callback;
    }

    void Handshake::setOnError(std::function<void(const std::string&)> callback) {
        onError = callback;
    }

    std::string Handshake::stateToString(HandshakeState state) {
        switch (state) {
            case HandshakeState::INIT: return "INIT";
            case HandshakeState::SENT_VERSION: return "SENT_VERSION";
            case HandshakeState::SENT_VERACK: return "SENT_VERACK";
            case HandshakeState::RECEIVED_VERSION: return "RECEIVED_VERSION";
            case HandshakeState::RECEIVED_VERACK: return "RECEIVED_VERACK";
            case HandshakeState::COMPLETE: return "COMPLETE";
            case HandshakeState::FAILED: return "FAILED";
            case HandshakeState::TIMEOUT: return "TIMEOUT";
            default: return "UNKNOWN";
        }
    }

    // ============== HandshakeManager Implementation ==============

    HandshakeManager::HandshakeManager(const HandshakeConfig& config) 
        : defaultConfig(config) {}

    HandshakeManager::~HandshakeManager() = default;

    VersionMessage HandshakeManager::startHandshake(const std::string& peerId) {
        std::lock_guard<std::mutex> lock(mutex);

        auto handshake = std::make_unique<Handshake>(defaultConfig);
        auto version = handshake->start();

        auto peerHandshake = std::make_unique<PeerHandshake>();
        peerHandshake->peerId = peerId;
        peerHandshake->handshake = std::move(handshake);
        peerHandshake->startTime = std::chrono::steady_clock::now();

        handshakes[peerId] = std::move(peerHandshake);

        return version;
    }

    std::unique_ptr<NetworkMessage> HandshakeManager::processMessage(const std::string& peerId,
                                                                      const NetworkMessage& message) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = handshakes.find(peerId);
        if (it == handshakes.end()) {
            return nullptr;
        }

        auto response = it->second->handshake->processMessage(message);

        // Update statistics if handshake completed
        if (it->second->handshake->isComplete() || it->second->handshake->hasFailed()) {
            globalStats.update(it->second->handshake->getResult());
        }

        return response;
    }

    std::unique_ptr<NetworkMessage> HandshakeManager::processData(const std::string& peerId,
                                                                   const std::vector<uint8_t>& data) {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = handshakes.find(peerId);
        if (it == handshakes.end()) {
            return nullptr;
        }

        auto response = it->second->handshake->processData(data);

        // Update statistics if handshake completed
        if (it->second->handshake->isComplete() || it->second->handshake->hasFailed()) {
            globalStats.update(it->second->handshake->getResult());
        }

        return response;
    }

    bool HandshakeManager::isHandshakeComplete(const std::string& peerId) const {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = handshakes.find(peerId);
        if (it == handshakes.end()) {
            return false;
        }

        return it->second->handshake->isComplete();
    }

    HandshakeResult HandshakeManager::getHandshakeResult(const std::string& peerId) const {
        std::lock_guard<std::mutex> lock(mutex);

        auto it = handshakes.find(peerId);
        if (it == handshakes.end()) {
            return HandshakeResult();
        }

        return it->second->handshake->getResult();
    }

    void HandshakeManager::removeHandshake(const std::string& peerId) {
        std::lock_guard<std::mutex> lock(mutex);
        handshakes.erase(peerId);
    }

    void HandshakeManager::cleanup() {
        std::lock_guard<std::mutex> lock(mutex);

        auto now = std::chrono::steady_clock::now();
        for (auto it = handshakes.begin(); it != handshakes.end();) {
            if (it->second->handshake->hasTimedOut()) {
                // Update statistics for timeout
                HandshakeResult result;
                result.success = false;
                result.finalState = HandshakeState::TIMEOUT;
                result.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
                    now - it->second->startTime);
                globalStats.update(result);

                it = handshakes.erase(it);
            } else {
                ++it;
            }
        }
    }

    size_t HandshakeManager::getActiveCount() const {
        std::lock_guard<std::mutex> lock(mutex);
        return handshakes.size();
    }

    void HandshakeManager::resetGlobalStats() {
        std::lock_guard<std::mutex> lock(mutex);
        globalStats.reset();
    }

    // ============== HandshakeBuilder Implementation ==============

    HandshakeBuilder::HandshakeBuilder() {
        config = HandshakeConfig();
    }

    HandshakeBuilder& HandshakeBuilder::withProtocolVersion(uint32_t version) {
        config.protocolVersion = version;
        return *this;
    }

    HandshakeBuilder& HandshakeBuilder::withServices(uint64_t services) {
        config.localServices = services;
        return *this;
    }

    HandshakeBuilder& HandshakeBuilder::withUserAgent(const std::string& userAgent) {
        config.localUserAgent = userAgent;
        return *this;
    }

    HandshakeBuilder& HandshakeBuilder::withHeight(uint32_t height) {
        config.localHeight = height;
        return *this;
    }

    HandshakeBuilder& HandshakeBuilder::withPort(uint16_t port) {
        config.localPort = port;
        return *this;
    }

    HandshakeBuilder& HandshakeBuilder::withHandshakeTimeout(std::chrono::milliseconds timeout) {
        config.handshakeTimeout = timeout;
        return *this;
    }

    HandshakeBuilder& HandshakeBuilder::withPingTimeout(std::chrono::milliseconds timeout) {
        config.pingTimeout = timeout;
        return *this;
    }

    HandshakeBuilder& HandshakeBuilder::withRequireVerack(bool require) {
        config.requireVerack = require;
        return *this;
    }

    HandshakeBuilder& HandshakeBuilder::withRequireWitness(bool require) {
        config.requireWitness = require;
        return *this;
    }

    HandshakeBuilder& HandshakeBuilder::withRequireBloom(bool require) {
        config.requireBloom = require;
        return *this;
    }

    HandshakeBuilder& HandshakeBuilder::withSendPing(bool send) {
        config.sendPingAfterHandshake = send;
        return *this;
    }

    HandshakeConfig HandshakeBuilder::build() const {
        return config;
    }

    // ============== HandshakeValidator Implementation ==============

    bool HandshakeValidator::validate(const HandshakeResult& result,
                                      const HandshakeConfig& expectedConfig) {
        if (!result.success) {
            return false;
        }

        if (!validateVersion(result.peerVersion, expectedConfig.protocolVersion)) {
            return false;
        }

        if (!validateServices(result.peerServices, expectedConfig.localServices)) {
            return false;
        }

        if (!validateUserAgent(result.peerUserAgent)) {
            return false;
        }

        return true;
    }

    bool HandshakeValidator::validateVersion(uint32_t version, uint32_t minVersion) {
        return version >= minVersion;
    }

    bool HandshakeValidator::validateServices(uint64_t services, uint64_t requiredServices) {
        return (services & requiredServices) == requiredServices;
    }

    bool HandshakeValidator::validateUserAgent(const std::string& userAgent) {
        // Basic validation - not empty and reasonable length
        if (userAgent.empty() || userAgent.length() > 256) {
            return false;
        }

        // Check for valid characters
        for (char c : userAgent) {
            if (c < 32 || c > 126) {
                return false;
            }
        }

        return true;
    }

    bool HandshakeValidator::validateHeight(uint32_t height, uint32_t maxHeight) {
        return height <= maxHeight + 1000; // Allow some drift
    }

} // namespace powercoin