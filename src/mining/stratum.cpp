#include "stratum.h"
#include "../crypto/sha256.h"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

using json = nlohmann::json;

namespace powercoin {

    // ============== StratumJob Implementation ==============

    StratumJob::StratumJob()
        : height(0), difficulty(0), target(0), cleanJobs(false) {}

    std::string StratumJob::toString() const {
        std::stringstream ss;
        ss << "Stratum Job:\n";
        ss << "  Job ID: " << jobId << "\n";
        ss << "  Height: " << height << "\n";
        ss << "  Difficulty: " << difficulty << "\n";
        ss << "  PrevHash: " << prevHash.substr(0, 16) << "...\n";
        ss << "  Merkle Branches: " << merkleBranches.size() << "\n";
        ss << "  Clean Jobs: " << (cleanJobs ? "yes" : "no") << "\n";
        return ss.str();
    }

    bool StratumJob::isValid() const {
        return !jobId.empty() && !prevHash.empty() && difficulty > 0;
    }

    // ============== StratumShare Implementation ==============

    StratumShare::StratumShare()
        : difficulty(0), isBlock(false), timestamp(0) {}

    std::string StratumShare::toString() const {
        std::stringstream ss;
        ss << "Stratum Share:\n";
        ss << "  Job ID: " << jobId << "\n";
        ss << "  Nonce: " << nonce << "\n";
        ss << "  Hash: " << hash.substr(0, 16) << "...\n";
        ss << "  Difficulty: " << difficulty << "\n";
        ss << "  Is Block: " << (isBlock ? "yes" : "no") << "\n";
        return ss.str();
    }

    // ============== StratumConfig Implementation ==============

    StratumConfig::StratumConfig()
        : port(3333), useSSL(false), reconnectDelay(5), timeout(30),
          maxRetries(3), subscribeExtranonce(true), version("1.0") {}

    // ============== StratumStats Implementation ==============

    StratumStats::StratumStats()
        : state(StratumState::DISCONNECTED), uptime(0), jobsReceived(0),
          sharesSubmitted(0), sharesAccepted(0), sharesRejected(0),
          blocksFound(0), averageLatency(0), lastDifficulty(0),
          reconnectCount(0) {}

    std::string StratumStats::toString() const {
        std::stringstream ss;
        ss << "Stratum Statistics:\n";
        ss << "  State: " << static_cast<int>(state) << "\n";
        ss << "  Uptime: " << uptime << " seconds\n";
        ss << "  Jobs Received: " << jobsReceived << "\n";
        ss << "  Shares Submitted: " << sharesSubmitted << "\n";
        ss << "  Shares Accepted: " << sharesAccepted << "\n";
        ss << "  Shares Rejected: " << sharesRejected << "\n";
        ss << "  Blocks Found: " << blocksFound << "\n";
        ss << "  Avg Latency: " << averageLatency << " ms\n";
        ss << "  Last Difficulty: " << lastDifficulty << "\n";
        if (!lastError.empty()) {
            ss << "  Last Error: " << lastError << "\n";
        }
        return ss.str();
    }

    // ============== StratumClient Implementation ==============

    StratumClient::StratumClient(const StratumConfig& cfg)
        : config(cfg), state(StratumState::DISCONNECTED), running(false),
          extranonce1(0), extranonce2Size(0), nonceCounter(0) {
        workerName = config.workerName.empty() ? config.username : config.workerName;
    }

    StratumClient::~StratumClient() {
        disconnect();
    }

    bool StratumClient::connect() {
        if (state != StratumState::DISCONNECTED) {
            return false;
        }

        state = StratumState::CONNECTING;
        running = true;

        // Initialize WebSocket client
        wsClient = std::make_unique<WebsocketClient>();

        try {
            wsClient->init_asio();
            wsClient->set_tls_init_handler([](websocketpp::connection_hdl) {
                return websocketpp::lib::make_shared<boost::asio::ssl::context>(
                    boost::asio::ssl::context::tlsv12);
            });

            wsClient->set_open_handler([this](websocketpp::connection_hdl hdl) {
                connection = hdl;
                state = StratumState::CONNECTED;
                
                // Subscribe to jobs
                sendSubscribe();
                
                if (onConnected) {
                    onConnected();
                }
            });

            wsClient->set_close_handler([this](websocketpp::connection_hdl) {
                state = StratumState::DISCONNECTED;
                if (onDisconnected) {
                    onDisconnected();
                }
                
                if (running) {
                    reconnect();
                }
            });

            wsClient->set_message_handler([this](websocketpp::connection_hdl,
                                                WebsocketClient::message_ptr msg) {
                handleMessage(msg->get_payload());
            });

            wsClient->set_fail_handler([this](websocketpp::connection_hdl) {
                state = StratumState::ERROR;
                stats.lastError = "Connection failed";
                
                if (running) {
                    reconnect();
                }
            });

            // Create connection
            std::string uri = (config.useSSL ? "wss://" : "ws://") +
                              config.host + ":" + std::to_string(config.port);
            
            websocketpp::lib::error_code ec;
            auto con = wsClient->get_connection(uri, ec);
            
            if (ec) {
                stats.lastError = ec.message();
                state = StratumState::ERROR;
                return false;
            }

            wsClient->connect(con);

            // Start network thread
            networkThread = std::thread([this]() {
                wsClient->run();
            });

        } catch (const std::exception& e) {
            stats.lastError = e.what();
            state = StratumState::ERROR;
            return false;
        }

        return true;
    }

    void StratumClient::disconnect() {
        running = false;
        
        if (wsClient && connection.lock()) {
            websocketpp::lib::error_code ec;
            wsClient->close(connection, websocketpp::close::status::going_away, "", ec);
        }

        if (networkThread.joinable()) {
            networkThread.join();
        }

        wsClient.reset();
        state = StratumState::DISCONNECTED;
    }

    void StratumClient::reconnect() {
        if (!running) return;

        stats.reconnectCount++;
        std::this_thread::sleep_for(std::chrono::seconds(config.reconnectDelay));
        
        state = StratumState::RECONNECTING;
        disconnect();
        connect();
    }

    bool StratumClient::isConnected() const {
        return state == StratumState::CONNECTED ||
               state == StratumState::SUBSCRIBED ||
               state == StratumState::AUTHORIZED ||
               state == StratumState::MINING;
    }

    StratumStats StratumClient::getStats() const {
        std::lock_guard<std::mutex> lock(mutex);
        return stats;
    }

    StratumJob StratumClient::getCurrentJob() const {
        std::lock_guard<std::mutex> lock(jobMutex);
        return currentJob;
    }

    void StratumClient::sendMessage(const json& message) {
        if (!isConnected() || !wsClient || !connection.lock()) {
            return;
        }

        try {
            std::string msg = message.dump();
            websocketpp::lib::error_code ec;
            wsClient->send(connection, msg, websocketpp::frame::opcode::text, ec);
            
            if (ec) {
                stats.lastError = ec.message();
            }
        } catch (const std::exception& e) {
            stats.lastError = e.what();
        }
    }

    void StratumClient::handleMessage(const std::string& payload) {
        try {
            auto json = json::parse(payload);
            
            if (config.protocol == StratumProtocol::STRATUM_V1 ||
                config.protocol == StratumProtocol::STRATUM_V1_EXT) {
                handleStratumV1(json);
            } else if (config.protocol == StratumProtocol::STRATUM_V2) {
                handleStratumV2(json);
            }
        } catch (const std::exception& e) {
            stats.lastError = std::string("JSON parse error: ") + e.what();
        }
    }

    void StratumClient::handleStratumV1(const json& message) {
        // Handle response to previous request
        if (message.contains("id") && message["id"].is_number()) {
            bool accepted = false;
            std::string error;
            
            if (message.contains("error") && !message["error"].is_null()) {
                error = message["error"].dump();
            } else if (message.contains("result") && !message["result"].is_null()) {
                accepted = true;
            }

            // Check if it's a share submission response
            if (message["id"] == 3) { // Submit share
                stats.sharesSubmitted++;
                
                if (accepted) {
                    stats.sharesAccepted++;
                    if (onShareAccepted) {
                        // We need the original share
                    }
                } else {
                    stats.sharesRejected++;
                    if (onShareRejected) {
                        // We need the original share
                    }
                }
            }
        }

        // Handle notification (method)
        if (message.contains("method") && message["method"].is_string()) {
            std::string method = message["method"];
            
            if (method == "mining.notify") {
                // New job
                parseJob(message["params"]);
                
            } else if (method == "mining.set_difficulty") {
                // Difficulty change
                if (message["params"].is_array() && message["params"].size() > 0) {
                    currentJob.difficulty = message["params"][0];
                    stats.lastDifficulty = currentJob.difficulty;
                }
                
            } else if (method == "mining.set_extranonce") {
                // Extranonce change
                if (message["params"].is_array() && message["params"].size() >= 2) {
                    extranonce1 = message["params"][0];
                    extranonce2Size = message["params"][1];
                }
            }
        }
    }

    void StratumClient::handleStratumV2(const json& message) {
        // Stratum V2 handling (simplified)
        // Would implement proper V2 protocol
    }

    void StratumClient::sendSubscribe() {
        json subscribe;
        subscribe["id"] = 1;
        subscribe["method"] = "mining.subscribe";
        subscribe["params"] = {config.version, "PowerCoin"};

        sendMessage(subscribe);
        state = StratumState::SUBSCRIBED;
    }

    void StratumClient::sendAuthorize() {
        json authorize;
        authorize["id"] = 2;
        authorize["method"] = "mining.authorize";
        authorize["params"] = {config.username, config.password};

        sendMessage(authorize);
        state = StratumState::AUTHORIZED;
    }

    void StratumClient::sendSubmit(const StratumShare& share) {
        json submit;
        submit["id"] = 3;
        submit["method"] = "mining.submit";
        submit["params"] = {workerName, share.jobId, share.nonce, share.ntime};

        sendMessage(submit);
    }

    void StratumClient::parseJob(const json& params) {
        if (!params.is_array() || params.size() < 8) {
            return;
        }

        StratumJob job;
        job.jobId = params[0];
        job.prevHash = params[1];
        job.coinbase1 = params[2];
        job.coinbase2 = params[3];
        
        if (params[4].is_array()) {
            for (const auto& branch : params[4]) {
                job.merkleBranches.push_back(branch);
            }
        }
        
        job.version = params[5];
        job.nbits = params[6];
        job.ntime = params[7];
        job.cleanJobs = params.size() > 8 ? params[8] : false;

        jobs[job.jobId] = job;
        currentJob = job;
        stats.jobsReceived++;

        if (onJobReceived) {
            onJobReceived(job);
        }
    }

    std::string StratumClient::generateNonce() {
        nonceCounter++;
        std::stringstream ss;
        ss << std::hex << std::setw(8) << std::setfill('0') << nonceCounter;
        return ss.str();
    }

    bool StratumClient::validateShare(const StratumShare& share) {
        auto it = jobs.find(share.jobId);
        if (it == jobs.end()) {
            return false;
        }

        const auto& job = it->second;
        
        // Build coinbase and calculate hash
        std::string coinbase = job.coinbase1 + share.nonce + job.coinbase2;
        std::string coinbaseHash = SHA256::doubleHash(coinbase);
        
        // Build merkle root
        std::string merkleRoot = coinbaseHash;
        for (const auto& branch : job.merkleBranches) {
            merkleRoot = SHA256::doubleHash(merkleRoot + branch);
        }
        
        // Build block header
        std::stringstream header;
        header << job.version
               << job.prevHash
               << merkleRoot
               << job.ntime
               << job.nbits
               << share.nonce;
        
        std::string blockHash = SHA256::doubleHash(header.str());
        
        // Check difficulty
        return StratumShareValidator::checkDifficulty(blockHash, job.difficulty);
    }

    bool StratumClient::submitShare(const StratumShare& share) {
        if (!isConnected()) {
            return false;
        }

        if (!validateShare(share)) {
            return false;
        }

        sendSubmit(share);
        return true;
    }

    bool StratumClient::submitBlock(const std::string& block) {
        if (!isConnected()) {
            return false;
        }

        json submit;
        submit["id"] = 4;
        submit["method"] = "mining.submit";
        submit["params"] = {workerName, block};

        sendMessage(submit);
        return true;
    }

    void StratumClient::setWorkerName(const std::string& name) {
        workerName = name;
    }

    void StratumClient::setOnJobReceived(std::function<void(const StratumJob&)> callback) {
        onJobReceived = callback;
    }

    void StratumClient::setOnShareAccepted(std::function<void(const StratumShare&)> callback) {
        onShareAccepted = callback;
    }

    void StratumClient::setOnShareRejected(std::function<void(const StratumShare&, const std::string&)> callback) {
        onShareRejected = callback;
    }

    void StratumClient::setOnStatsUpdate(std::function<void(const StratumStats&)> callback) {
        onStatsUpdate = callback;
    }

    void StratumClient::setOnError(std::function<void(const std::string&)> callback) {
        onError = callback;
    }

    void StratumClient::setOnConnected(std::function<void()> callback) {
        onConnected = callback;
    }

    void StratumClient::setOnDisconnected(std::function<void()> callback) {
        onDisconnected = callback;
    }

    // ============== StratumJobBuilder Implementation ==============

    StratumJob StratumJobBuilder::fromV1(const json& params) {
        StratumJob job;
        
        if (params.is_array() && params.size() >= 8) {
            job.jobId = params[0];
            job.prevHash = params[1];
            job.coinbase1 = params[2];
            job.coinbase2 = params[3];
            
            if (params[4].is_array()) {
                for (const auto& branch : params[4]) {
                    job.merkleBranches.push_back(branch);
                }
            }
            
            job.version = params[5];
            job.nbits = params[6];
            job.ntime = params[7];
            job.cleanJobs = params.size() > 8 ? params[8] : false;
        }
        
        return job;
    }

    StratumJob StratumJobBuilder::fromV2(const json& params) {
        StratumJob job;
        // Stratum V2 parsing would go here
        return job;
    }

    std::string StratumJobBuilder::buildCoinbase(const StratumJob& job, 
                                                   const std::string& coinbaseExtra) {
        return job.coinbase1 + coinbaseExtra + job.coinbase2;
    }

    std::string StratumJobBuilder::buildMerkleRoot(const StratumJob& job,
                                                     const std::string& coinbaseHash) {
        std::string merkleRoot = coinbaseHash;
        for (const auto& branch : job.merkleBranches) {
            merkleRoot = SHA256::doubleHash(merkleRoot + branch);
        }
        return merkleRoot;
    }

    // ============== StratumShareValidator Implementation ==============

    bool StratumShareValidator::validate(const StratumShare& share, const StratumJob& job) {
        // Build coinbase and calculate hash
        std::string coinbase = job.coinbase1 + share.nonce + job.coinbase2;
        std::string coinbaseHash = SHA256::doubleHash(coinbase);
        
        // Build merkle root
        std::string merkleRoot = coinbaseHash;
        for (const auto& branch : job.merkleBranches) {
            merkleRoot = SHA256::doubleHash(merkleRoot + branch);
        }
        
        // Build block header
        std::stringstream header;
        header << job.version
               << job.prevHash
               << merkleRoot
               << share.ntime
               << job.nbits
               << share.nonce;
        
        std::string blockHash = SHA256::doubleHash(header.str());
        
        // Check difficulty
        return checkDifficulty(blockHash, job.difficulty);
    }

    bool StratumShareValidator::checkDifficulty(const std::string& hash, uint32_t difficulty) {
        std::string target(difficulty >> 24, '0');
        return hash.substr(0, difficulty >> 24) == target;
    }

    uint32_t StratumShareValidator::getShareDifficulty(const std::string& hash) {
        uint32_t leadingZeros = 0;
        for (char c : hash) {
            if (c == '0') leadingZeros++;
            else break;
        }
        return leadingZeros << 24;
    }

    // ============== StratumProtocolHandler Implementation ==============

    json StratumProtocolHandler::createSubscribe(StratumProtocol protocol) {
        json msg;
        msg["id"] = 1;
        msg["method"] = "mining.subscribe";
        msg["params"] = {"PowerCoin/1.0", "PowerCoin"};
        return msg;
    }

    json StratumProtocolHandler::createAuthorize(const std::string& username,
                                                   const std::string& password) {
        json msg;
        msg["id"] = 2;
        msg["method"] = "mining.authorize";
        msg["params"] = {username, password};
        return msg;
    }

    json StratumProtocolHandler::createSubmit(const StratumShare& share) {
        json msg;
        msg["id"] = 3;
        msg["method"] = "mining.submit";
        msg["params"] = {share.worker, share.jobId, share.nonce, share.ntime};
        return msg;
    }

    json StratumProtocolHandler::createExtranonceSubscribe() {
        json msg;
        msg["id"] = 4;
        msg["method"] = "mining.extranonce.subscribe";
        msg["params"] = json::array();
        return msg;
    }

    json StratumProtocolHandler::createConfigure(const std::map<std::string, bool>& extensions) {
        json msg;
        msg["id"] = 5;
        msg["method"] = "mining.configure";
        
        json params = json::array();
        for (const auto& [ext, enabled] : extensions) {
            params.push_back({{ext, enabled}});
        }
        msg["params"] = params;
        
        return msg;
    }

    bool StratumProtocolHandler::parseResponse(const json& response, std::string& error) {
        if (response.contains("error") && !response["error"].is_null()) {
            error = response["error"].dump();
            return false;
        }
        return true;
    }

    bool StratumProtocolHandler::parseJob(const json& message, StratumJob& job) {
        if (!message.contains("params") || !message["params"].is_array()) {
            return false;
        }
        
        job = StratumJobBuilder::fromV1(message["params"]);
        return job.isValid();
    }

    bool StratumProtocolHandler::parseShare(const json& response, bool& accepted, std::string& error) {
        accepted = response.contains("result") && !response["result"].is_null();
        
        if (!accepted && response.contains("error") && !response["error"].is_null()) {
            error = response["error"].dump();
        }
        
        return true;
    }

} // namespace powercoin