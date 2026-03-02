#include "config.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <getopt.h>
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>

namespace powercoin {

    // Global config instance
    Config gConfig;

    Config::Config() 
        : network("mainnet"),
          magic(NetworkConfig::MAGIC_MAINNET),
          port(NetworkConfig::DEFAULT_PORT_MAINNET),
          daemonMode(false),
          verbosity(1),
          testnet(false),
          regtest(false),
          rpcBind(RPCConfig::RPC_BIND),
          rpcPort(RPCConfig::RPC_PORT),
          rpcUser(RPCConfig::RPC_USER),
          rpcPassword(""),
          rpcEnabled(true),
          enableSmartContracts(AdvancedConfig::ENABLE_SMART_CONTRACTS),
          enablePrivacy(AdvancedConfig::ENABLE_PRIVACY),
          enableGovernance(AdvancedConfig::ENABLE_GOVERNANCE),
          enableCrossChain(AdvancedConfig::ENABLE_CROSS_CHAIN),
          enableLightning(AdvancedConfig::ENABLE_LIGHTNING),
          enableMasternodes(AdvancedConfig::ENABLE_MASTERNODES),
          enableMining(false),
          miningThreads(MiningConfig::NUM_CPU_THREADS),
          walletFile(WalletConfig::DEFAULT_WALLET_FILE),
          walletUnlocked(false),
          maxConnections(125),
          maxUploadTarget(0),
          initialized(false) {
        
        setDefaults();
    }

    void Config::setDefaults() {
        // Set default paths
        dataDir = getDefaultDataDir();
        configFile = dataDir + "/" + PathConfig::CONFIG_FILE;
        pidFile = dataDir + "/" + PathConfig::PID_FILE;
        
        // Set seed nodes
        seedNodes.clear();
        for (const auto& seed : NetworkConfig::SEED_NODES_MAINNET) {
            seedNodes.push_back(seed);
        }
    }

    bool Config::load(int argc, char** argv) {
        if (!parseCommandLine(argc, argv)) {
            return false;
        }
        
        // Create data directory if it doesn't exist
        struct stat st;
        if (stat(dataDir.c_str(), &st) != 0) {
            if (mkdir(dataDir.c_str(), 0700) != 0) {
                std::cerr << "Failed to create data directory: " << dataDir << std::endl;
                return false;
            }
        }
        
        // Parse config file if it exists
        if (stat(configFile.c_str(), &st) == 0) {
            if (!parseConfigFile(configFile)) {
                std::cerr << "Failed to parse config file: " << configFile << std::endl;
                return false;
            }
        }
        
        updateFromNetwork();
        initialized = true;
        
        return true;
    }

    bool Config::parseCommandLine(int argc, char** argv) {
        static struct option long_options[] = {
            {"network", required_argument, 0, 'n'},
            {"datadir", required_argument, 0, 'd'},
            {"config", required_argument, 0, 'c'},
            {"daemon", no_argument, 0, 'D'},
            {"verbose", no_argument, 0, 'v'},
            {"quiet", no_argument, 0, 'q'},
            {"testnet", no_argument, 0, 't'},
            {"regtest", no_argument, 0, 'r'},
            {"rpccreds", required_argument, 0, 'u'},
            {"rpcbind", required_argument, 0, 'b'},
            {"rpcport", required_argument, 0, 'p'},
            {"mine", no_argument, 0, 'm'},
            {"miningaddr", required_argument, 0, 'a'},
            {"help", no_argument, 0, 'h'},
            {"version", no_argument, 0, 'V'},
            {0, 0, 0, 0}
        };

        int option_index = 0;
        int c;

        while ((c = getopt_long(argc, argv, "n:d:c:Dvqtrb:p:ma:hV", long_options, &option_index)) != -1) {
            switch (c) {
                case 'n':
                    network = optarg;
                    break;
                case 'd':
                    dataDir = optarg;
                    break;
                case 'c':
                    configFile = optarg;
                    break;
                case 'D':
                    daemonMode = true;
                    break;
                case 'v':
                    verbosity++;
                    break;
                case 'q':
                    verbosity = 0;
                    break;
                case 't':
                    testnet = true;
                    network = "testnet";
                    break;
                case 'r':
                    regtest = true;
                    network = "regtest";
                    break;
                case 'u': {
                    std::string creds = optarg;
                    size_t colon = creds.find(':');
                    if (colon != std::string::npos) {
                        rpcUser = creds.substr(0, colon);
                        rpcPassword = creds.substr(colon + 1);
                    }
                    break;
                }
                case 'b':
                    rpcBind = optarg;
                    break;
                case 'p':
                    rpcPort = std::stoi(optarg);
                    break;
                case 'm':
                    enableMining = true;
                    break;
                case 'a':
                    miningAddress = optarg;
                    break;
                case 'h':
                    print();
                    return false;
                case 'V':
                    std::cout << "Power Coin v" << VersionConfig::VERSION_STRING << std::endl;
                    return false;
                default:
                    return false;
            }
        }

        return true;
    }

    bool Config::parseConfigFile(const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) {
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            // Skip comments and empty lines
            if (line.empty() || line[0] == '#') {
                continue;
            }

            size_t equals = line.find('=');
            if (equals == std::string::npos) {
                continue;
            }

            std::string key = line.substr(0, equals);
            std::string value = line.substr(equals + 1);

            // Trim whitespace
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);

            // Parse key-value pairs
            if (key == "network") {
                network = value;
            } else if (key == "datadir") {
                dataDir = value;
            } else if (key == "daemon") {
                daemonMode = (value == "1" || value == "yes" || value == "true");
            } else if (key == "testnet") {
                testnet = (value == "1" || value == "yes" || value == "true");
                if (testnet) network = "testnet";
            } else if (key == "regtest") {
                regtest = (value == "1" || value == "yes" || value == "true");
                if (regtest) network = "regtest";
            } else if (key == "rpcuser") {
                rpcUser = value;
            } else if (key == "rpcpassword") {
                rpcPassword = value;
            } else if (key == "rpcbind") {
                rpcBind = value;
            } else if (key == "rpcport") {
                rpcPort = std::stoi(value);
            } else if (key == "rpcenable") {
                rpcEnabled = (value == "1" || value == "yes" || value == "true");
            } else if (key == "mine") {
                enableMining = (value == "1" || value == "yes" || value == "true");
            } else if (key == "miningaddr") {
                miningAddress = value;
            } else if (key == "maxconnections") {
                maxConnections = std::stoi(value);
            } else if (key == "verbosity") {
                verbosity = std::stoi(value);
            }
        }

        file.close();
        return true;
    }

    void Config::updateFromNetwork() {
        if (network == "testnet") {
            magic = NetworkConfig::MAGIC_TESTNET;
            port = NetworkConfig::DEFAULT_PORT_TESTNET;
            seedNodes.clear();
            for (const auto& seed : NetworkConfig::SEED_NODES_TESTNET) {
                seedNodes.push_back(seed);
            }
        } else if (network == "regtest") {
            magic = NetworkConfig::MAGIC_REGTEST;
            port = NetworkConfig::DEFAULT_PORT_REGTEST;
            seedNodes.clear();
        } else {
            magic = NetworkConfig::MAGIC_MAINNET;
            port = NetworkConfig::DEFAULT_PORT_MAINNET;
            seedNodes.clear();
            for (const auto& seed : NetworkConfig::SEED_NODES_MAINNET) {
                seedNodes.push_back(seed);
            }
        }
    }

    bool Config::save() const {
        // Create config file with current settings
        std::ofstream file(configFile);
        if (!file.is_open()) {
            return false;
        }

        file << "# Power Coin Configuration File\n";
        file << "# Generated: " << std::time(nullptr) << "\n\n";
        
        file << "network=" << network << "\n";
        file << "datadir=" << dataDir << "\n";
        file << "daemon=" << (daemonMode ? "1" : "0") << "\n";
        file << "testnet=" << (testnet ? "1" : "0") << "\n";
        file << "regtest=" << (regtest ? "1" : "0") << "\n";
        file << "verbosity=" << verbosity << "\n\n";
        
        file << "# RPC Settings\n";
        file << "rpcuser=" << rpcUser << "\n";
        file << "rpcpassword=" << rpcPassword << "\n";
        file << "rpcbind=" << rpcBind << "\n";
        file << "rpcport=" << rpcPort << "\n";
        file << "rpcenable=" << (rpcEnabled ? "1" : "0") << "\n\n";
        
        file << "# Mining Settings\n";
        file << "mine=" << (enableMining ? "1" : "0") << "\n";
        if (!miningAddress.empty()) {
            file << "miningaddr=" << miningAddress << "\n";
        }
        file << "\n# Connection Settings\n";
        file << "maxconnections=" << maxConnections << "\n";

        file.close();
        return true;
    }

    void Config::print() const {
        std::cout << "\n=== Power Coin Configuration ===\n";
        std::cout << "Version: " << VersionConfig::VERSION_STRING << "\n";
        std::cout << "Network: " << network << "\n";
        std::cout << "Data Directory: " << dataDir << "\n";
        std::cout << "Config File: " << configFile << "\n";
        std::cout << "Mode: " << (daemonMode ? "Daemon" : "Interactive") << "\n";
        std::cout << "Verbosity: " << verbosity << "\n";
        std::cout << "Port: " << port << "\n";
        std::cout << "Magic: 0x" << std::hex << magic << std::dec << "\n";
        std::cout << "Seed Nodes: " << seedNodes.size() << "\n";
        
        std::cout << "\n--- RPC Settings ---\n";
        std::cout << "RPC Enabled: " << (rpcEnabled ? "Yes" : "No") << "\n";
        std::cout << "RPC Bind: " << rpcBind << "\n";
        std::cout << "RPC Port: " << rpcPort << "\n";
        std::cout << "RPC User: " << rpcUser << "\n";
        std::cout << "RPC Password: " << (rpcPassword.empty() ? "<not set>" : "********") << "\n";
        
        std::cout << "\n--- Mining Settings ---\n";
        std::cout << "Mining Enabled: " << (enableMining ? "Yes" : "No") << "\n";
        if (!miningAddress.empty()) {
            std::cout << "Mining Address: " << miningAddress << "\n";
        }
        std::cout << "Mining Threads: " << miningThreads << "\n";
        
        std::cout << "\n--- Advanced Features ---\n";
        std::cout << "Smart Contracts: " << (enableSmartContracts ? "Enabled" : "Disabled") << "\n";
        std::cout << "Privacy Features: " << (enablePrivacy ? "Enabled" : "Disabled") << "\n";
        std::cout << "Governance: " << (enableGovernance ? "Enabled" : "Disabled") << "\n";
        std::cout << "Cross-Chain: " << (enableCrossChain ? "Enabled" : "Disabled") << "\n";
        std::cout << "Lightning Network: " << (enableLightning ? "Enabled" : "Disabled") << "\n";
        std::cout << "Masternodes: " << (enableMasternodes ? "Enabled" : "Disabled") << "\n";
        
        std::cout << "\n--- Connection Limits ---\n";
        std::cout << "Max Connections: " << maxConnections << "\n";
        if (maxUploadTarget > 0) {
            std::cout << "Max Upload: " << maxUploadTarget << " bytes/sec\n";
        }
        
        std::cout << "===============================\n";
    }

    bool Config::validate() const {
        // Check network setting
        if (network != "mainnet" && network != "testnet" && network != "regtest") {
            std::cerr << "Invalid network: " << network << std::endl;
            return false;
        }

        // Check RPC settings
        if (rpcEnabled && rpcPassword.empty()) {
            std::cerr << "RPC password must be set when RPC is enabled" << std::endl;
            return false;
        }

        // Check mining settings
        if (enableMining && miningAddress.empty()) {
            std::cerr << "Mining address must be set when mining is enabled" << std::endl;
            return false;
        }

        // Check data directory
        struct stat st;
        if (stat(dataDir.c_str(), &st) != 0) {
            std::cerr << "Data directory does not exist: " << dataDir << std::endl;
            return false;
        }

        return true;
    }

    void Config::setNetwork(const std::string& net) {
        network = net;
        updateFromNetwork();
    }

    void Config::setDataDir(const std::string& dir) {
        dataDir = dir;
        configFile = dataDir + "/" + PathConfig::CONFIG_FILE;
        pidFile = dataDir + "/" + PathConfig::PID_FILE;
    }

    void Config::setRpcCredentials(const std::string& user, const std::string& pass) {
        rpcUser = user;
        rpcPassword = pass;
    }

    std::string Config::getDefaultConfigPath() {
        return getDefaultDataDir() + "/" + PathConfig::CONFIG_FILE;
    }

    std::string Config::getDefaultDataDir() {
        const char* home = getenv("HOME");
        if (!home) {
            struct passwd* pw = getpwuid(getuid());
            if (pw) {
                home = pw->pw_dir;
            }
        }
        
        if (home) {
            return std::string(home) + "/.powercoin";
        }
        
        return ".";
    }

} // namespace powercoin