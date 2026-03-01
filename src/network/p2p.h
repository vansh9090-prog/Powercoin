#ifndef POWERCOIN_P2P_H
#define POWERCOIN_P2P_H

#include <string>
#include <vector>
#include <map>
#include <thread>
#include <atomic>
#include <functional>
#include <netinet/in.h>

namespace PowerCoin {
    
    struct Peer {
        std::string id;
        std::string ip;
        uint16_t port;
        uint64_t lastSeen;
        uint32_t height;
        bool isConnected;
    };
    
    class P2PNetwork {
    private:
        int serverSocket;
        struct sockaddr_in serverAddr;
        std::map<std::string, Peer> peers;
        std::vector<std::thread> clientThreads;
        std::atomic<bool> isRunning;
        
        std::string nodeId;
        uint16_t listenPort;
        
        void serverLoop();
        void handleClient(int clientSocket, const std::string& clientIp);
        void sendMessage(int socket, const std::string& message);
        std::string receiveMessage(int socket);
        
    public:
        P2PNetwork(uint16_t port = 8333);
        ~P2PNetwork();
        
        // Network control
        bool start();
        void stop();
        bool connectToPeer(const std::string& ip, uint16_t port);
        
        // Broadcasting
        void broadcastBlock(const std::string& blockData);
        void broadcastTransaction(const std::string& txData);
        void broadcastPeerList();
        
        // Getters
        size_t getPeerCount() const { return peers.size(); }
        std::vector<Peer> getPeerList() const;
        std::string getNodeId() const { return nodeId; }
        
        // Callbacks
        std::function<void(const std::string&, const std::string&)> onBlockReceived;
        std::function<void(const std::string&, const std::string&)> onTransactionReceived;
        std::function<void(const Peer&)> onNewPeer;
        std::function<void(const std::string&)> onPeerDisconnected;
    };
    
}

#endif // POWERCOIN_P2P_H