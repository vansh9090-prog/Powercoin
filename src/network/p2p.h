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
        bool isConnected;
    };
    
    class P2PNetwork {
    private:
        int serverSocket;
        std::map<std::string, Peer> peers;
        std::atomic<bool> isRunning;
        std::string nodeId;
        uint16_t listenPort;
        
        void serverLoop();
        void handleClient(int clientSocket);
        void sendMessage(int socket, const std::string& message);
        std::string receiveMessage(int socket);
        std::string getPeerListString() const;

    public:
        P2PNetwork(uint16_t port = 8333);
        ~P2PNetwork();
        
        bool start();
        void stop();
        
        size_t getPeerCount() const { return peers.size(); }
        std::string getNodeId() const { return nodeId; }
    };
    
}

#endif // POWERCOIN_P2P_H