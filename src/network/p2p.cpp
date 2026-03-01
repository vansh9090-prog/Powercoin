#include "p2p.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <chrono>
#include <thread>
#include <random>
#include <sstream>

namespace PowerCoin {
    
    P2PNetwork::P2PNetwork(uint16_t port) 
        : serverSocket(-1), isRunning(false), listenPort(port) {
        
        // Generate random node ID
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 15);
        
        const char* hexChars = "0123456789abcdef";
        for (int i = 0; i < 16; i++) {
            nodeId += hexChars[dis(gen)];
        }
    }
    
    P2PNetwork::~P2PNetwork() {
        stop();
    }
    
    bool P2PNetwork::start() {
        // Create socket
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }
        
        // Set socket options
        int opt = 1;
        if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
            std::cerr << "Failed to set socket options" << std::endl;
            return false;
        }
        
        // Bind socket
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_addr.s_addr = INADDR_ANY;
        serverAddr.sin_port = htons(listenPort);
        
        if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
            std::cerr << "Failed to bind socket to port " << listenPort << std::endl;
            return false;
        }
        
        // Listen for connections
        if (listen(serverSocket, 10) < 0) {
            std::cerr << "Failed to listen on socket" << std::endl;
            return false;
        }
        
        isRunning = true;
        
        // Start server thread
        std::thread serverThread(&P2PNetwork::serverLoop, this);
        serverThread.detach();
        
        std::cout << "🌐 P2P Network started on port " << listenPort << std::endl;
        std::cout << "🆔 Node ID: " << nodeId << std::endl;
        
        return true;
    }
    
    void P2PNetwork::stop() {
        isRunning = false;
        
        if (serverSocket >= 0) {
            close(serverSocket);
            serverSocket = -1;
        }
        
        std::cout << "🌐 P2P Network stopped" << std::endl;
    }
    
    void P2PNetwork::serverLoop() {
        while (isRunning) {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            
            int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
            
            if (clientSocket < 0) {
                if (isRunning) {
                    std::cerr << "Failed to accept connection" << std::endl;
                }
                continue;
            }
            
            std::string clientIp = inet_ntoa(clientAddr.sin_addr);
            
            // Handle client in new thread
            std::thread clientThread(&P2PNetwork::handleClient, this, clientSocket, clientIp);
            clientThread.detach();
        }
    }
    
    void P2PNetwork::handleClient(int clientSocket, const std::string& clientIp) {
        std::string message = receiveMessage(clientSocket);
        
        if (message.empty()) {
            close(clientSocket);
            return;
        }
        
        // Process message
        if (message.substr(0, 5) == "BLOCK") {
            if (onBlockReceived) {
                onBlockReceived(clientIp, message.substr(6));
            }
        } else if (message.substr(0, 4) == "TX") {
            if (onTransactionReceived) {
                onTransactionReceived(clientIp, message.substr(5));
            }
        } else if (message.substr(0, 5) == "PEERS") {
            // Send peer list
            sendMessage(clientSocket, "PEERLIST:" + getPeerListString());
        } else if (message.substr(0, 7) == "HANDSHAKE") {
            // Add peer
            Peer peer;
            peer.id = message.substr(8, 16);
            peer.ip = clientIp;
            peer.port = listenPort;
            peer.lastSeen = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            peer.isConnected = true;
            
            peers[peer.id] = peer;
            
            if (onNewPeer) {
                onNewPeer(peer);
            }
            
            // Send handshake response
            sendMessage(clientSocket, "HANDSHAKE_OK:" + nodeId);
        }
        
        close(clientSocket);
    }
    
    bool P2PNetwork::connectToPeer(const std::string& ip, uint16_t port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return false;
        }
        
        struct sockaddr_in peerAddr;
        peerAddr.sin_family = AF_INET;
        peerAddr.sin_port = htons(port);
        
        if (inet_pton(AF_INET, ip.c_str(), &peerAddr.sin_addr) <= 0) {
            close(sock);
            return false;
        }
        
        if (connect(sock, (struct sockaddr*)&peerAddr, sizeof(peerAddr)) < 0) {
            close(sock);
            return false;
        }
        
        // Send handshake
        sendMessage(sock, "HANDSHAKE:" + nodeId);
        
        std::string response = receiveMessage(sock);
        
        if (response.substr(0, 12) == "HANDSHAKE_OK:") {
            std::string peerId = response.substr(12);
            
            Peer peer;
            peer.id = peerId;
            peer.ip = ip;
            peer.port = port;
            peer.lastSeen = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            peer.isConnected = true;
            
            peers[peerId] = peer;
            
            std::cout << "🔗 Connected to peer: " << peerId << " @ " << ip << ":" << port << std::endl;
        }
        
        close(sock);
        return true;
    }
    
    void P2PNetwork::broadcastBlock(const std::string& blockData) {
        std::string message = "BLOCK:" + blockData;
        
        for (const auto& [id, peer] : peers) {
            if (peer.isConnected) {
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) continue;
                
                struct sockaddr_in peerAddr;
                peerAddr.sin_family = AF_INET;
                peerAddr.sin_port = htons(peer.port);
                
                if (inet_pton(AF_INET, peer.ip.c_str(), &peerAddr.sin_addr) <= 0) {
                    close(sock);
                    continue;
                }
                
                if (connect(sock, (struct sockaddr*)&peerAddr, sizeof(peerAddr)) == 0) {
                    sendMessage(sock, message);
                }
                
                close(sock);
            }
        }
    }
    
    void P2PNetwork::broadcastTransaction(const std::string& txData) {
        std::string message = "TX:" + txData;
        
        for (const auto& [id, peer] : peers) {
            if (peer.isConnected) {
                int sock = socket(AF_INET, SOCK_STREAM, 0);
                if (sock < 0) continue;
                
                struct sockaddr_in peerAddr;
                peerAddr.sin_family = AF_INET;
                peerAddr.sin_port = htons(peer.port);
                
                if (inet_pton(AF_INET, peer.ip.c_str(), &peerAddr.sin_addr) <= 0) {
                    close(sock);
                    continue;
                }
                
                if (connect(sock, (struct sockaddr*)&peerAddr, sizeof(peerAddr)) == 0) {
                    sendMessage(sock, message);
                }
                
                close(sock);
            }
        }
    }
    
    void P2PNetwork::sendMessage(int socket, const std::string& message) {
        uint32_t length = htonl(message.length());
        send(socket, &length, sizeof(length), 0);
        send(socket, message.c_str(), message.length(), 0);
    }
    
    std::string P2PNetwork::receiveMessage(int socket) {
        uint32_t length;
        if (recv(socket, &length, sizeof(length), 0) <= 0) {
            return "";
        }
        
        length = ntohl(length);
        
        std::vector<char> buffer(length + 1);
        if (recv(socket, buffer.data(), length, 0) <= 0) {
            return "";
        }
        
        buffer[length] = '\0';
        return std::string(buffer.data());
    }
    
    std::vector<Peer> P2PNetwork::getPeerList() const {
        std::vector<Peer> result;
        for (const auto& [id, peer] : peers) {
            result.push_back(peer);
        }
        return result;
    }
    
    std::string P2PNetwork::getPeerListString() const {
        std::stringstream ss;
        for (const auto& [id, peer] : peers) {
            ss << peer.ip << ":" << peer.port << ",";
        }
        return ss.str();
    }
    
}