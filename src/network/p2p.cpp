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
    
    P2PNetwork::P2PNetwork(uint16_t port) : isRunning(false), listenPort(port) {
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
        serverSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (serverSocket < 0) return false;
        
        int opt = 1;
        setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(listenPort);
        
        if (bind(serverSocket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(serverSocket);
            return false;
        }
        
        if (listen(serverSocket, 10) < 0) {
            close(serverSocket);
            return false;
        }
        
        isRunning = true;
        std::thread serverThread(&P2PNetwork::serverLoop, this);
        serverThread.detach();
        
        std::cout << "🌐 P2P Node: " << nodeId << " on port " << listenPort << "\n";
        return true;
    }
    
    void P2PNetwork::stop() {
        isRunning = false;
        if (serverSocket >= 0) {
            close(serverSocket);
        }
    }
    
    void P2PNetwork::serverLoop() {
        while (isRunning) {
            struct sockaddr_in clientAddr;
            socklen_t clientLen = sizeof(clientAddr);
            
            int clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientLen);
            if (clientSocket < 0) continue;
            
            std::thread([this, clientSocket]() {
                this->handleClient(clientSocket);
            }).detach();
        }
    }
    
    void P2PNetwork::handleClient(int clientSocket) {
        std::string message = receiveMessage(clientSocket);
        if (message.empty()) {
            close(clientSocket);
            return;
        }
        close(clientSocket);
    }
    
    void P2PNetwork::sendMessage(int socket, const std::string& message) {
        uint32_t len = htonl(message.length());
        send(socket, &len, sizeof(len), 0);
        send(socket, message.c_str(), message.length(), 0);
    }
    
    std::string P2PNetwork::receiveMessage(int socket) {
        uint32_t len;
        if (recv(socket, &len, sizeof(len), 0) <= 0) return "";
        len = ntohl(len);
        
        std::vector<char> buffer(len + 1);
        if (recv(socket, buffer.data(), len, 0) <= 0) return "";
        buffer[len] = '\0';
        return std::string(buffer.data());
    }
    
    std::string P2PNetwork::getPeerListString() const {
        std::stringstream ss;
        for (const auto& [id, peer] : peers) {
            ss << peer.ip << ":" << peer.port << ",";
        }
        return ss.str();
    }
    
}