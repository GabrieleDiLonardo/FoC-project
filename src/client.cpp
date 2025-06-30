#include "client.hpp"
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>

DSS_Client::DSS_Client(const std::string& serverIP, int port)
    : serverIP(serverIP), port(port) {}

bool DSS_Client::connectToServer() {
    std::cout << "[CLIENT] Connecting to server " << serverIP << ":" << port << std::endl;
    return true; // Qui andrà la connessione reale via socket
}

void DSS_Client::run() {
    if (connectToServer()) {
        std::cout << "[CLIENT] Connected. Ready to interact." << std::endl;
    } else {
        std::cerr << "[CLIENT] Connection failed." << std::endl;
    }
}
