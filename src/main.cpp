#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <sstream>
#include "dss_server.h"

#pragma comment(lib, "ws2_32.lib")

#define PORT 8080

using namespace std;

void handleClient(SOCKET clientSocket) {
    char buffer[2048];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived <= 0) {
        cerr << "Errore nella ricezione dati o connessione chiusa.\n";
        closesocket(clientSocket);
        return;
    }

    buffer[bytesReceived] = '\0'; // Assicura che sia una stringa C valida
    string request(buffer);
    cout << "[Server] Ricevuto: " << request << endl;

    istringstream iss(request);
    string command, username, document;
    iss >> command >> username;
    getline(iss, document);
    if (!document.empty() && document[0] == ' ') document = document.substr(1);

    string response;

    if (command == "CreateKeys") {
        response = create_keys(username);
    } else if (command == "GetPublicKey") {
        response = get_public_key(username);
    } else if (command == "SignDoc") {
        response = sign_document(username, document);
    } else if (command == "DeleteKeys") {
        response = delete_keys(username);
    } else if (command == "exit") {
        response = "Connessione terminata.\n";
    } else {
        response = "Comando non riconosciuto.\n";
    }

    send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
    closesocket(clientSocket);
}

int main() {
    WSADATA wsaData;
    SOCKET serverSocket = INVALID_SOCKET;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "WSAStartup fallita.\n";
        return 1;
    }

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        cerr << "Errore creazione socket.\n";
        WSACleanup();
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Errore bind().\n";
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == SOCKET_ERROR) {
        cerr << "Errore listen().\n";
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    cout << "Server in ascolto sulla porta " << PORT << "...\n";

    while (true) {
        sockaddr_in clientAddr;
        int clientAddrSize = sizeof(clientAddr);
        SOCKET clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientAddrSize);
        if (clientSocket == INVALID_SOCKET) {
            cerr << "Errore accept().\n";
            continue;
        }

        handleClient(clientSocket);
    }

    closesocket(serverSocket);
    WSACleanup();
    return 0;
}
