#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

void handle_client(SOCKET client_socket) {
    char buffer[512];
    int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received == SOCKET_ERROR || bytes_received == 0) {
        std::cerr << "Errore ricezione dati o connessione chiusa." << std::endl;
        closesocket(client_socket);
        return;
    }
    buffer[bytes_received] = '\0';
    std::cout << "Messaggio ricevuto dal client: " << buffer << std::endl;

    const char* reply = "Messaggio ricevuto con successo dal server!";
    send(client_socket, reply, (int)strlen(reply), 0);

    closesocket(client_socket);
}

int main() {
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup fallito" << std::endl;
        return 1;
    }

    SOCKET listen_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_socket == INVALID_SOCKET) {
        std::cerr << "Errore creazione socket: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_port = htons(54000);
    if (inet_pton(AF_INET, "127.0.0.1", &service.sin_addr) != 1) {
        std::cerr << "inet_pton fallito" << std::endl;
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    if (bind(listen_socket, (SOCKADDR*)&service, sizeof(service)) == SOCKET_ERROR) {
        std::cerr << "Bind fallito: " << WSAGetLastError() << std::endl;
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    if (listen(listen_socket, SOMAXCONN) == SOCKET_ERROR) {
        std::cerr << "Listen fallito: " << WSAGetLastError() << std::endl;
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    std::cout << "Server in ascolto su 127.0.0.1:54000..." << std::endl;

    SOCKET client_socket = accept(listen_socket, NULL, NULL);
    if (client_socket == INVALID_SOCKET) {
        std::cerr << "Accept fallito: " << WSAGetLastError() << std::endl;
        closesocket(listen_socket);
        WSACleanup();
        return 1;
    }

    std::cout << "Connessione accettata." << std::endl;

    handle_client(client_socket);

    closesocket(listen_socket);
    WSACleanup();
    return 0;
}
