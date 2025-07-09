#include <iostream>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib")

using namespace std;

constexpr int PORT = 8080;
constexpr const char* SERVER_IP = "127.0.0.1";

string getCommandFromChoice(int choice) {
    switch (choice) {
        case 1: return "CreateKeys";
        case 2: return "SignDoc";
        case 3: return "GetPublicKey";
        case 4: return "DeleteKeys";
        case 5: return "Exit";
        default: return "";
    }
}

bool sendRequestToServer(const string& request, string& response) {
    WSADATA wsaData;
    SOCKET clientSocket;
    sockaddr_in serverAddr;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        cerr << "Errore WSAStartup.\n";
        return false;
    }

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == INVALID_SOCKET) {
        cerr << "Errore nella creazione del socket.\n";
        WSACleanup();
        return false;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

    if (connect(clientSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
        cerr << "Errore di connessione al server.\n";
        closesocket(clientSocket);
        WSACleanup();
        return false;
    }

    send(clientSocket, request.c_str(), static_cast<int>(request.length()), 0);

    char buffer[2048];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived > 0) {
        buffer[bytesReceived] = '\0';
        response = buffer;
    }

    closesocket(clientSocket);
    WSACleanup();
    return true;
}

int main() {
    string username;
    cout << "Inserisci il tuo nome utente: ";
    getline(cin, username);

    while (true) {
        cout << "\nScegli un comando:\n";
        cout << "1. CreateKeys\n";
        cout << "2. SignDoc\n";
        cout << "3. GetPublicKey\n";
        cout << "4. DeleteKeys\n";
        cout << "5. Exit\n";
        cout << "Scelta: ";

        string input;
        getline(cin, input);
        int choice;

        try {
            choice = stoi(input);
        } catch (...) {
            cout << "Input non valido. Inserisci un numero tra 1 e 5.\n";
            continue;
        }

        string command = getCommandFromChoice(choice);
        if (command.empty()) {
            cout << "Scelta non valida.\n";
            continue;
        }

        string fullRequest = command + " " + username;

        if (command == "Exit")
            break;

        if (command == "SignDoc") {
            string document;
            cout << "Inserisci il documento da firmare: ";
            getline(cin, document);
            fullRequest += " " + document;
        } else if (command == "GetPublicKey") {
            string userToQuery;
            cout << "Inserisci il nome dell'utente: ";
            getline(cin, userToQuery);
            fullRequest = command + " " + userToQuery;
        }

        string serverResponse;
        if (sendRequestToServer(fullRequest, serverResponse)) {
            cout << "Risposta dal server:\n" << serverResponse << endl;
        } 
    }

    return 0;
}
