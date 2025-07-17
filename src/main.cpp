#include <iostream>
#include <string>
#include <sstream>
#include <unistd.h>         // close()
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../include/dss_server.h"
#include "../include/utility.h"
#include "../include/secure_channel.h"
using namespace std;

// Gestisce multipli comandi su un singolo clientSocket
void handleClientSession(int clientSocket,
                         const vector<unsigned char>& session_key)
{
    while (true)
    {
        // --- 1) ricevi un messaggio cifrato singolo ---
        string request;
        if (!recvEncryptedMessage(clientSocket, session_key, request)) {
            cerr << "[Server] Errore o connessione chiusa durante recvEncryptedMessage.\n";
            break;
        }

        if (request == "exit\n") {
            // conferma e chiudi
            sendEncryptedMessage(clientSocket, session_key, "Connection terminated.\n");
            cout << "[Server] Terminazione sessione client.\n";
            break;
        }

        cout << "[Server] Ricevuto: " << request;

        // parse
        istringstream iss(request);
        string command, username, password, document;
        iss >> command >> username >> password;
        getline(iss, document);
        if (!document.empty() && document[0] == ' ')
            document.erase(0, 1);

        // processa comando
        string response;
        if (command == "Login")
            response = login(username, password);
        else if (command == "UpdatePassword")
            response = change_temporary_password(username, password);
        else if (command == "CreateKeys")
            response = create_keys(username);
        else if (command == "GetPublicKey")
            response = get_public_key(username);
        else if (command == "SignDoc")
            response = sign_document(username, document);
        else if (command == "DeleteKeys")
            response = delete_keys(username);
        else
            response = "Command not recognized.\n";

        // invia la risposta cifrata
        if (!sendEncryptedMessage(clientSocket, session_key, response))
        {
            cerr << "[Server] Errore durante sendEncryptedMessage.\n";
            break;
        }
    }
}

int main()
{
    vector<unsigned char> session_key;
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0) {
        cerr << "Error creating socket.\n";
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family      = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port        = htons(PORT);

    if (::bind(serverSocket, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        cerr << "Error on bind().\n";
        close(serverSocket);
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) < 0) {
        cerr << "Error on listen().\n";
        close(serverSocket);
        return 1;
    }

    cout << "Server in ascolto sulla porta " << PORT << "...\n";

    while (true)
    {
        sockaddr_in clientAddr;
        socklen_t   clientLen = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &clientLen);
        if (clientSocket < 0) {
            cerr << "Error on accept().\n";
            continue;
        }

        cout << "[Server] Nuova connessione, avvio handshake sicuro...\n";
        // apertura canale sicuro e derivazione session_key
        if (apertura_canale_sicuro_server(clientSocket, session_key) == 0) {
            cout << "[Server] Handshake completato, inizio sessione comandi.\n";
            handleClientSession(clientSocket, session_key);
        } else {
            cerr << "[Server] Handshake fallito, chiudo connessione.\n";
        }

        close(clientSocket);
    }

    close(serverSocket);
    return 0;
}