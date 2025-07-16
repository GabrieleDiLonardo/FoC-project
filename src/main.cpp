#include <iostream>
#include <string>
#include <sstream>
#include "dss_server.h"
#include "utility.h"

using namespace std;

void handleClient(int clientSocket)
{
    char buffer[2048];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived <= 0)
    {
        cerr << "Error receiving data or connection closed.\n";
        close(clientSocket);
        return;
    }

    buffer[bytesReceived] = '\0'; // Assicura che sia una stringa C valida
    string request(buffer);
    cout << "[Server] Ricevuto: " << request << endl;

    istringstream iss(request);
    string command, username, password, document;
    iss >> command >> username >> password;
    getline(iss, document);
    
    if (!document.empty() && document[0] == ' ')
    {
        document = document.substr(1);
    }

    string response;

    if (command == "Login")
    {
        response = login(username, password);
    }
    else if (command == "UpdatePassword")
    {
        cout << "PASSWORD NUOVA: " << password << endl;
        response = change_temporary_password(username, password);
    }
    else if (command == "CreateKeys")
    {
        response = create_keys(username);
    }
    else if (command == "GetPublicKey")
    {
        response = get_public_key(username);
    }
    else if (command == "SignDoc")
    {
        response = sign_document(username, document);
    }
    else if (command == "DeleteKeys")
    {
        response = delete_keys(username);
    }
    else if (command == "exit")
    {
        response = "Connection terminated.\n";;
    }
    else
    {
        response = "Command not recognized.\n";
    }

    send(clientSocket, response.c_str(), static_cast<int>(response.length()), 0);
    close(clientSocket);
}

int main()
{
    int serverSocket;

    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1)
    {
        cerr << "Error creating socket.\n";
        return 1;
    }

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (::bind(serverSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == -1)
    {
        cerr << "Error on bind().\n";
        close(serverSocket);
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) == -1)
    {
        cerr << "Error on listen().\n";
        close(serverSocket);
        return 1;
    }

    cout << "Server in ascolto sulla porta " << PORT << "...\n";

    while (true)
    {
        sockaddr_in clientAddr;
        socklen_t clientAddrSize = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (sockaddr *)&clientAddr, &clientAddrSize);
        if (clientSocket == -1)
        {
            cerr << "Error on accept().\n";
            continue;
        }
        handleClient(clientSocket);
    }

    close(serverSocket);
    return 0;
}
