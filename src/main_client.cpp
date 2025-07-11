#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../include/utility.h"

using namespace std;

constexpr int PORT = 8080;
constexpr const char *SERVER_IP = "127.0.0.1";

string getCommandFromChoice(int choice)
{
    switch (choice)
    {
    case 1:
        return "CreateKeys";
    case 2:
        return "SignDoc";
    case 3:
        return "GetPublicKey";
    case 4:
        return "DeleteKeys";
    case 5:
        return "Exit";
    default:
        return "";
    }
}

bool sendRequestToServer(const string &request, string &response)
{
    int clientSocket;
    sockaddr_in serverAddr;

    clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1)
    {
        cerr << "Errore nella creazione del socket.\n";
        return false;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

    if (connect(clientSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == /*SOCKET_ERROR*/ -1)
    {
        cerr << "Errore di connessione al server.\n";
        close(clientSocket);
        return false;
    }

    send(clientSocket, request.c_str(), static_cast<int>(request.length()), 0);

    char buffer[2048];
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    if (bytesReceived > 0)
    {
        buffer[bytesReceived] = '\0';
        response = buffer;
    }

    close(clientSocket);
    return true;
}

int main()
{
    string username;
    string password;
    string fullRequest;
    string serverResponse;
    string hashed_password;

    do
    {
        system("clear");
        cout << "Inserisci il tuo nome utente: ";
        getline(cin, username);
        cout << "Password: ";
        getline(cin, password);
        hashed_password = hash_password(password);
        fullRequest = "Login " + username + " " + hashed_password;
        sendRequestToServer(fullRequest, serverResponse);
    } while (serverResponse == "Username e/o password non corretti/o.\n");


    if (serverResponse == "Inserisci nuova password: ")
    {
        cout << serverResponse;
        while (serverResponse != "Password modificata.\n")
        {
            fullRequest = "\0";
            password = "\0";
            getline(cin, password);
            hashed_password = hash_password(password);
            fullRequest = "UpdatePassword " + username + " " + hashed_password;
            sendRequestToServer(fullRequest, serverResponse);
        }
    }

    fullRequest = "\0";

    while (true)
    {
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

        try
        {
            choice = stoi(input);
        }
        catch (...)
        {
            cout << "Input non valido. Inserisci un numero tra 1 e 5.\n";
            continue;
        }

        string command = getCommandFromChoice(choice);
        if (command.empty())
        {
            cout << "Scelta non valida.\n";
            continue;
        }

        fullRequest = command + " " + username + " " + password;

        if (command == "Exit")
            break;

        if (command == "SignDoc")
        {
            string document;
            cout << "Inserisci il documento da firmare: ";
            getline(cin, document);
            fullRequest += " " + document;
        }
        else if (command == "GetPublicKey")
        {
            string userToQuery;
            cout << "Inserisci il nome dell'utente: ";
            getline(cin, userToQuery);
            fullRequest = command + " " + userToQuery;
        }

        if (sendRequestToServer(fullRequest, serverResponse))
        {
            cout << "Risposta dal server:\n"
                 << serverResponse << endl;
        }
    }

    return 0;
}
