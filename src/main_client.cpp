#include <iostream>
#include <string>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../include/utility.h"
#include "../include/user.h"

using namespace std;

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
        cerr << "Error connecting to the server.\n";
        return false;
    }

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr);

    if (connect(clientSocket, (sockaddr *)&serverAddr, sizeof(serverAddr)) == /*SOCKET_ERROR*/ -1)
    {
        cerr << "Error connecting to the server.\n";
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
        cout << "Username: ";
        getline(cin, username);
        cout << "Password: ";
        getline(cin, password);
        hashed_password = hash_password(password);
        fullRequest = "Login " + username + " " + hashed_password;
        sendRequestToServer(fullRequest, serverResponse);
    } while (serverResponse == "Invalid username or password.\n");

    system("clear");

    if (serverResponse == "First login detected. Please set a new password: ")
    {
        cout << serverResponse;
        while (serverResponse != "Password successfully updated..\n")
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
        cout << "\nEnter the number corresponding to a command:" << endl;
        cout << "1. CreateKeys" << endl;
        cout << "2. SignDoc" << endl;
        cout << "3. GetPublicKey" << endl;
        cout << "4. DeleteKeys" << endl;
        cout << "5. Exit" << endl;
        cout << "Choice: ";

        string input;
        getline(cin, input);
        int choice;

        try
        {
            choice = stoi(input);
        }
        catch (...)
        {
            cout << "Invalid input. Please enter a number between 1 and 5." << endl;
            continue;
        }

        string command = getCommandFromChoice(choice);
        if (command.empty())
        {
            cout << "Invalid choice" << endl;
            continue;
        }

        fullRequest = command + " " + username + " " + password;

        if (command == "Exit")
        {
            break;
        }

        if (command == "SignDoc")
        {
            string file_name;
            while (true)
            {
                system("clear");
                cout << "Enter the name of the document to be signed (including extension, e.g., file.txt): ";
                getline(cin, file_name);

                size_t dotPos = file_name.find_last_of('.');
                if (dotPos != string::npos && dotPos != file_name.length() - 1)
                {
                    break;
                }
                else
                {
                    cout << "Error: you must also include the file extension (e.g., file.txt)." << endl;
                }
            }
            vector<unsigned char> fileData = readFile(file_name);
            vector<unsigned char> document = sha256(fileData);
            string documentHex = toHex(document);
            fullRequest += " " + documentHex;
        }
        else if (command == "GetPublicKey")
        {
            string userToQuery;
            cout << "Enter the username of the user whose public key you want to retrieve: ";
            getline(cin, userToQuery);
            fullRequest = command + " " + userToQuery;
        }

        if (sendRequestToServer(fullRequest, serverResponse))
        {
            cout << serverResponse << endl;
        }

        if (command == "DeleteKeys")
        {
            cout << "New registration required. Logging out..." << endl;
            break;
        }
    }

    return 0;
}
