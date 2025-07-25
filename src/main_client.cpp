#include <iostream>
#include <string>
#include <vector>
#include <sys/socket.h>
#include <cstdlib>
#include <arpa/inet.h>
#include <unistd.h>
#include "../include/utility.h"
#include "../include/user.h"
#include "../include/secure_channel.h"

using namespace std;

// Legge da sock fino a '\n' (inclusa), ritorna la riga senza '\n'
bool recvLine(int sock, string &out) {
    out.clear();
    char c;
    while (true) {
        ssize_t n = recv(sock, &c, 1, 0);
        if (n <= 0) return false;        // errore o connessione chiusa
        if (c == '\n') break;
        out.push_back(c);
    }
    return true;
}

// Mappa scelta numerica → comando testuale
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

int main() {

    // 1) Handshake sicuro
     int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { perror("socket"); return 1; }
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);
    if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("connect"); close(sock); return 1;
    }

    std::vector<unsigned char> session_key;
    bool handshake_success = false;
    const int MAX_ATTEMPTS = 3;
    std::string username, password, hashed_pw,line;

    // Handshake sicuro con retry credenziali
    for (int attempt = 1; attempt <= MAX_ATTEMPTS; ++attempt) {
        std::cout << "Username: "; std::getline(std::cin, username);
        std::cout << "Password: "; std::getline(std::cin, password);
        hashed_pw = hash_password(password);

        std::cout << "[Client] Handshake attempt #" << attempt << "...\n";
        if (apertura_canale_sicuro_client(sock, username, hashed_pw, session_key) == 0) {
            handshake_success = true;
            resetMessageCounter();
            break;
        }
        std::cerr << "Handshake fallito. Riprova.\n";
        close(sock);
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { perror("socket"); return 1; }
        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("connect"); close(sock); return 1;
        }
    }
    
    if (!handshake_success) {
        std::cerr << "Impossibile stabilire canale sicuro dopo "
                  << MAX_ATTEMPTS << " tentativi.\n";
        close(sock);
        return 1;
    }

    // 2) Login loop (gestisce anche primo cambio password)
    while (true) {
        // send encrypted Login
        string req = "Login " + username + " " + hashed_pw + "\n";
        if (!sendEncryptedMessage(sock, session_key, req)) break;

        // receive encrypted response
        if (!recvEncryptedMessage(sock, session_key, line)) break;
        if (line == "Invalid username or password.") {
            cout << "Username: "; getline(cin, username);
            cout << "Password: "; getline(cin, password);
            hashed_pw = hash_password(password);
            continue;
        }
        if (line == "First login detected. Please set a new password: ") {
            do {
                cout << line << "\n";
                cout << "> "; 
                getline(cin, password);
                hashed_pw = hash_password(password);
                req = "UpdatePassword " + username + " " + hashed_pw + "\n";
                sendEncryptedMessage(sock, session_key, req);
                recvEncryptedMessage(sock, session_key, line);
            } while (line != "Password successfully updated..\n");
        }
        break;
    }

    // 3) Interaction loop
    for (;;) {
        cout << "\nMenu:\n"
             << "1) CreateKeys\n"
             << "2) SignDoc\n"
             << "3) GetPublicKey\n"
             << "4) DeleteKeys\n"
             << "5) Exit\n"
             << "Choice> ";
        int choice; 
        if (!(cin >> choice)) break;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        string cmd = getCommandFromChoice(choice);
        if (cmd.empty()) { cout<<"Invalid\n"; continue; }
        if (cmd == "Exit") {
            sendEncryptedMessage(sock, session_key, "exit\n");
            break;
        }

        // build request
        string req = cmd + " " + username;
        if (cmd == "SignDoc") {
            cout<<"File to sign> "; string fn; getline(cin, fn);
            auto data = readFile(fn);
            req += " " + toHex(sha256(data));
        }
        else if (cmd == "GetPublicKey") {
            cout<<"Target username> "; string tgt; getline(cin, tgt);
            req = cmd + " " + tgt;
        }
        req += "\n";

        // send & recv
        sendEncryptedMessage(sock, session_key, req);
        if (!recvEncryptedMessage(sock, session_key, line)) break;
        cout << line << "\n";

        if (cmd == "DeleteKeys") {
            cout<<"Deleted; exiting.\n";
            break;
        }
    }
    fill(session_key.begin(), session_key.end(), 0);
    session_key.clear();

    close(sock);
    resetMessageCounter(); 
    return 0;
}
