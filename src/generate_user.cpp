#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <random>
#include "../include/utility.h"
#include <openssl/sha.h>

using namespace std;

// Generazione password temporanea casuale
string generateTemporaryPassword(int length = 10) {
    const string characters =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";

    default_random_engine rng(static_cast<unsigned>(time(nullptr)));
    uniform_int_distribution<> dist(0, characters.size() - 1);

    string tempPassword;
    for (int i = 0; i < length; ++i) {
        tempPassword += characters[dist(rng)];
    }
    return tempPassword;
}

// Creazione del file utente con password temporanea hashata
void createUserFile(const string& username) {
    string tempPassword = generateTemporaryPassword();
    string hashed = hash_password(tempPassword);

    ofstream file("users/" + username + ".txt");
    if (file.is_open()) {
        file << "password: " << hashed << "\n";
        file << "modified_password: 0\n";
        file.close();
        cout << "Utente \"" << username << "\" creato.\n";
        cout << "Password temporanea (da comunicare all'utente): " << tempPassword << endl;
    } else {
        cerr << "Errore nella creazione del file utente.\n";
    }
}

// Funzione main per testare la creazione di un utente
int main() {
    string username;
    cout << "Inserisci il nome utente da registrare: ";
    cin >> username;

    createUserFile(username);

    return 0;
}