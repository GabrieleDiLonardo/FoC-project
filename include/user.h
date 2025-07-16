#ifndef USER_H
#define USER_H

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <random>
#include <vector>
#include <openssl/sha.h>

#define SERVER_IP "127.0.0.1"

using namespace std;

// Generazione password temporanea casuale
string generateTemporaryPassword();

// Creazione del file utente con password temporanea hashata
string createUserFile(const string& username);

// Funzione per leggere tutto il contenuto del file in un vettore di byte
vector<unsigned char> readFile(const string& filename);

// Funzione per calcolare l'hash SHA-256
vector<unsigned char> sha256(const vector<unsigned char>& data);

#endif
