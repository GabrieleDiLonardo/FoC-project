#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <openssl/sha.h>

using namespace std;


// Funzione per leggere tutto il contenuto del file in un vettore di byte
vector<unsigned char> readFile(const string& filename);

// Funzione per calcolare l'hash SHA-256
vector<unsigned char> sha256(const vector<unsigned char>& data);