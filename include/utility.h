#ifndef UTILITY_H
#define UTILITY_H

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/opensslv.h>
#include <iostream>
#include <string>
#include <chrono>
#include <openssl/param_build.h> 
#include <sstream>
#include <iomanip>  
using namespace std;


// Funzione che ritorna il timestamp corrente in secondi
inline uint64_t get_current_unix_timestamp();

// Funzione generatrice di p e g
EVP_PKEY *generate_dh_params();

// Funzione generatrice di a o b e di g^a mod p o g^b mod p
EVP_PKEY *generate_dh_keypair(EVP_PKEY *dh_params);

bool sign_dh_parameters(
    EVP_PKEY *dss_private_key,      // chiave privata del DSS
    const unsigned char *dh_pubkey, // dati da firmare (es. g^b mod p)
    size_t dh_pubkey_len,           // lunghezza dei dati
    unsigned char *signature,       // buffer in cui salvare la firma
    size_t &signature_len           // output: lunghezza effettiva della firma
    );


bool verify_dh_signature(
    const unsigned char *dh_pubkey, size_t dh_pubkey_len, /* dati firmati da verificare (g^b mod p) */
    const unsigned char *signature, size_t signature_len, /* firma ricevuta dal DSS */
    const std::string &public_key_file = "../public.pem" /* file da cui ricavare chiave pubblica DSS */
    ); 

// Funzione per calcolare la chiave di sessione condivisa
unsigned char *derive_shared_secret(EVP_PKEY *my_keypair, EVP_PKEY *peer_pubkey, size_t &secret_len);

// Funzione per cifratura con AES a 128 bit e MAC
bool aes_encrypt_gcm(
    const unsigned char *key, const unsigned char *plaintext, int plaintext_len,
    const unsigned char *iv, const unsigned char *aad, int aad_len,
    unsigned char *ciphertext, unsigned char *tag, int &ciphertext_len
    );

// Funzione per decifratura con AES a 128 bit e MAC
bool aes_decrypt_gcm(
    const unsigned char *ciphertext, int ciphertext_len,
    const unsigned char *aad, int aad_len,
    const unsigned char *tag,
    const unsigned char *key,
    const unsigned char *iv, int iv_len,
    unsigned char *plaintext, int &plaintext_len, uint64_t max_delay
    );

string hash_password(const string &password);
#endif