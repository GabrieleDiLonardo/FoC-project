// utility.h

#ifndef UTILITY_H
#define UTILITY_H

#include <string>
#include <vector>
#include <openssl/evp.h>
#include <cstddef>
#include <cstdint>
#include "secure_channel.h"
#include <sys/socket.h>
#include <arpa/inet.h>
using namespace std;
#define PORT 8080


// === RSA-OAEP ===
std::vector<unsigned char> rsa_oaep_encrypt(EVP_PKEY* pub, const std::vector<unsigned char>& pt);
std::vector<unsigned char> rsa_oaep_decrypt(EVP_PKEY* priv, const std::vector<unsigned char>& ct);

// === PEM Key Loaders ===
EVP_PKEY* load_public_key(const std::string& file);
EVP_PKEY* load_private_key(const std::string& file);

// === DH (Diffie-Hellman) Key Exchange Helpers ===
EVP_PKEY* generate_dh_params();
EVP_PKEY* generate_dh_keypair(EVP_PKEY* params);
EVP_PKEY* import_dh_pubkey(const unsigned char* pubkey_data, size_t pubkey_len);
unsigned char* derive_shared_secret(EVP_PKEY* priv, EVP_PKEY* peer, size_t& secret_len);

// === Key Derivation Function ===
std::vector<unsigned char> kdf(const std::vector<unsigned char>& shared,
                               const std::string& user,
                               uint64_t n1, uint64_t n2);

// === AES-256-GCM Encryption/Decryption ===
bool aes_encrypt_gcm(const unsigned char* key,
                     const unsigned char* pt, int pt_len,
                     const unsigned char* iv, int iv_len,
                     const unsigned char* aad, int aad_len,
                     unsigned char* ct, unsigned char* tag);

bool aes_decrypt_gcm(const unsigned char* ct, int ct_len,
                     const unsigned char* iv, int iv_len,
                     const unsigned char* tag,
                     const unsigned char* key,
                     const unsigned char* aad, int aad_len,
                     unsigned char* pt);

// === SHA-256 Hashing ===
std::string hash_password(const std::string& pw);
std::vector<unsigned char> hex_to_bytes(const std::string& hex);

// === RSA Sign/Verify ===
bool sign_data(EVP_PKEY* priv,
               const unsigned char* data, size_t data_len,
               unsigned char* sig, size_t& sig_len);

bool verify_signature(EVP_PKEY* pub,
                      const unsigned char* data, size_t data_len,
                      const unsigned char* sig, size_t sig_len);

/*DAL VECCHIO FILE*/
string toHex(const vector<unsigned char> &data);

//WRAPPER
void gen_iv(unsigned char iv[12]);

/// High‑level encrypted send/recv
bool sendEncryptedMessage(int sock,
                          const std::vector<unsigned char>& K,
                          const std::string& plaintext);

bool recvEncryptedMessage(int sock,
                          const std::vector<unsigned char>& K,
                          std::string &out_plain);

void dumpHex(const unsigned char* buf, size_t len, const std::string& title);

#endif // UTILITY_H
