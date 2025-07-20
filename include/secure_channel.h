// secure_channel.h

#ifndef SECURE_CHANNEL_H
#define SECURE_CHANNEL_H

#include <string>
#include <vector>
#include <openssl/evp.h>

#define MAX_SKEW 45
// === Funzioni principali client/server ===
// secure_channel.h
/*

static void write_be64(unsigned char *p, uint64_t v);

static uint64_t read_be64(const unsigned char *p);

static bool send_msg(int s, const std::vector<unsigned char>& b); 

static bool recv_msg(int s, std::vector<unsigned char>& b);

static uint64_t gen_nonce();

*/

void resetMessageCounter();
uint32_t getCurrentMessageCounter();

/// Perform the handshake on 'sock', authenticating 'user' with 'pass'.
/// On success, returns 0 *and* sets session_key to your 32‑byte shared key.
/// On failure, returns -1 and session_key is left unspecified.

int apertura_canale_sicuro_client(int sock,
                                  const std::string& user,
                                  const std::string& pass,
                                  std::vector<unsigned char>& session_key);

/// Same for the server side: after this returns 0 you have your session_key.
int apertura_canale_sicuro_server(int sock,
                                  std::vector<unsigned char>& session_key);


// === Logging & utility ===
void log_openssl_errors(const char* filename);

// === Step CLIENT ===
bool client_step1_send_hello(int sock, const std::string& user, uint64_t& n1);
bool client_step2_recv_challenge(int sock, const std::string& pass, uint64_t n1, uint64_t& n2, std::vector<unsigned char>& key);
bool client_step3_send_dh(int sock, const std::string& user, uint64_t n2,
                          const std::vector<unsigned char>& key,
                          EVP_PKEY*& dhk, std::vector<unsigned char>& pubB);
bool client_step4_recv_pubA(int sock, const std::vector<unsigned char>& key,
                            EVP_PKEY*& pubA_out);
bool client_step5_recv_nonce3(int sock, const std::vector<unsigned char>& K, uint64_t& n3);
bool client_step6_send_nonce3plus1(int sock, const std::vector<unsigned char>& K, uint64_t n3);
bool client_step7_recv_result(int sock, const std::vector<unsigned char>& K,
                              bool& success, uint64_t& n3p2);

// === Step SERVER ===
bool server_step1_recv_hello(int sock, uint64_t& n1, std::string& user);
bool server_step2_send_nonce_signature(int sock, const std::string& user, uint64_t n1, uint64_t& n2, std::vector<unsigned char>& key);
bool server_step3_recv_dh_pubB(int sock, const std::string& user, uint64_t n2,
                               const std::vector<unsigned char>& key, std::vector<unsigned char>& pubB);
bool server_step4_send_dh_pubA(int sock, EVP_PKEY*& dhk, const std::vector<unsigned char>& key);
bool server_step5_send_nonce3(int sock, const std::vector<unsigned char>& K, uint64_t& n3);
bool server_step6_recv_nonce3plus1(int sock, const std::vector<unsigned char>& K, uint64_t n3, bool& valid);
bool server_step7_send_final(int sock, const std::vector<unsigned char>& K, uint64_t n3, bool ok);

#endif // SECURE_CHANNEL_H
