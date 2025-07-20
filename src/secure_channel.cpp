
// secure_channel.cpp (modular version)
#include <openssl/err.h>
#include "utility.h"
#include <openssl/rand.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/dh.h>
#include<ctime>
#include <vector>
#include <iostream>
#include <cstring>
#include <random>
#include <chrono>
#include <string>
#include <openssl/core_names.h>
#include <cstdio>
#include <fstream>  // necessario per std::ofstream
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/bn.h>



void log_openssl_errors(const char* filename) {
    FILE* err = fopen(filename, "a");
    if (err) {
        ERR_print_errors_fp(err);
        fclose(err);
    }
}

static void add_padded_message(std::vector<unsigned char>& dest, 
                             const unsigned char* data, 
                             size_t data_size) {
    // Aggiunge: [4 byte size][data][padding fino a 32 byte]
    uint32_t net_size = htonl(static_cast<uint32_t>(data_size));
    dest.insert(dest.end(), (unsigned char*)&net_size, (unsigned char*)&net_size + 4);
    dest.insert(dest.end(), data, data + data_size);
    
    // Calcola padding necessario (almeno 32 byte totali)
    size_t total_size = 4 + data_size;
    size_t padding_needed = total_size >= 32 ? 0 : 32 - total_size;
    
    // Aggiungi padding casuale
    std::random_device rd;
    std::uniform_int_distribution<unsigned char> dist(0, 255);
    for (size_t i = 0; i < padding_needed; ++i) {
        dest.push_back(dist(rd));
    }
}

static bool extract_padded_message(const std::vector<unsigned char>& src,
                                 std::vector<unsigned char>& dest) {
    
    if (src.size() < 4) return false;
    
    uint32_t net_size;
    memcpy(&net_size, src.data(), 4);
    size_t data_size = ntohl(net_size);
    
    if (4 + data_size > src.size()) return false;
    
    dest.assign(src.begin() + 4, src.begin() + 4 + data_size);
    return true;
}




// === Helpers ===
static void write_be64(unsigned char *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (v >> (56 - 8 * i)) & 0xFF;
}
static uint64_t read_be64(const unsigned char *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= uint64_t(p[i]) << (56 - 8 * i);
    return v;
}

static bool send_msg(int s, const std::vector<unsigned char>& b) {
    uint32_t n = htonl((uint32_t)b.size());
    if (send(s, &n, 4, MSG_NOSIGNAL) != 4) return false;
    size_t off = 0;
    while (off < b.size()) {
        ssize_t w = send(s, b.data() + off, b.size() - off, MSG_NOSIGNAL);
        if (w <= 0) return false;
        off += w;
    }
    return true;
}

static bool recv_msg(int s, std::vector<unsigned char>& b) {
    uint32_t nl;
    if (recv(s, &nl, 4, MSG_WAITALL) != 4) return false;
    uint32_t l = ntohl(nl);
    if (l == 0 || l > 16 * 1024 * 1024) return false;
    b.resize(l);
    return recv(s, b.data(), l, MSG_WAITALL) == (ssize_t)l;
}

static uint64_t gen_nonce() {
    static std::mt19937_64 rng{ std::random_device{}() };
    return rng();
}


static constexpr char HELLO_MARKER[] = "HELLO";
static constexpr int HELLO_LEN = sizeof(HELLO_MARKER) - 1;

#include <fstream>
#include <random>
#include <string>
#include "utility.h"   // for hash_password

static std::string get_password_or_dummy(const std::string& username) {
    const std::string path = "users/" + username + ".txt";
    std::ifstream file(path);
    if (file.is_open()) {
        std::string line;
        if (std::getline(file, line)) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                std::string register_hashed_password = line.substr(pos + 1);
                
                register_hashed_password.erase(
                    0,
                    register_hashed_password.find_first_not_of(" \t")
                );
                return register_hashed_password;
            }
        }
        
    }

    
    // Create 16 random bytes (the "plain" dummy password)
    std::random_device rd;
    std::mt19937_64 rng(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    std::string random_plain;
    random_plain.reserve(16);
    for (int i = 0; i < 16; ++i) {
        random_plain.push_back(static_cast<char>(dist(rng)));
    }

    // Hash it
    return hash_password(random_plain);
}

  

// --- CLIENT STEP 1: HELLO || nonce1 || user ---
bool client_step1_send_hello(int sock, const std::string& user, uint64_t& n1) {
    n1 = gen_nonce();
    std::vector<unsigned char> pt;
    pt.insert(pt.end(), (unsigned char*)HELLO_MARKER, (unsigned char*)HELLO_MARKER + HELLO_LEN);
    unsigned char buf[8]; write_be64(buf, n1);
    pt.insert(pt.end(), buf, buf + 8);
    pt.insert(pt.end(), user.begin(), user.end());

    EVP_PKEY* spub = load_public_key("keys/server_pub.pem");
    if (!spub) return false;
    auto ct = rsa_oaep_encrypt(spub, pt);
    EVP_PKEY_free(spub);
    
    return send_msg(sock, ct);
}


// --- CLIENT STEP 2: Receive AES-GCM(n1, n2, ts), verify ---
bool client_step2_recv_challenge(int sock, const std::string& pass, uint64_t n1,
                                 uint64_t& n2, std::vector<unsigned char>& key) {
    
    
    std::vector<unsigned char> b2;
    if (!recv_msg(sock, b2)) return false;

    size_t offset = 0;
    uint32_t sl2 = ntohl(*(uint32_t*)&b2[offset]); offset += 4;
    std::vector<unsigned char> sig(b2.begin() + offset, b2.begin() + offset + sl2); offset += sl2;
    unsigned char iv[12], tag[16];
    memcpy(iv, &b2[offset], 12); offset += 12;
    memcpy(tag, &b2[offset], 16); offset += 16;
    std::vector<unsigned char> ct(b2.begin() + offset, b2.end());

    EVP_PKEY* spub = load_public_key("keys/server_pub.pem");
    if (!verify_signature(spub, ct.data(), ct.size(), sig.data(), sl2)) return false;
    EVP_PKEY_free(spub);

    key = hex_to_bytes(pass);
    std::vector<unsigned char> pt(ct.size());
    if (!aes_decrypt_gcm(ct.data(), ct.size(), iv, 12, tag, key.data(), iv, 12, pt.data()))
        return false;

    uint64_t rn1 = read_be64(pt.data());
    n2 = read_be64(pt.data() + 8);
    uint64_t ts = read_be64(pt.data() + 16);

    std::time_t now = std::time(nullptr);
    const int64_t max_skew = MAX_SKEW;

    if (std::abs((int64_t)(ts - now)) > max_skew) {
        return false;
    }

    return (rn1 == n1);
}

// --- CLIENT STEP 3: DH gen, send AES(user || n2 || pubB) ---
bool client_step3_send_dh(int sock, const std::string& user, uint64_t n2,
                         const std::vector<unsigned char>& key,
                         EVP_PKEY*& dhk, std::vector<unsigned char>& pubB) {
    // Genera i parametri DH (ffdhe2048)
    EVP_PKEY* dhp = generate_dh_params();
    if (!dhp) {
        std::cout << "[DBG CLIENT] Failed to generate DH params\n";
        return false;
    }

    // Genera la chiave DH
    dhk = generate_dh_keypair(dhp);
    EVP_PKEY_free(dhp);  // Libera i parametri, ora abbiamo la chiave
    if (!dhk) {
        std::cout << "[DBG CLIENT] Failed to generate DH keypair\n";
        return false;
    }
    if (EVP_PKEY_id(dhk) != EVP_PKEY_DH) {
        std::cout << "[DBG CLIENT] Not a DH key\n";
        EVP_PKEY_free(dhk);
        return false;
    }

    // Estrai la chiave pubblica come BIGNUM
    BIGNUM *pub_key = nullptr;
    if (EVP_PKEY_get_bn_param(dhk, "pub", &pub_key) != 1) {
        std::cout << "[DBG CLIENT] Failed to get DH public key (BN)\n";
        EVP_PKEY_free(dhk);
        return false;
    }

    // Converti BIGNUM in array di byte
    pubB.resize(BN_num_bytes(pub_key));
    BN_bn2bin(pub_key, pubB.data());
    BN_free(pub_key);  // Libera la memoria del BIGNUM

    
    // Costruisci il messaggio plaintext: user || n2 || pubB
    std::vector<unsigned char> pt(user.begin(), user.end());
    unsigned char buf[8];
    write_be64(buf, n2);
    pt.insert(pt.end(), buf, buf + 8);
    pt.insert(pt.end(), pubB.begin(), pubB.end());

    // Cifra il messaggio con AES-GCM
    unsigned char iv[12], tag[16];
    gen_iv(iv);
    std::vector<unsigned char> ct(pt.size());
    aes_encrypt_gcm(key.data(), pt.data(), pt.size(), iv, 12, iv, 12, ct.data(), tag);

    // Costruisci il messaggio finale: IV (12) || TAG (16) || CIPHERTEXT
    std::vector<unsigned char> msg;
    msg.insert(msg.end(), iv, iv + 12);
    msg.insert(msg.end(), tag, tag + 16);
    msg.insert(msg.end(), ct.begin(), ct.end());

    return send_msg(sock, msg);
}



bool client_step4_recv_pubA(int sock, const std::vector<unsigned char>& key,
                          EVP_PKEY*& pubA_out) {
    std::vector<unsigned char> encrypted_msg;
    if (!recv_msg(sock, encrypted_msg)) return false;

    if (encrypted_msg.size() < 28) return false; // IV + TAG

    unsigned char iv[12], tag[16];
    memcpy(iv, encrypted_msg.data(), 12);
    memcpy(tag, encrypted_msg.data() + 12, 16);
    std::vector<unsigned char> ct(encrypted_msg.begin() + 28, encrypted_msg.end());
    
    // Decifra
    std::vector<unsigned char> pt(ct.size());
    const std::string aad = "STEP4";
    if (!aes_decrypt_gcm(ct.data(), ct.size(), iv, 12, tag, key.data(),
                        (const unsigned char*)aad.data(), aad.size(), pt.data()))
        return false;

    // Estrai la chiave pubblica dal messaggio strutturato
    std::vector<unsigned char> pub_key_data;
    if (!extract_padded_message(pt, pub_key_data)) {
        std::cerr << "[ERROR] Invalid pubA format\n";
        return false;
    }

    // Importa la chiave pubblica DH (solo dati utili, senza padding)
    pubA_out = import_dh_pubkey(pub_key_data.data(), pub_key_data.size());
    if (!pubA_out) {
        std::cerr << "[ERROR] Failed to import DH public key\n";
        ERR_print_errors_fp(stderr);
        return false;
    }

    return true;
}
// --- CLIENT STEP 5: recv AES(n3) ---
bool client_step5_recv_nonce3(int sock, const std::vector<unsigned char>& K, uint64_t& n3) {
    std::vector<unsigned char> b5;
    if (!recv_msg(sock, b5)) return false;

    if (b5.size() < 60) return false; // IV(12) + TAG(16) + 32 byte ciphertext

    unsigned char iv[12], tag[16];
    memcpy(iv, b5.data(), 12);
    memcpy(tag, b5.data() + 12, 16);
    std::vector<unsigned char> ct(b5.begin() + 28, b5.end());
    
    // Decifra
    std::vector<unsigned char> pt(ct.size());
    const std::string aad = "STEP5";
    if (!aes_decrypt_gcm(ct.data(), ct.size(), iv, 12, tag, K.data(),
                        (const unsigned char*)aad.data(), aad.size(), pt.data()))
        return false;

    // Estrai il nonce dal messaggio strutturato
    std::vector<unsigned char> nonce_data;
    if (!extract_padded_message(pt, nonce_data) || nonce_data.size() != 8) {
        std::cerr << "[ERROR] Invalid nonce3 format\n";
        return false;
    }

    n3 = read_be64(nonce_data.data());
    return true;
}
// --- CLIENT STEP 6: send AES(n3+1) ---
bool client_step6_send_nonce3plus1(int sock, const std::vector<unsigned char>& K, uint64_t n3) {
    uint64_t n3p = n3 + 1;
    unsigned char n3p_buf[8];
    write_be64(n3p_buf, n3p);

    // Costruisci plaintext strutturato
    std::vector<unsigned char> pt;
    add_padded_message(pt, n3p_buf, 8); // Aggiunge size(8) + data + padding

    // Cifra
    unsigned char iv[12], tag[16];
    gen_iv(iv);
    std::vector<unsigned char> ct(pt.size());
    const std::string aad = "STEP6";
    if (!aes_encrypt_gcm(K.data(), pt.data(), pt.size(), iv, 12,
                        (const unsigned char*)aad.data(), aad.size(), ct.data(), tag))
        return false;

    // Costruisci messaggio finale
    std::vector<unsigned char> msg;
    msg.insert(msg.end(), iv, iv + 12);
    msg.insert(msg.end(), tag, tag + 16);
    msg.insert(msg.end(), ct.begin(), ct.end());
    
    return send_msg(sock, msg);
}

// --- CLIENT STEP 7: recv AES("OK"/"RETRY" || n3+2), verify signature ---
bool client_step7_recv_result(int sock, const std::vector<unsigned char>& K,
                            bool& success, uint64_t& n3p2) {
    std::vector<unsigned char> b7;
    if (!recv_msg(sock, b7)) return false;

    size_t offset = 0;
    uint32_t sig_len = ntohl(*(uint32_t*)&b7[offset]); offset += 4;
    std::vector<unsigned char> sig(b7.begin() + offset, b7.begin() + offset + sig_len); offset += sig_len;

    unsigned char iv[12], tag[16];
    memcpy(iv, b7.data() + offset, 12); offset += 12;
    memcpy(tag, b7.data() + offset, 16); offset += 16;
    std::vector<unsigned char> ct(b7.begin() + offset, b7.end());

    // Verifica firma
    EVP_PKEY* spub = load_public_key("keys/server_pub.pem");
    if (!verify_signature(spub, ct.data(), ct.size(), sig.data(), sig_len)) {
        EVP_PKEY_free(spub);
        return false;
    }
    EVP_PKEY_free(spub);

    // Decifra
    std::vector<unsigned char> pt(ct.size());
    const std::string aad = "STEP7";
    if (!aes_decrypt_gcm(ct.data(), ct.size(), iv, 12, tag, K.data(),
                        (const unsigned char*)aad.data(), aad.size(), pt.data()))
        return false;

    // Estrai risultato
    std::vector<unsigned char> result_data;
    if (!extract_padded_message(pt, result_data) || result_data.size() < 10) {
        std::cerr << "[ERROR] Invalid result format\n";
        return false;
    }

    success = (result_data[0] == 'O' && result_data[1] == 'K');
    n3p2 = read_be64(result_data.data() + 2);
    return true;
}
int apertura_canale_sicuro_client(int sock, const std::string& user, const std::string& pass, std::vector<unsigned char>& session_key) {
    //std::cout << "[DBG CLIENT] Starting secure channel setup\n";
    
    // Inizializza tutte le variabili
    uint64_t n1 = 0, n2 = 0, n3 = 0;
    std::vector<unsigned char> key;
    EVP_PKEY* dhk = nullptr;
    EVP_PKEY* pubA = nullptr;
    std::vector<unsigned char> pubB;
    unsigned char* sec = nullptr;
    int ret = -1; // Valore di ritorno di default (errore)
    bool success = false;
    uint64_t n3p2 = 0;

    try {
        // Step 1: Invia HELLO + n1 + username
        if (!client_step1_send_hello(sock, user, n1)) {
            throw std::runtime_error("Client failed");
        }

        // Step 2: Ricevi e verifica la sfida
        if (!client_step2_recv_challenge(sock, pass, n1, n2, key)) {
            throw std::runtime_error("Client failed");
        }

        // Step 3: Genera e invia chiave DH
        if (!client_step3_send_dh(sock, user, n2, key, dhk, pubB)) {
            throw std::runtime_error("Client failed");
        }

        // Step 4: Ricevi chiave pubblica DH del server
        if (!client_step4_recv_pubA(sock, key, pubA)) {
            throw std::runtime_error("Client failed");
        }
        

        // Calcola segreto condiviso
        size_t slen = 0;
        sec = derive_shared_secret(dhk, pubA, slen);
        if (!sec || slen == 0) {
            std::cerr << "[ERROR CLIENT] Shared secret derivation failed\n";
            throw std::runtime_error("Shared secret failed");
        }

        // Deriva la chiave di sessione
        std::vector<unsigned char> K;
        try {
            K = kdf({sec, sec + slen}, user, n1, n2);
            if (K.empty()) {
                throw std::runtime_error("Empty KDF result");
            }
        } catch (const std::exception& e) {
            //std::cerr << "[ERROR CLIENT] KDF failed: " << e.what() << "\n";
            throw;
        }

        // Step 5: Ricevi nonce3 dal server
        if (!client_step5_recv_nonce3(sock, K, n3)) {
            ;
            throw std::runtime_error("handshake failed");
        }

        // Step 6: Invia nonce3+1 al server
        if (!client_step6_send_nonce3plus1(sock, K, n3)) {
            
            throw std::runtime_error("handshake failed");
        }

        // Step 7: Ricevi risultato finale
        if (!client_step7_recv_result(sock, K, success, n3p2)) {
            
            throw std::runtime_error("handshake failed");
        }

        if (!success) {
            //std::cerr << "[WARN CLIENT] Server requested handshake retry\n";
            ret = -1;
        } else {
            //std::cout << "[DBG CLIENT] Handshake completed successfully\n";
            session_key = std::move(K);
            ret = 0;
        }
    } catch (const std::exception& e) {
        //std::cerr << "[FATAL CLIENT] Exception during handshake: " << e.what() << "\n";
        ret = -1;
    }

    // Pulizia delle risorse
    if (sec) OPENSSL_free(sec);
    if (pubA) EVP_PKEY_free(pubA);
    if (dhk) EVP_PKEY_free(dhk);


    return ret;
}


bool server_step1_recv_hello(int sock, uint64_t& n1, std::string& user) {
    std::vector<unsigned char> b1;
    if (!recv_msg(sock, b1)) return false;

    EVP_PKEY* priv = load_private_key("keys/server_priv.pem");
    auto pt1 = rsa_oaep_decrypt(priv, b1);
    EVP_PKEY_free(priv);

    n1 = read_be64(pt1.data() + HELLO_LEN);
    user.assign((char*)pt1.data() + HELLO_LEN + 8, pt1.size() - HELLO_LEN - 8);

    return true;
}

bool server_step2_send_nonce_signature(int sock, const std::string& user, uint64_t n1, uint64_t& n2, std::vector<unsigned char>& key) {

    key = hex_to_bytes(get_password_or_dummy(user));
    n2 = gen_nonce();
    uint64_t ts = std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::system_clock::now().time_since_epoch()).count();

    std::vector<unsigned char> pt2(24);
    write_be64(pt2.data(), n1);
    write_be64(pt2.data() + 8, n2);
    write_be64(pt2.data() + 16, ts);

    unsigned char iv2[12], tag2[16];
    gen_iv(iv2);
    std::vector<unsigned char> ct2(24);
    aes_encrypt_gcm(key.data(), pt2.data(), 24, iv2, 12, iv2, 12, ct2.data(), tag2);

    EVP_PKEY* priv = load_private_key("keys/server_priv.pem");
    std::vector<unsigned char> sig2(512);
    size_t sl2;
    sign_data(priv, ct2.data(), 24, sig2.data(), sl2);
    EVP_PKEY_free(priv);

    std::vector<unsigned char> o2;
    uint32_t net_sl2 = htonl((uint32_t)sl2);
    o2.insert(o2.end(), (unsigned char*)&net_sl2, (unsigned char*)&net_sl2 + 4);
    o2.insert(o2.end(), sig2.begin(), sig2.begin() + sl2);
    o2.insert(o2.end(), iv2, iv2 + 12);
    o2.insert(o2.end(), tag2, tag2 + 16);
    o2.insert(o2.end(), ct2.begin(), ct2.end());
    send_msg(sock, o2);

    return true;
}

bool server_step3_recv_dh_pubB(int sock, const std::string& user, uint64_t n2, const std::vector<unsigned char>& key,
                                std::vector<unsigned char>& pubB) {
    std::vector<unsigned char> b3;
    if (!recv_msg(sock, b3)) return false;

    unsigned char iv3[12], tag3[16];
    memcpy(iv3, b3.data(), 12);
    memcpy(tag3, b3.data() + 12, 16);
    std::vector<unsigned char> ct3(b3.begin() + 28, b3.end());
    std::vector<unsigned char> pt3(ct3.size());
    aes_decrypt_gcm(ct3.data(), ct3.size(), iv3, 12, tag3, key.data(), iv3, 12, pt3.data());

    uint64_t rn2 = read_be64(pt3.data() + user.size());
    if (rn2 != n2) {
        std::cerr << "[ERROR SERVER] nonce2 mismatch\n";
        return false;
    }

    pubB.assign(pt3.begin() + user.size() + 8, pt3.end());
    return true;
}
// --- SERVER STEP 4: Send AES(pubA) ---
bool server_step4_send_dh_pubA(int sock, EVP_PKEY*& dhk, 
                              const std::vector<unsigned char>& key) {

    EVP_PKEY* dh_params = generate_dh_params();
    if (!dh_params) return false;
    dhk = generate_dh_keypair(dh_params);
    EVP_PKEY_free(dh_params);
    if (!dhk) return false;
    // Estrai chiave pubblica
    BIGNUM* pub_key = nullptr;
    if (EVP_PKEY_get_bn_param(dhk, "pub", &pub_key) != 1) {
        EVP_PKEY_free(dhk);
        return false;
    }

    // Converti in formato binario
    std::vector<unsigned char> pub_key_data(BN_num_bytes(pub_key));
    BN_bn2bin(pub_key, pub_key_data.data());
    BN_free(pub_key);

    // Costruisci plaintext strutturato
    std::vector<unsigned char> pt;
    add_padded_message(pt, pub_key_data.data(), pub_key_data.size());

    // Cifra
    unsigned char iv[12], tag[16];
    gen_iv(iv);
    std::vector<unsigned char> ct(pt.size());
    const std::string aad = "STEP4";
    if (!aes_encrypt_gcm(key.data(), pt.data(), pt.size(), iv, 12,
                        (const unsigned char*)aad.data(), aad.size(), ct.data(), tag))
        return false;

    // Costruisci messaggio finale
    std::vector<unsigned char> msg;
    msg.insert(msg.end(), iv, iv + 12);
    msg.insert(msg.end(), tag, tag + 16);
    msg.insert(msg.end(), ct.begin(), ct.end());
    
    return send_msg(sock, msg);
}
// --- SERVER STEP 5: Send AES(n3) ---
bool server_step5_send_nonce3(int sock, const std::vector<unsigned char>& K, uint64_t& n3) {
    n3 = gen_nonce();
    unsigned char n3_buf[8];
    write_be64(n3_buf, n3);

    // Costruisci plaintext strutturato
    std::vector<unsigned char> pt;
    add_padded_message(pt, n3_buf, 8);

    // Cifra
    unsigned char iv[12], tag[16];
    gen_iv(iv);
    std::vector<unsigned char> ct(pt.size());
    const std::string aad = "STEP5";
    if (!aes_encrypt_gcm(K.data(), pt.data(), pt.size(), iv, 12,
                        (const unsigned char*)aad.data(), aad.size(), ct.data(), tag))
        return false;

    // Costruisci messaggio finale
    std::vector<unsigned char> msg;
    msg.insert(msg.end(), iv, iv + 12);
    msg.insert(msg.end(), tag, tag + 16);
    msg.insert(msg.end(), ct.begin(), ct.end());
    
    return send_msg(sock, msg);
}

// --- SERVER STEP 6: Receive AES(n3+1) ---
bool server_step6_recv_nonce3plus1(int sock, const std::vector<unsigned char>& K, uint64_t n3, bool& valid) {
    std::vector<unsigned char> b;
    if (!recv_msg(sock, b)) return false;

    if (b.size() < 60) return false; // IV(12) + TAG(16) + 32 byte ciphertext

    unsigned char iv[12], tag[16];
    memcpy(iv, b.data(), 12);
    memcpy(tag, b.data() + 12, 16);
    std::vector<unsigned char> ct(b.begin() + 28, b.end());
    
    // Decifra
    std::vector<unsigned char> pt(ct.size());
    const std::string aad = "STEP6";
    if (!aes_decrypt_gcm(ct.data(), ct.size(), iv, 12, tag, K.data(),
                        (const unsigned char*)aad.data(), aad.size(), pt.data()))
        return false;

    // Estrai il nonce+1
    std::vector<unsigned char> nonce_data;
    if (!extract_padded_message(pt, nonce_data) || nonce_data.size() != 8) {
        std::cerr << "[ERROR] Invalid nonce3+1 format\n";
        return false;
    }

    uint64_t received = read_be64(nonce_data.data());
    valid = (received == n3 + 1);
    return true;
}
// --- SERVER STEP 7: Send AES("OK"/"RETRY" || n3+2) + signature ---
bool server_step7_send_final(int sock, const std::vector<unsigned char>& K, uint64_t n3, bool ok) {
    const char* res = ok ? "OK" : "RETRY";
    uint64_t n3p2 = n3 + 2;
    
    // Costruisci messaggio
    unsigned char result_msg[10];
    memcpy(result_msg, res, 2);
    write_be64(result_msg + 2, n3p2);

    // Costruisci plaintext strutturato
    std::vector<unsigned char> pt;
    add_padded_message(pt, result_msg, 10);

    // Cifra
    unsigned char iv[12], tag[16];
    gen_iv(iv);
    std::vector<unsigned char> ct(pt.size());
    const std::string aad = "STEP7";
    if (!aes_encrypt_gcm(K.data(), pt.data(), pt.size(), iv, 12,
                        (const unsigned char*)aad.data(), aad.size(), ct.data(), tag))
        return false;

    // Firma il ciphertext
    EVP_PKEY* priv = load_private_key("keys/server_priv.pem");
    std::vector<unsigned char> sig(512);
    size_t siglen;
    sign_data(priv, ct.data(), ct.size(), sig.data(), siglen);
    EVP_PKEY_free(priv);

    // Costruisci messaggio finale
    std::vector<unsigned char> msg;
    uint32_t net_siglen = htonl(static_cast<uint32_t>(siglen));
    msg.insert(msg.end(), (unsigned char*)&net_siglen, (unsigned char*)&net_siglen + 4);
    msg.insert(msg.end(), sig.begin(), sig.begin() + siglen);
    msg.insert(msg.end(), iv, iv + 12);
    msg.insert(msg.end(), tag, tag + 16);
    msg.insert(msg.end(), ct.begin(), ct.end());
    
    return send_msg(sock, msg);
}
int apertura_canale_sicuro_server(int sock, std::vector<unsigned char>& session_key) {
    //std::cout << "[DBG SERVER] Starting secure channel setup\n";

    // Inizializza tutte le variabili
    uint64_t n1 = 0, n2 = 0, n3 = 0;
    std::string user;
    std::vector<unsigned char> key;
    std::vector<unsigned char> pubB;
    EVP_PKEY* dhk = nullptr;
    EVP_PKEY* pubB_key = nullptr;
    unsigned char* sec = nullptr;
    int ret = -1; // Valore di ritorno di default (errore)

    try {
        // Step 1: ricevi HELLO + n1 + username
        if (!server_step1_recv_hello(sock, n1, user)) {
            ret = -1;
        }

        // Step 2: invia E(Hash(p), n1||n2||ts) + firma
        if (!server_step2_send_nonce_signature(sock, user, n1, n2, key)) {
            ret = -1;
        }

        // Step 3: ricevi E(username || n2 || pubB)
        if (!server_step3_recv_dh_pubB(sock, user, n2, key, pubB)) {
            ret = -1;
        }

        // Step 4: genera e invia DH pubA
        if (!server_step4_send_dh_pubA(sock, dhk, key)) {
            ret = -1;
        }

        
        pubB_key = import_dh_pubkey(pubB.data(), pubB.size());
        
        if (!pubB_key ) {                   
            throw std::runtime_error("Invalid client DH key");
        }

        // Calcola segreto condiviso
        size_t slen = 0;
        sec = derive_shared_secret(dhk, pubB_key, slen);
        if (!sec || slen == 0) {
            std::cerr << "[ERROR SERVER] Shared secret derivation failed\n";
            throw std::runtime_error("Shared secret failed");
        }

        // Deriva la chiave di sessione
        std::vector<unsigned char> K;
        try {
            K = kdf({sec, sec + slen}, user, n1, n2);
            if (K.empty()) {
                throw std::runtime_error("Empty KDF result");
            }
        } catch (const std::exception& e) {
            std::cerr << "[ERROR SERVER] KDF failed: " << e.what() << "\n";
            throw;
        }

        // Step 5: invia E(K, nonce3)
        if (!server_step5_send_nonce3(sock, K, n3)) {
            ret = -1;
            
        }

        // Step 6: ricevi E(K, nonce3 + 1)
        bool valid_n3 = false;
        if (!server_step6_recv_nonce3plus1(sock, K, n3, valid_n3)) {
            ret = -1;
            
        }

        // Step 7: invia E(K, OK/RETRY || nonce3+2) + firma
        if (!server_step7_send_final(sock, K, n3, valid_n3)) {
            ret = -1;
            
        }

        if (valid_n3) {
            session_key = std::move(K);
            ret = 0; // Successo
        } else {
            ret = -1; // Fallimento
        }
    } catch (const std::exception& e) {
        
        ret = -1;
    }

    // Pulizia delle risorse
    if (sec) OPENSSL_free(sec);
    if (pubB_key) EVP_PKEY_free(pubB_key);
    if (dhk) EVP_PKEY_free(dhk);

    

    return ret;
}
