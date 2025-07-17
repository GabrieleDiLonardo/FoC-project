
// secure_channel.cpp (modular version)
#include <openssl/err.h>
#include "utility.h"
#include <openssl/rand.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/dh.h>
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

/*static void gen_iv(unsigned char iv[12]) {
    if (RAND_bytes(iv, 12) != 1) {
        std::cerr << "[FATAL] RAND_bytes failed \n";
        std::abort();
    }
}*/

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
                // trim leading whitespace
                register_hashed_password.erase(
                    0,
                    register_hashed_password.find_first_not_of(" \t")
                );
                return register_hashed_password;
            }
        }
        // malformed file → fall back to dummy
    }

    // --- File missing or malformed: generate a dummy password ---
    // 1) Create 16 random bytes (the "plain" dummy password)
    std::random_device rd;
    std::mt19937_64 rng(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    std::string random_plain;
    random_plain.reserve(16);
    for (int i = 0; i < 16; ++i) {
        random_plain.push_back(static_cast<char>(dist(rng)));
    }

    // 2) Hash it exactly as real passwords are hashed
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
    std::cout << "[DBG CLIENT] Step1 nonce=" << n1 << "\n";
    return send_msg(sock, ct);
}


// --- CLIENT STEP 2: Receive AES-GCM(n1, n2, ts), verify ---
bool client_step2_recv_challenge(int sock, const std::string& pass, uint64_t n1,
                                 uint64_t& n2, std::vector<unsigned char>& key) {
    
    std::cout << "[DBG CLIENT] Step2 \n";
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
    std::cout << "[DBG CLIENT] Step2 rn1=" << rn1 << " n2=" << n2 << " ts=" << ts << "\n";
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

    // Debug
    std::cout << "[DBG CLIENT] pubB.length = " << pubB.size() << "\n";

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
    std::cout << "[DBG CLIENT] Step4: receiving server's DH public key\n";

    // Ricevi il messaggio cifrato
    std::vector<unsigned char> encrypted_msg;
    if (!recv_msg(sock, encrypted_msg)) {
        std::cerr << "[ERROR CLIENT] Failed to receive encrypted message\n";
        return false;
    }

    // Verifica dimensione minima (IV + TAG)
    if (encrypted_msg.size() < 28) {  // 12 (IV) + 16 (TAG)
        std::cerr << "[ERROR CLIENT] Message too short\n";
        return false;
    }

    // Estrai componenti
    unsigned char iv[12], tag[16];
    memcpy(iv, encrypted_msg.data(), 12);
    memcpy(tag, encrypted_msg.data() + 12, 16);
    std::vector<unsigned char> ct(encrypted_msg.begin() + 28, encrypted_msg.end());
    std::vector<unsigned char> pt(ct.size());

    // Decifra il messaggio
    
    if (!aes_decrypt_gcm(
        ct.data(),                     // ciphertext
        static_cast<int>(ct.size()),  // lunghezza ciphertext
        iv,                            // IV
        12,                            // lunghezza IV
        tag,                           // TAG
        key.data(),                    // chiave
        iv,                            // AAD (usiamo IV come AAD)
        12,                            // lunghezza AAD
        pt.data())) {                  // output buffer
        std::cerr << "[ERROR CLIENT] Decryption failed\n";
        return false;
    }


    // DEBUG: Stampa i byte ricevuti
    std::cout << "[DBG CLIENT] Decrypted DH public key (" << pt.size() << " bytes): ";
    for (size_t i = 0; i < std::min(pt.size(), (size_t)16); ++i) {
        printf("%02x ", pt[i]);
    }
    std::cout << (pt.size() > 16 ? "..." : "") << "\n";

    // Importa la chiave pubblica DH
    EVP_PKEY* imported_key = import_dh_pubkey(pt.data(), pt.size());
    if (!imported_key) {
        std::cerr << "[ERROR CLIENT] Critical: Failed to import DH public key\n";
        ERR_print_errors_fp(stderr);
        
        // DEBUG aggiuntivo
        if (pt.empty()) {
            std::cerr << "[DEBUG] Empty public key data received\n";
        } else {
            std::cerr << "[DEBUG] Public key data looks invalid or corrupted\n";
        }
        
        return false;
    }

    // Verifica che la chiave importata sia effettivamente DH
    if (EVP_PKEY_id(imported_key) != EVP_PKEY_DH) {
        std::cerr << "[ERROR CLIENT] Imported key is not a DH key\n";
        EVP_PKEY_free(imported_key);
        return false;
    }

    pubA_out = imported_key;
    std::cout << "[DBG CLIENT] Successfully imported server's public DH key\n";
    return true;
}


// --- CLIENT STEP 5: recv AES(n3) ---
bool client_step5_recv_nonce3(int sock, const std::vector<unsigned char>& K, uint64_t& n3) {
    // Ricevi il messaggio (dovrebbe essere IV + TAG + CIPHERTEXT)
    std::vector<unsigned char> b5;
    if (!recv_msg(sock, b5)) {
        std::cerr << "[ERROR CLIENT] Failed to receive message\n";
        return false;
    }

    // Verifica dimensione minima (IV 12 + TAG 16 + almeno 8 byte ciphertext)
    if (b5.size() < 36) {  // 12 (IV) + 16 (TAG) + 8 (minimo per un nonce)
        std::cerr << "[ERROR CLIENT] Message too short. Received: " << b5.size() << " bytes\n";
        return false;
    }

    // Estrai componenti
    unsigned char iv[12], tag[16];
    memcpy(iv, b5.data(), 12);
    memcpy(tag, b5.data() + 12, 16);
    std::vector<unsigned char> ct(b5.begin() + 28, b5.end());

    // DEBUG: Stampa le dimensioni
    std::cout << "[DEBUG] Received: IV=12, TAG=16, CT=" << ct.size() << " bytes\n";

    // Buffer per il plaintext (dovremmo aspettarci 8 byte per un uint64_t)
    unsigned char pt[8];
    
    // Decifra con controlli aggiuntivi
    if (!aes_decrypt_gcm(ct.data(),       // ciphertext
                        ct.size(),        // ciphertext length
                        iv,               // IV
                        12,               // IV length
                        tag,              // authentication tag
                        K.data(),         // key
                        iv,               // AAD (usiamo IV come Additional Auth Data)
                        12,               // AAD length
                        pt)) {            // output buffer
        std::cerr << "[ERROR CLIENT] Decryption failed. Possible causes:\n"
                 << " - Invalid/Mismatched key\n"
                 << " - Corrupted data\n"
                 << " - Authentication failure (wrong tag)\n";
        ERR_print_errors_fp(stderr);  // Mostra eventuali errori OpenSSL
        return false;
    }

    // Converti il plaintext in uint64_t (big-endian)
    n3 = read_be64(pt);
    std::cout << "[DBG CLIENT] Step5 successfully decrypted n3=" << n3 << "\n";
    return true;
}

// --- CLIENT STEP 6: send AES(n3+1) ---
bool client_step6_send_nonce3plus1(int sock, const std::vector<unsigned char>& K, uint64_t n3) {
    uint64_t n3p = n3 + 1;
    unsigned char pt[8]; write_be64(pt, n3p);

    unsigned char iv[12], tag[16], ct[8];
    gen_iv(iv);
    aes_encrypt_gcm(K.data(), pt, 8, iv, 12, iv, 12, ct, tag);

    std::vector<unsigned char> msg(iv, iv + 12);
    msg.insert(msg.end(), tag, tag + 16);
    msg.insert(msg.end(), ct, ct + 8);
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

    EVP_PKEY* spub = load_public_key("keys/server_pub.pem");
    if (!verify_signature(spub, ct.data(), ct.size(), sig.data(), sig_len)) return false;
    EVP_PKEY_free(spub);

    std::vector<unsigned char> pt(ct.size());
    if (!aes_decrypt_gcm(ct.data(), ct.size(), iv, 12, tag, K.data(), iv, 12, pt.data()))
        return false;

    success = (pt[0] == 'O');
    n3p2 = read_be64(pt.data() + 2);
    std::cout << "[DBG CLIENT] Step7 OK=" << success << " n3+2=" << n3p2 << "\n";
    return true;
}

int apertura_canale_sicuro_client(int sock, const std::string& user, const std::string& pass, std::vector<unsigned char>& session_key) {
    std::cout << "[DBG CLIENT] Start\n";
    std::cout << "[DBG CLIENT] Username = "<< user << ",Password = "<< pass <<"\n";
    uint64_t n1;
    if (!client_step1_send_hello(sock, user, n1)) return -1;

    uint64_t n2;
    std::vector<unsigned char> key;
    if (!client_step2_recv_challenge(sock, pass, n1, n2, key)) return -1;

    EVP_PKEY* dhk = nullptr;
    std::vector<unsigned char> pubB;
    if (!client_step3_send_dh(sock, user, n2, key, dhk, pubB)) return -1;
    std::cout <<"[DBG CLIENT] step3\n";
    EVP_PKEY* pubA = nullptr;
    if (!client_step4_recv_pubA(sock, key, pubA)) return -1;
    std::cout <<"[DBG CLIENT] step4\n";
    // derive shared secret
    size_t slen;
    unsigned char* sec = derive_shared_secret(dhk, pubA, slen);
    std::vector<unsigned char> K = kdf({sec, sec + slen}, user, n1, n2);
    OPENSSL_free(sec);
    EVP_PKEY_free(pubA);
    EVP_PKEY_free(dhk);

    uint64_t n3;
    if (!client_step5_recv_nonce3(sock, K, n3)) return -1;
    std::cout <<"[DBG CLIENT] step5\n";
    if (!client_step6_send_nonce3plus1(sock, K, n3)) return -1;
    std::cout <<"[DBG CLIENT] step6 \n";
    bool success;
    uint64_t n3p2;
    if (!client_step7_recv_result(sock, K, success, n3p2)) return -1;

    if (!success) {
        std::cerr << "[DBG CLIENT] RETRY handshake\n";
        return -1;
        //return apertura_canale_sicuro_client(sock, user, pass);  // retry
    }

    std::cout << "[DBG CLIENT] Handshake complete\n";
    // handshake successful: hand back the key
    session_key = std::move(K);
    return 0;
}


bool server_step1_recv_hello(int sock, uint64_t& n1, std::string& user) {
    std::cout << "[DBG SERVER] Step1 recv\n";
    std::vector<unsigned char> b1;
    if (!recv_msg(sock, b1)) return false;

    EVP_PKEY* priv = load_private_key("keys/server_priv.pem");
    auto pt1 = rsa_oaep_decrypt(priv, b1);
    EVP_PKEY_free(priv);

    n1 = read_be64(pt1.data() + HELLO_LEN);
    user.assign((char*)pt1.data() + HELLO_LEN + 8, pt1.size() - HELLO_LEN - 8);

    std::cout << "[DBG SERVER] Step1 user=" << user << " n1=" << n1 << "\n";
    return true;
}

bool server_step2_send_nonce_signature(int sock, const std::string& user, uint64_t n1, uint64_t& n2, std::vector<unsigned char>& key) {
    std::cout << "[DBG SERVER] Step2\n";

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

    std::cout << "[DBG SERVER] Step2 done\n";
    return true;
}

bool server_step3_recv_dh_pubB(int sock, const std::string& user, uint64_t n2, const std::vector<unsigned char>& key,
                                std::vector<unsigned char>& pubB) {
    std::cout << "[DBG SERVER] Step3 recv\n";
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
    std::cout << "[DBG SERVER] Step3 done\n";
    return true;
}

    bool server_step4_send_dh_pubA(int sock, EVP_PKEY*& dhk, 
                              const std::vector<unsigned char>& key) {
    std::cout << "[DBG SERVER] Step4: generating DH keypair and sending pubA\n";

    // Genera parametri DH
    EVP_PKEY* dh_params = generate_dh_params();
    if (!dh_params) {
        std::cerr << "[FATAL SERVER] Failed to generate DH params\n";
        return false;
    }

    // Genera coppia di chiavi DH
    dhk = generate_dh_keypair(dh_params);
    EVP_PKEY_free(dh_params);
    if (!dhk) {
        std::cerr << "[FATAL SERVER] Failed to generate DH keypair\n";
        return false;
    }

    // Estrai la chiave pubblica come BIGNUM (stesso approccio del client)
    BIGNUM* pub_key = nullptr;
    if (EVP_PKEY_get_bn_param(dhk, "pub", &pub_key) != 1) {
        std::cerr << "[FATAL SERVER] Failed to get DH public key (BN)\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(dhk);
        return false;
    }

    // Converti BIGNUM in formato binario
    std::vector<unsigned char> pubA(BN_num_bytes(pub_key));
    BN_bn2bin(pub_key, pubA.data());
    BN_free(pub_key);

    // Debug output
    std::cout << "[DBG SERVER] pubA length: " << pubA.size() << " bytes\n";

    // Cifra la chiave pubblica con AES-GCM
    unsigned char iv[12], tag[16];
    gen_iv(iv);
    std::vector<unsigned char> ct(pubA.size());
    if (!aes_encrypt_gcm(key.data(),        // chiave
                        pubA.data(),        // plaintext
                        pubA.size(),        // lunghezza plaintext
                        iv,                 // IV
                        12,                 // lunghezza IV
                        iv,                 // AAD
                        12,                 // lunghezza AAD
                        ct.data(),          // buffer output ciphertext
                        tag)) {             // buffer output tag
        std::cerr << "[FATAL SERVER] AES encryption failed\n";
        EVP_PKEY_free(dhk);
        return false;
    }

    // Prepara messaggio: IV (12) || TAG (16) || CIPHERTEXT
    std::vector<unsigned char> msg;
    msg.insert(msg.end(), iv, iv + 12);
    msg.insert(msg.end(), tag, tag + 16);
    msg.insert(msg.end(), ct.begin(), ct.end());

    std::cout << "[DBG SERVER] Step4 completed, sending " << msg.size() << " bytes\n";
    return send_msg(sock, msg);
}


bool server_step5_send_nonce3(int sock, const std::vector<unsigned char>& K, uint64_t& n3) {
    std::cout << "[DBG SERVER] Step5 send nonce3\n";
    n3 = gen_nonce();
    unsigned char buf[8]; write_be64(buf, n3);
    unsigned char iv[12], tag[16], ct[8];
    gen_iv(iv);
    aes_encrypt_gcm(K.data(), buf, 8, iv, 12, iv, 12, ct, tag);

    std::vector<unsigned char> o(iv, iv + 12);
    o.insert(o.end(), tag, tag + 16);
    o.insert(o.end(), ct, ct + 8);
    return send_msg(sock, o);
}

bool server_step6_recv_nonce3plus1(int sock, const std::vector<unsigned char>& K, uint64_t n3, bool& valid) {
    std::cout << "[DBG SERVER] Step6 recv n3+1\n";
    std::vector<unsigned char> b;
    if (!recv_msg(sock, b)) return false;

    unsigned char iv[12], tag[16], ct[8], pt[8];
    memcpy(iv, b.data(), 12);
    memcpy(tag, b.data() + 12, 16);
    memcpy(ct, b.data() + 28, 8);
    aes_decrypt_gcm(ct, 8, iv, 12, tag, K.data(), iv, 12, pt);

    uint64_t received = read_be64(pt);
    valid = (received == n3 + 1);
    return true;
}

bool server_step7_send_final(int sock, const std::vector<unsigned char>& K, uint64_t n3, bool ok) {
    std::cout << "[DBG SERVER] Step7 send final msg\n";
    const char* res = ok ? "OK" : "RETRY";
    uint64_t n3p2 = n3 + 2;
    unsigned char buf[10];
    memcpy(buf, res, 2);
    write_be64(buf + 2, n3p2);

    unsigned char iv[12], tag[16], ct[10];
    gen_iv(iv);
    aes_encrypt_gcm(K.data(), buf, 10, iv, 12, iv, 12, ct, tag);

    EVP_PKEY* priv = load_private_key("keys/server_priv.pem");
    std::vector<unsigned char> sig(512);
    size_t siglen;
    sign_data(priv, ct, 10, sig.data(), siglen);
    EVP_PKEY_free(priv);

    std::vector<unsigned char> o;
    uint32_t slen_net = htonl(siglen);
    o.insert(o.end(), (unsigned char*)&slen_net, (unsigned char*)&slen_net + 4);
    o.insert(o.end(), sig.begin(), sig.begin() + siglen);
    o.insert(o.end(), iv, iv + 12);
    o.insert(o.end(), tag, tag + 16);
    o.insert(o.end(), ct, ct + 10);
    return send_msg(sock, o);
}

int apertura_canale_sicuro_server(int sock, std::vector<unsigned char>& session_key) {
    std::cout << "[DBG SERVER] Start\n";

    uint64_t n1, n2, n3;
    std::string user;
    std::vector<unsigned char> key;
    std::vector<unsigned char> pubB;
    EVP_PKEY* dhk = nullptr;

    // Step 1: ricevi HELLO + n1 + username
    if (!server_step1_recv_hello(sock, n1, user)) {
        std::cerr << "[ERROR SERVER] Step1 failed\n";
        return -1;
    }

    // Step 2: invia E(Hash(p), n1||n2||ts) + firma
    if (!server_step2_send_nonce_signature(sock, user, n1, n2, key)) {
        std::cerr << "[ERROR SERVER] Step2 failed\n";
        return -1;
    }

    // Step 3: ricevi E(username || n2 || pubB)
    if (!server_step3_recv_dh_pubB(sock, user, n2, key, pubB)) {
        std::cerr << "[ERROR SERVER] Step3 failed\n";
        return -1;
    }

    // Step 4: genera e invia DH pubA
    if (!server_step4_send_dh_pubA(sock, dhk, key)) {
        std::cerr << "[ERROR SERVER] Step4 failed\n";
        return -1;
    }

    // Calcola chiave K condivisa
    EVP_PKEY* pubB_key = import_dh_pubkey(pubB.data(), pubB.size());
    size_t slen = 0;
    unsigned char* sec = derive_shared_secret(dhk, pubB_key, slen);
    std::vector<unsigned char> K = kdf({sec, sec + slen}, user, n1, n2);
    OPENSSL_free(sec);
    EVP_PKEY_free(pubB_key);
    EVP_PKEY_free(dhk);

    // Step 5: invia E(K, nonce3)
    if (!server_step5_send_nonce3(sock, K, n3)) {
        std::cerr << "[ERROR SERVER] Step5 failed\n";
        return -1;
    }

    // Step 6: ricevi E(K, nonce3 + 1)
    bool valid_n3 = false;
    if (!server_step6_recv_nonce3plus1(sock, K, n3, valid_n3)) {
        std::cerr << "[ERROR SERVER] Step6 failed\n";
        return -1;
    }

    // Step 7: invia E(K, OK/RETRY || nonce3+2) + firma
    if (!server_step7_send_final(sock, K, n3, valid_n3)) {
        std::cerr << "[ERROR SERVER] Step7 failed\n";
        return -1;
    }

    std::cout << "[DBG SERVER] Handshake completed " << (valid_n3 ? "successfully" : "with RETRY") << "\n";
    // handshake successful: hand back the key
    session_key = std::move(K);
    return valid_n3 ? 0 : -1;
}

