#include "utility.h"
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <iostream>
#include <cstring>
#include <openssl/param_build.h>
#include <openssl/core_names.h>
#include <iomanip>



static constexpr size_t IV_LEN          = 12;
static constexpr size_t TAG_LEN         = 16;
static constexpr size_t MIN_MSG         = IV_LEN + TAG_LEN;
static constexpr size_t MAX_PLAINTEXT   = 4*1024;              // e.g. 4 KiB
static constexpr size_t MAX_MSG_TOTAL   = MIN_MSG + MAX_PLAINTEXT;


static uint32_t message_counter = 0;

void resetMessageCounter() {
    message_counter = 0;
}

uint32_t getCurrentMessageCounter() {
    return message_counter;
}



// Stampa un buffer come esadecimale, separato da spazi
void dumpHex(const unsigned char* buf, size_t len, const std::string& title = "") {
    if (!title.empty()) std::cout << title << " (" << len << " bytes):\n";
    for (size_t i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << (int)buf[i] << ' ';
        if ((i & 0xF) == 0xF) std::cout << '\n';
    }
    std::cout << std::dec << "\n\n";
}


// --- RSA-OAEP using EVP ---
std::vector<unsigned char> rsa_oaep_encrypt(EVP_PKEY* pub,
    const std::vector<unsigned char>& pt)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub, NULL);
    EVP_PKEY_encrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    size_t outlen;
    EVP_PKEY_encrypt(ctx, NULL, &outlen, pt.data(), pt.size());
    std::vector<unsigned char> out(outlen);
    EVP_PKEY_encrypt(ctx, out.data(), &outlen, pt.data(), pt.size());
    out.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return out;
}

std::vector<unsigned char> rsa_oaep_decrypt(EVP_PKEY* priv,
    const std::vector<unsigned char>& ct)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, NULL);
    EVP_PKEY_decrypt_init(ctx);
    EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING);
    size_t outlen;
    EVP_PKEY_decrypt(ctx, NULL, &outlen, ct.data(), ct.size());
    std::vector<unsigned char> out(outlen);
    EVP_PKEY_decrypt(ctx, out.data(), &outlen, ct.data(), ct.size());
    out.resize(outlen);
    EVP_PKEY_CTX_free(ctx);
    return out;
}

// --- Load PEM keys ---
EVP_PKEY* load_public_key(const std::string& file) {
    FILE* fp = fopen(file.c_str(),"r");
    if(!fp){ perror("fopen"); return nullptr;}
    EVP_PKEY* p = PEM_read_PUBKEY(fp,NULL,NULL,NULL);
    fclose(fp);
    return p;
}
EVP_PKEY* load_private_key(const std::string& file) {
    FILE* fp = fopen(file.c_str(),"r");
    if(!fp){ perror("fopen"); return nullptr;}
    EVP_PKEY* p = PEM_read_PrivateKey(fp,NULL,NULL,NULL);
    fclose(fp);
    return p;
}

// --- DH helpers ---


EVP_PKEY* generate_dh_params() {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);
    if (!ctx) return nullptr;

    if (EVP_PKEY_paramgen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME, (char*)"ffdhe2048", 0),
        OSSL_PARAM_END
    };

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY* dh_params = nullptr;
    if (EVP_PKEY_paramgen(ctx, &dh_params) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return dh_params;
}


EVP_PKEY* generate_dh_keypair(EVP_PKEY* params) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(params, nullptr);
    if (!ctx) return nullptr;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return key;
}


EVP_PKEY* import_dh_pubkey(const unsigned char* pubkey_data, size_t pubkey_len) {
    if (!pubkey_data || pubkey_len == 0) {
        std::cerr << "Invalid public key data\n";
        return nullptr;
    }

    // Converti i dati in BIGNUM
    BIGNUM* pub_bn = BN_bin2bn(pubkey_data, pubkey_len, nullptr);
    if (!pub_bn) {
        std::cerr << "Failed to create BIGNUM from public key data\n";
        return nullptr;
    }

    // Crea il builder dei parametri
    OSSL_PARAM_BLD* param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld) {
        std::cerr << "Failed to create parameter builder\n";
        BN_free(pub_bn);
        return nullptr;
    }

    // Aggiungi i parametri necessari
    if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, 
                                       OSSL_PKEY_PARAM_GROUP_NAME, 
                                       "ffdhe2048", 0)) {
        std::cerr << "Failed to set DH group\n";
        OSSL_PARAM_BLD_free(param_bld);
        BN_free(pub_bn);
        return nullptr;
    }

    // Nota: Cast esplicito a void* per risolvere l'errore di conversione
    if (!OSSL_PARAM_BLD_push_BN(param_bld, 
                              OSSL_PKEY_PARAM_PUB_KEY, 
                              pub_bn)) {
        std::cerr << "Failed to set public key\n";
        OSSL_PARAM_BLD_free(param_bld);
        BN_free(pub_bn);
        return nullptr;
    }

    // Costruisci i parametri finali
    OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(param_bld);
    if (!params) {
        std::cerr << "Failed to build parameters\n";
        OSSL_PARAM_BLD_free(param_bld);
        BN_free(pub_bn);
        return nullptr;
    }

    // Crea il contesto per la chiave
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "DH", nullptr);
    if (!ctx) {
        std::cerr << "Failed to create EVP_PKEY_CTX\n";
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(param_bld);
        BN_free(pub_bn);
        return nullptr;
    }

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_fromdata_init(ctx) <= 0 ||
        EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        std::cerr << "Failed to create EVP_PKEY from data\n";
        ERR_print_errors_fp(stderr);
    }

    // Pulizia delle risorse
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(param_bld);
    EVP_PKEY_CTX_free(ctx);
    BN_free(pub_bn);

    // Verifica finale
    if (pkey && EVP_PKEY_id(pkey) != EVP_PKEY_DH) {
        std::cerr << "Imported key is not a DH key\n";
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    return pkey;
}
unsigned char* derive_shared_secret(EVP_PKEY* priv,
                                    EVP_PKEY* peer,
                                    size_t& secret_len)
{
    EVP_PKEY_CTX* ctx=EVP_PKEY_CTX_new(priv,NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx,peer);
    EVP_PKEY_derive(ctx,NULL,&secret_len);
    unsigned char* sec=(unsigned char*)OPENSSL_malloc(secret_len);
    EVP_PKEY_derive(ctx,sec,&secret_len);
    EVP_PKEY_CTX_free(ctx);
    return sec;
}

std::vector<unsigned char> kdf(const std::vector<unsigned char>& shared,
                             const std::string& user, uint64_t n1, uint64_t n2) {
    unsigned char out[32];
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    
    // Prepara i parametri
    OSSL_PARAM params[] = {
        OSSL_PARAM_utf8_string("digest", (char *)"SHA256", 0),  // Specifica esplicita del digest
        OSSL_PARAM_octet_string("salt", nullptr, 0),    // Salt opzionale
        OSSL_PARAM_octet_string("key", const_cast<unsigned char*>(shared.data()), shared.size()),
        OSSL_PARAM_octet_string("info", nullptr, 0),    // Info opzionale
        OSSL_PARAM_END
    };

    if (EVP_KDF_derive(kctx, out, sizeof(out), params) <= 0) {
        std::cerr << "HKDF derivation failed\n";
        ERR_print_errors_fp(stderr);
        EVP_KDF_CTX_free(kctx);
        EVP_KDF_free(kdf);
        return {};
    }

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return std::vector<unsigned char>(out, out+32);
}
// --- AES-256-GCM ---
bool aes_encrypt_gcm(const unsigned char* key,
    const unsigned char* pt,int pt_len,
    const unsigned char* iv,int iv_len,
    const unsigned char* aad,int aad_len,
    unsigned char* ct, unsigned char* tag)
{
    EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),NULL,NULL,NULL);
    EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,iv_len,NULL);
    EVP_EncryptInit_ex(c,NULL,NULL,key,iv);
    int len;
    if(aad_len) EVP_EncryptUpdate(c,NULL,&len,aad,aad_len);
    EVP_EncryptUpdate(c,ct,&len,pt,pt_len);
    EVP_EncryptFinal_ex(c,ct+len,&len);
    EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,16,tag);
    EVP_CIPHER_CTX_free(c);
    return true;
}
bool aes_decrypt_gcm(const unsigned char* ct,int ct_len,
    const unsigned char* iv,int iv_len,
    const unsigned char* tag,
    const unsigned char* key,
    const unsigned char* aad,int aad_len,
    unsigned char* pt)
{
    EVP_CIPHER_CTX* c=EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(c,EVP_aes_256_gcm(),NULL,NULL,NULL);
    EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,iv_len,NULL);
    EVP_DecryptInit_ex(c,NULL,NULL,key,iv);
    int len;
    if(aad_len) EVP_DecryptUpdate(c,NULL,&len,aad,aad_len);
    EVP_DecryptUpdate(c,pt,&len,ct,ct_len);
    EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,16,(void*)tag);
    int ret=EVP_DecryptFinal_ex(c,pt+len,&len);
    EVP_CIPHER_CTX_free(c);
    return ret>0;
}

// --- SHA256 hex ---
std::string hash_password(const std::string& pw){
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)pw.c_str(),pw.size(),h);
    std::ostringstream ss;
    ss<<std::hex<<std::setfill('0');
    for(int i=0;i<SHA256_DIGEST_LENGTH;i++) ss<<std::setw(2)<<(int)h[i];
    return ss.str();
}
std::vector<unsigned char> hex_to_bytes(const std::string& hex){
    std::vector<unsigned char> out;
    for(size_t i=0;i<hex.size();i+=2){
        out.push_back((unsigned char)strtol(hex.substr(i,2).c_str(),NULL,16));
    }
    return out;
}

// --- RSA signing ---
bool sign_data(EVP_PKEY* priv,
    const unsigned char* data,size_t data_len,
    unsigned char* sig,size_t& sig_len)
{
    EVP_MD_CTX* m=EVP_MD_CTX_new();
    EVP_DigestSignInit(m,NULL,EVP_sha256(),NULL,priv);
    EVP_DigestSignUpdate(m,data,data_len);
    EVP_DigestSignFinal(m,NULL,&sig_len);
    // prima misura la lunghezza
    EVP_DigestSignFinal(m, NULL, &sig_len);
    // quindi ottieni la firma vera
    EVP_DigestSignFinal(m, sig, &sig_len);
    EVP_MD_CTX_free(m);
    return true;
}
bool verify_signature(EVP_PKEY* pub,
    const unsigned char* data,size_t data_len,
    const unsigned char* sig,size_t sig_len)
{
    EVP_MD_CTX* m=EVP_MD_CTX_new();
    EVP_DigestVerifyInit(m,NULL,EVP_sha256(),NULL,pub);
    EVP_DigestVerifyUpdate(m,data,data_len);
    int ok=EVP_DigestVerifyFinal(m,sig,sig_len);
    EVP_MD_CTX_free(m);
    return ok==1;
}

/* DALLA VECCHIA VERSIONE*/



string toHex(const vector<unsigned char> &data)
{
    stringstream ss;
    ss << hex << setfill('0');
    for (unsigned char byte : data)
    {
        ss << setw(2) << (int)byte;
    }
    return ss.str();
}

//WRAPPER MESSAGGI


bool sendEncryptedMessage(int sock,
                          const std::vector<unsigned char>& K,
                          const std::string& plaintext)
{
    // 1) encrypt
    message_counter++;
    unsigned char aad[4];
    memcpy(aad, &message_counter, 4);
    unsigned char iv[IV_LEN], tag[TAG_LEN];
    gen_iv(iv);

    std::vector<unsigned char> ct(plaintext.size());
    aes_encrypt_gcm(
      K.data(),
      (const unsigned char*)plaintext.data(), (int)plaintext.size(),
      iv, IV_LEN,
      aad, sizeof(aad),
      ct.data(), tag
    );

    // 2) build packet payload = [ IV || TAG || CT ]
    size_t body_len = IV_LEN + TAG_LEN + ct.size();
    std::vector<unsigned char> packet(4 + body_len);

    // 2a) write length prefix
    uint32_t be_len = htonl((uint32_t)body_len);
    memcpy(packet.data(), &be_len, 4);

    // 2b) write IV, TAG, CT
    unsigned char* p = packet.data() + 4;
    memcpy(p,                   iv, IV_LEN);
    memcpy(p + IV_LEN,          tag, TAG_LEN);
    memcpy(p + IV_LEN + TAG_LEN, ct.data(), ct.size());

    dumpHex(packet.data(), packet.size(), "OUTGOING ENCRYPTED MESSAGE");
    // 3) single send()
    ssize_t sent = send(sock, packet.data(), packet.size(), MSG_NOSIGNAL);
    return sent == (ssize_t)packet.size();
}

/// One‐call receiver: reads the 4‑byte length, validates it, allocates exactly once,
/// reads body, decrypts, and returns the plaintext in out_plain.
bool recvEncryptedMessage(int sock,
                          const std::vector<unsigned char>& K,
                          std::string &out_plain)
{
    // 1) read the 4‑byte BE length
    message_counter++;
    unsigned char aad[4];
    memcpy(aad, &message_counter, 4);
    uint32_t be_len;
    if (recv(sock, &be_len, sizeof(be_len), MSG_WAITALL) != sizeof(be_len))
        return false;
    uint32_t body_len = ntohl(be_len);

    // 2) validate BEFORE allocation
    if (body_len < MIN_MSG || body_len > MAX_MSG_TOTAL)
        return false;

    // 3) read the entire body in one go
    std::vector<unsigned char> body(body_len);
    if (recv(sock, body.data(), body_len, MSG_WAITALL) != (ssize_t)body_len)
        return false;

        // body.data() e body_len letti dal socket…
    dumpHex(body.data(), body_len, "INCOMING ENCRYPTED MESSAGE");

    // 4) split IV, TAG, CT
    
    const unsigned char* iv = body.data();
    const unsigned char* tag = body.data() + IV_LEN;
    const unsigned char* ct = body.data() + IV_LEN + TAG_LEN;
    int ct_len = (int)(body_len - IV_LEN - TAG_LEN);

    // 5) decrypt
    std::vector<unsigned char> pt(ct_len);
    if (!aes_decrypt_gcm(ct, ct_len, iv, IV_LEN, tag,
                         K.data(), aad, sizeof(aad), pt.data()))
      return false;

    // 6) return as std::string
    out_plain.assign((char*)pt.data(), pt.size());
    return true;
}


// gen_iv implementation
void gen_iv(unsigned char iv[12]) {
    if (RAND_bytes(iv, 12) != 1) {
        std::cerr << "[FATAL] RAND_bytes failed in gen_iv\n";
        std::abort();
    }
}