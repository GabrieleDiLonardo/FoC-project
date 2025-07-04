#ifndef UTILITY_HPP
#define UTILITY_HPP

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/core_names.h>
#include <iostream>

// Funzione generatrice di p e g
EVP_PKEY *generate_dh_params()
{
    EVP_PKEY_CTX *pctx = nullptr;
    EVP_PKEY *dh_params = nullptr;
    OSSL_PARAM_BLD *param_bld = nullptr;
    OSSL_PARAM *params_array = nullptr;

    // Costruzione parametri per il gruppo ffdhe2048
    param_bld = OSSL_PARAM_BLD_new();
    if (!param_bld)
    {
        std::cerr << "Errore: impossibile creare param_bld" << std::endl;
        return nullptr;
    }

    // Definizione del gruppo da usare per p e g
    if (!OSSL_PARAM_BLD_push_utf8_string(param_bld, OSSL_PKEY_PARAM_GROUP_NAME, "ffdhe2048", 0))
    {
        std::cerr << "Errore: impossibile settare il gruppo" << std::endl;
        OSSL_PARAM_BLD_free(param_bld);
        return nullptr;
    }

    // Generazione array del tipo: {"group name" = "ffdhe2048"}
    params_array = OSSL_PARAM_BLD_to_param(param_bld);
    if (!params_array)
    {
        std::cerr << "Errore: impossibile convertire i parametri" << std::endl;
        OSSL_PARAM_BLD_free(param_bld);
        return nullptr;
    }

    // Creazione contesto per lavorare con parametri DH
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (!pctx)
    {
        std::cerr << "Errore: impossibile creare contesto EVP_PKEY_CTX" << std::endl;
        OSSL_PARAM_free(params_array);
        OSSL_PARAM_BLD_free(param_bld);
        return nullptr;
    }
    if (EVP_PKEY_paramgen_init(pctx) <= 0)
    {
        std::cerr << "Errore: EVP_PKEY_paramgen_init fallito" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        OSSL_PARAM_free(params_array);
        OSSL_PARAM_BLD_free(param_bld);
        return nullptr;
    }

    // Indicazione dei parametri da usare (gruppo ffdhe2048)
    if (EVP_PKEY_CTX_set_params(pctx, params_array) <= 0)
    {
        std::cerr << "Errore: EVP_PKEY_CTX_set_params fallito" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        OSSL_PARAM_free(params_array);
        OSSL_PARAM_BLD_free(param_bld);
        return nullptr;
    }

    // Generazione parametri DH (p e g) dal gruppo specificato e salvati in dh_params
    if (EVP_PKEY_paramgen(pctx, &dh_params) <= 0)
    {
        std::cerr << "Errore: EVP_PKEY_paramgen fallito" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        OSSL_PARAM_free(params_array);
        OSSL_PARAM_BLD_free(param_bld);
        return nullptr;
    }

    // Cleanup
    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_free(params_array);
    OSSL_PARAM_BLD_free(param_bld);

    return dh_params;
}

// Funzione generatrice di a o b e di g^a mod p o g^b mod p
EVP_PKEY *generate_dh_keypair(EVP_PKEY *dh_params)
{
    if (!dh_params)
    {
        std::cerr << "Errore: parametri DH nulli" << std::endl;
        return nullptr;
    }

    // Creazione contesto per generare chiave con parametri dh_params
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new(dh_params, NULL);

    if (!kctx)
    {
        std::cerr << "Errore: impossibile creare contesto per keygen" << std::endl;
        return nullptr;
    }

    // Inizializzo creazione chiave
    if (EVP_PKEY_keygen_init(kctx) <= 0)
    {
        std::cerr << "Errore: EVP_PKEY_keygen_init fallito" << std::endl;
        EVP_PKEY_CTX_free(kctx);
        return nullptr;
    }

    // Creazione chiave
    EVP_PKEY *keypair = nullptr;
    if (EVP_PKEY_keygen(kctx, &keypair) <= 0)
    {
        std::cerr << "Errore: generazione chiave DH fallita" << std::endl;
        EVP_PKEY_CTX_free(kctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(kctx);

    return keypair;
}

bool sign_dh_parameters(
    EVP_PKEY *dss_private_key,              // chiave privata del DSS
    const unsigned char *dh_pubkey,         // dati da firmare (es. g^b mod p)
    size_t dh_pubkey_len,                   // lunghezza dei dati
    unsigned char *signature,               // buffer in cui salvare la firma
    size_t &signature_len                   // output: lunghezza effettiva della firma
)
{
    // Creazione contesto per firma
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        std::cerr << "Errore: creazione contesto firma fallita" << std::endl;
        return false;
    }

    // Inizializzazione firma con algoritmo di hashing da usare
    if (EVP_SignInit(mdctx, EVP_sha256()) <= 0)
    {
        std::cerr << "Errore: init firma fallita" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return false;
    }
    
    // Indicazione parametri da firmare
    if (EVP_SignUpdate(mdctx, dh_pubkey, dh_pubkey_len) <= 0)
    {
        std::cerr << "Errore: update firma fallito" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    // Firma effettiva
    if (EVP_SignFinal(mdctx, signature, &signature_len, dss_private_key) <= 0)
    {
        std::cerr << "Errore: firma fallita" << std::endl;
        EVP_MD_CTX_free(mdctx);
        return false;
    }

    EVP_MD_CTX_free(mdctx);
    return true;
}

// Funzione per calcolare la chiave di sessione condivisa
unsigned char *derive_shared_secret(EVP_PKEY *my_keypair, EVP_PKEY *peer_pubkey, size_t &secret_len)
{
    if (!my_keypair || !peer_pubkey)
    {
        std::cerr << "Errore: chiavi non valide" << std::endl;
        return nullptr;
    }

    // Creazione contesto per derivare chiave condivisa partendo da chiave privata
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(my_keypair, NULL);
    if (!ctx)
    {
        std::cerr << "Errore: contesto per derivazione fallito" << std::endl;
        return nullptr;
    }

    // Inizializzazione contesto per derivare chiave
    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        std::cerr << "Errore: EVP_PKEY_derive_init fallito" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    // Indicazione chiave pubblica dell'altro peer
    if (EVP_PKEY_derive_set_peer(ctx, peer_pubkey) <= 0)
    {
        std::cerr << "Errore: impostazione chiave peer fallita" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    // Calcolo dimensione del buffer per il segreto condiviso
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0)
    {
        std::cerr << "Errore: calcolo lunghezza segreto fallito" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    // Allocazione memoria per il segreto condiviso
    unsigned char *secret = (unsigned char *)OPENSSL_malloc(secret_len);
    if (!secret)
    {
        std::cerr << "Errore: allocazione memoria segreto fallita" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    // Derivazione segreto condiviso
    if (EVP_PKEY_derive(ctx, secret, &secret_len) <= 0)
    {
        std::cerr << "Errore: derivazione segreto fallita" << std::endl;
        OPENSSL_free(secret);
        EVP_PKEY_CTX_free(ctx);
        return nullptr;
    }

    EVP_PKEY_CTX_free(ctx);
    return secret;
}

/*
bool aes_encrypt_cbc(const unsigned char *key,
                     const unsigned char *plaintext, int plaintext_len,
                     unsigned char *iv, unsigned char *ciphertext, int &ciphertext_len) 
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    ciphertext_len = 0;

    if (!ctx)
    {
        return false;
    }

    // Generazione IV casuale (16 byte per AES)
    if (!RAND_bytes(iv, 16))
    {
        return false;
    }

    // Inizializzazione contesto con AES-256-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1)
    {
        return false;
    }

    // Cifratura dati
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
    {
        return false;
    }

    ciphertext_len = len;

    // Aggiunge eventuale padding (AES vuole blocchi da 16 byte)
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
        return false;
    }

    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Funzione per generare il MAC e garantire autenticità ed integrità
bool compute_hmac(
    const unsigned char *key, size_t key_len,
    const unsigned char *message, size_t msg_len,
    unsigned char *out_digest, unsigned int &out_len)
{
    // Creazione contesto per generazione MAC
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (!ctx)
    {
        std::cerr << "Errore: creazione HMAC_CTX fallita" << std::endl;
        return false;
    }

    // Inizializzazione contesto HMAC con chiave segreta e algoritmo
    if (!HMAC_Init_ex(ctx, key, key_len, EVP_sha256(), NULL))
    {
        std::cerr << "Errore: HMAC_Init_ex fallita" << std::endl;
        HMAC_CTX_free(ctx);
        return false;
    }

    // Indicazione messaggio da autenticare
    if (!HMAC_Update(ctx, message, msg_len))
    {
        std::cerr << "Errore: HMAC_Update fallita" << std::endl;
        HMAC_CTX_free(ctx);
        return false;
    }

    // Calcolo digest finale
    if (!HMAC_Final(ctx, out_digest, &out_len))
    {
        std::cerr << "Errore: HMAC_Final fallita" << std::endl;
        HMAC_CTX_free(ctx);
        return false;
    }

    HMAC_CTX_free(ctx);
    return true;
}*/

#endif