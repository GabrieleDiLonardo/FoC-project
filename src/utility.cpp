#include "utility.h"

// Funzione che ritorna il timestamp corrente in secondi
inline uint64_t get_current_unix_timestamp() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count()
    );
}

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

bool sign_data(
    EVP_PKEY *dss_private_key,  // chiave per firmare
    const unsigned char *data,  // dati da firmare
    size_t data_len,            // lunghezza dei dati
    unsigned char *signature,   // buffer in cui salvare la firma
    unsigned int &signature_len       // output: lunghezza effettiva della firma
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
    if (EVP_SignUpdate(mdctx, data, data_len) <= 0)
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

bool verify_signature(
    const unsigned char *dh_pubkey, size_t dh_pubkey_len, /* dati firmati da verificare (g^b mod p) */
    const unsigned char *signature, size_t signature_len, /* firma ricevuta dal DSS */
    const std::string &public_key_file) /* file da cui ricavare chiave pubblica DSS */
{
    bool result = false;
    EVP_PKEY *dss_pubkey = nullptr;
    EVP_MD_CTX *mdctx = nullptr;
    FILE *fp = nullptr;

    // Lettura della chiave pubblica del DSS
    fp = fopen(public_key_file.c_str(), "r");
    if (!fp)
    {
        std::cerr << "Errore: impossibile aprire " << public_key_file << std::endl;
        return false;
    }

    dss_pubkey = PEM_read_PUBKEY(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!dss_pubkey)
    {
        std::cerr << "Errore: lettura chiave pubblica fallita" << std::endl;
        return false;
    }

    // Creazione contesto per la verifica
    mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        std::cerr << "Errore: creazione contesto verifica fallita" << std::endl;
        EVP_PKEY_free(dss_pubkey);
        return false;
    }

    // Inizializzazione verifica con SHA-256
    if (EVP_VerifyInit(mdctx, EVP_sha256()) <= 0)
    {
        std::cerr << "Errore: init verifica fallita" << std::endl;
        goto cleanup;
    }

    // Fornisce i dati originali firmati da verificare
    if (EVP_VerifyUpdate(mdctx, dh_pubkey, dh_pubkey_len) <= 0)
    {
        std::cerr << "Errore: update verifica fallito" << std::endl;
        goto cleanup;
    }

    // Verifica la firma
    if (EVP_VerifyFinal(mdctx, signature, signature_len, dss_pubkey) == 1)
    {
        result = true; // Verifica riuscita
    }
    else
    {
        std::cerr << "Errore: firma non valida" << std::endl;
    }

cleanup:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(dss_pubkey);
    return result;
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

// Funzione per cifratura con AES a 128 bit e MAC
bool aes_encrypt_gcm(const unsigned char *key, const unsigned char *plaintext, int plaintext_len,
                     const unsigned char *iv, const unsigned char *aad, int aad_len,
                     unsigned char *ciphertext, unsigned char *tag, int &ciphertext_len)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    ciphertext_len = 0;

    if (!ctx)
    {
        return false;
    }

    // Scelta dell'algoritmo di cifratura (AES in modalità GCM con chiave a 128 bit)
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1)
    {
        return false;
    }

    // Inizializzazione del IV ad una lunghezza massima di 12 byte (opzionale)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
    {
        return false;
    }

    // Indicazione della chiave e del IV da usare per la cifratura
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
    {
        return false;
    }

    // Processa AAD se presente
    if (aad && aad_len > 0)
    {
        if (EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }

    // Cifratura del messaggio e salvataggio nel buffer ciphertext
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
    {
        return false;
    }
    ciphertext_len = len;

    // Termina processo di cifratura
    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    {
        return false;
    }
    ciphertext_len += len;

    // Derivazione del tag e salvataggio nella variabile
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
    {
        return false;
    }

    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// Funzione per decifratura con AES a 128 bit e MAC
bool aes_decrypt_gcm(const unsigned char *ciphertext, int ciphertext_len,
                     const unsigned char *aad, int aad_len,
                     const unsigned char *tag,
                     const unsigned char *key,
                     const unsigned char *iv, int iv_len,
                     unsigned char *plaintext, int &plaintext_len, uint64_t max_delay)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len = 0;
    uint64_t ts = 0;
    plaintext_len = 0;

    if (!ctx)
    {
        return false;
    }

    // Controlla lunghezza IV (opzionale)
    if (iv_len != 12)
    {
        return false;
    }

    // Scelta dell'algoritmo di decifratura (AES in modalità GCM con chiave a 128 bit)
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Inizializzazione del IV ad una lunghezza massima di 12 byte (opzionale)
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Indicazione della chiave e del IV da usare per la decifratura
    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Verifico timestamp con finestra temporale max_delayn per evitare replay attack
    for (int i = 0; i < 8; ++i) {
        ts |= (static_cast<uint64_t>(aad[i]) << (8 * i));
    }

    uint64_t now = get_current_unix_timestamp();
    if (ts > now || (now - ts) > max_delay)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Decifratura del messaggio e salvataggio nel buffer plaintext
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len = len;

    // Imposta il tag da verificare prima della finalizzazione
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Verifica il tag e completa la decifratura
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return true;
}

string hash_password(const string &password)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(password.c_str()), password.size(), hash);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

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

vector<unsigned char> hex_to_bytes(const string &hex)
{
    vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}