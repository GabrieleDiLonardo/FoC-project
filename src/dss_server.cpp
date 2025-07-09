#include "dss_server.h"
#include <openssl/applink.c>

using namespace std;
namespace fs = std::filesystem;

string get_key_path(const string& user, const string& ext) {
    return "keys/" + user + "." + ext;
}

// === CreateKeys ===
string create_keys(const string& user) {
    string privKeyPath = get_key_path(user, "priv.pem");
    string pubKeyPath  = get_key_path(user, "pub.pem");

    if (fs::exists(privKeyPath) && fs::exists(pubKeyPath)) {
        return "Chiavi già esistenti per l'utente '" + user + "'.";
    }

    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    if (!pkey) return "Errore nella generazione delle chiavi.";

    FILE* privFile = fopen(privKeyPath.c_str(), "wb");
    if (!privFile || !PEM_write_PrivateKey(privFile, pkey, nullptr, nullptr, 0, nullptr, nullptr)) {
        EVP_PKEY_free(pkey);
        if (privFile) fclose(privFile);
        return "Errore nel salvataggio della chiave privata.";
    }
    fclose(privFile);

    FILE* pubFile = fopen(pubKeyPath.c_str(), "wb");
    if (!pubFile || !PEM_write_PUBKEY(pubFile, pkey)) {
        EVP_PKEY_free(pkey);
        if (pubFile) fclose(pubFile);
        return "Errore nel salvataggio della chiave pubblica.";
    }
    fclose(pubFile);

    EVP_PKEY_free(pkey);
    return "Chiavi generate con successo per '" + user + "'.";
}

// === GetPublicKey ===
string get_public_key(const string& user) {
    string pubKeyPath = get_key_path(user, "pub.pem");

    if (!fs::exists(pubKeyPath)) {
        return "Chiave pubblica non trovata per '" + user + "'.";
    }

    ifstream in(pubKeyPath);
    if (!in) {
        return "Errore nell'apertura della chiave pubblica.";
    }

    stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// === SignDoc ===
string sign_document(const string& user, const string& document) {
    return "ancora non implementata";
}

// === DeleteKeys ===
string delete_keys(const string& user) {
    string privKeyPath = get_key_path(user, "priv.pem");
    string pubKeyPath  = get_key_path(user, "pub.pem");

    bool deleted = false;

    if (fs::exists(privKeyPath)) {
        fs::remove(privKeyPath);
        deleted = true;
    }

    if (fs::exists(pubKeyPath)) {
        fs::remove(pubKeyPath);
        deleted = true;
    }

    if (!deleted) {
        return "Nessuna chiave trovata per '" + user + "'.";
    }

    return "Chiavi eliminate per '" + user + "'.";
}


bool check_user(const string* username)
{
    string path = "../users/" + *username + ".txt";
    string line;

    ifstream file(path);

    if (!file.is_open())
    {   
        // Utente non registrato 
        return false;
    }

    file.close();

    return true;
}

int first_login(const string *username)
{
    string path = "../users/" + *username + ".txt";
    string line;

    ifstream file(path);

    if (!file.is_open())
    {
        // Impossibile aprire il file o file non esistente
        return -1;
    }

    while (getline(file, line))
    {
        if (line == "modified_password: 0")
        {
            file.close();
            return 1;
        }
    }

    file.close();

    // Password temporanea già modificata
    return 0;
}

string hash_password(const string &password)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        ss << hex << setw(2) << setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}


int change_temporary_password(const string *username, const string *new_password)
{
    const string path = "../users/" + *username + ".txt";
    const string new_path = "../users/" + *username + "_tmp.txt";
    const int login_status = first_login(username);

    // Controllo se il file esiste e se la password non è stata modificata (primo login)
    if (login_status != 1)
    {
        return login_status;
    }

    string hashed_password = hash_password(*new_password);

    ofstream new_file(new_path);

    if (!new_file.is_open())
    {
        // Impossibile aprire il file
        return -1;
    }

    new_file << "password: " << hashed_password << '\n';
    new_file << "modified_password: 1\n";

    new_file.close();

    if (rename(new_path.c_str(), path.c_str()) != 0) {
        // Errore nella rinominazione del file
        return -2;
    }

    return 1;
}