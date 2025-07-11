#include "dss_server.h"

using namespace std;
namespace fs = std::filesystem;

string get_key_path(const string &user, const string &ext)
{
    return "keys/" + user + "." + ext;
}

// === CreateKeys ===
string create_keys(const string &user)
{
    string privKeyPath = get_key_path(user, "priv.pem");
    string pubKeyPath = get_key_path(user, "pub.pem");

    if (fs::exists(privKeyPath) && fs::exists(pubKeyPath))
    {
        return "Chiavi già esistenti per l'utente '" + user + "'.";
    }

    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    if (!pkey)
        return "Errore nella generazione delle chiavi.";

    FILE *privFile = fopen(privKeyPath.c_str(), "wb");
    if (!privFile || !PEM_write_PrivateKey(privFile, pkey, nullptr, nullptr, 0, nullptr, nullptr))
    {
        EVP_PKEY_free(pkey);
        if (privFile)
            fclose(privFile);
        return "Errore nel salvataggio della chiave privata.";
    }
    fclose(privFile);

    FILE *pubFile = fopen(pubKeyPath.c_str(), "wb");
    if (!pubFile || !PEM_write_PUBKEY(pubFile, pkey))
    {
        EVP_PKEY_free(pkey);
        if (pubFile)
            fclose(pubFile);
        return "Errore nel salvataggio della chiave pubblica.";
    }
    fclose(pubFile);

    EVP_PKEY_free(pkey);
    return "Chiavi generate con successo per '" + user + "'.";
}

// === GetPublicKey ===
string get_public_key(const string &user)
{
    string pubKeyPath = get_key_path(user, "pub.pem");

    if (!fs::exists(pubKeyPath))
    {
        return "Chiave pubblica non trovata per '" + user + "'.";
    }

    ifstream in(pubKeyPath);
    if (!in)
    {
        return "Errore nell'apertura della chiave pubblica.";
    }

    stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// === SignDoc ===
string sign_document(const string &user, const string &document)
{
    return "ancora non implementata";
}

// === DeleteKeys ===
string delete_keys(const string &user)
{
    string privKeyPath = get_key_path(user, "priv.pem");
    string pubKeyPath = get_key_path(user, "pub.pem");

    bool deleted = false;

    if (fs::exists(privKeyPath))
    {
        fs::remove(privKeyPath);
        deleted = true;
    }

    if (fs::exists(pubKeyPath))
    {
        fs::remove(pubKeyPath);
        deleted = true;
    }

    if (!deleted)
    {
        return "Nessuna chiave trovata per '" + user + "'.";
    }

    return "Chiavi eliminate per '" + user + "'.";
}

bool check_user(const string &username)
{
    string path = "users/" + username + ".txt";
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

int first_login(const string &username)
{
    string path = "users/" + username + ".txt";
    string line;

    ifstream file(path);

    if (!file.is_open())
    {
        // Impossibile aprire il file
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

string change_temporary_password(const string &username, const string &new_password)
{
    const string path = "users/" + username + ".txt";
    const string new_path = "users/" + username + "_tmp.txt";

    ofstream new_file(new_path);

    if (!new_file.is_open())
    {
        // Impossibile aprire il file
        return "Errore nella modifica della password temporanea.\n";
    }

    new_file << "password: " << new_password << '\n';
    new_file << "modified_password: 1\n";

    new_file.close();

    if (rename(new_path.c_str(), path.c_str()) != 0)
    {
        // Errore nella rinominazione del file
        return "Errore nella modifica della password temporanea.\n";
    }

    return "Password modificata.\n";
}

bool check_password(const string &username, const string &password)
{
    const string path = "users/" + username + ".txt";
    string line;
    int pos;
    string register_hashed_password;

    ifstream file(path);

    if (!file.is_open())
    {
        // Impossibile aprire il file
        return false;
    }

    getline(file, line);
    pos = line.find(":");
    register_hashed_password = line.substr(pos + 1);
    register_hashed_password.erase(0, register_hashed_password.find_first_not_of(" \t"));

    if (register_hashed_password == password)
    {
        return true;
    }

    return false;
}

string login(const string &username, const string &password)
{
    int ret;

    if (!check_user(username))
    {
        return "Username e/o password non corretti/o.\n";
    }

    ret = first_login(username);

    if (ret != -1)
    {
        if (!check_password(username, password))
        {
            return "Username e/o password non corretti/o.\n";
        }

        if (ret == 1)
        {
            return "Inserisci nuova password: ";
        }
    }
    return "Errore nell'apertura del file.\n";
}