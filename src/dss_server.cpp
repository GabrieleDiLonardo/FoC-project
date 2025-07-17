#include "dss_server.h"
#include "utility.h"
#include "user.h"

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
        return "Keys already exist for user '" + user + "'.";
    }

    EVP_PKEY *pkey = EVP_RSA_gen(2048);
    if (!pkey)
        return "Error generating keys.";

    FILE *privFile = fopen(privKeyPath.c_str(), "wb");
    if (!privFile || !PEM_write_PrivateKey(privFile, pkey, nullptr, nullptr, 0, nullptr, nullptr))
    {
        EVP_PKEY_free(pkey);
        if (privFile)
            fclose(privFile);
        return "Error saving the private key.";
    }
    fclose(privFile);

    FILE *pubFile = fopen(pubKeyPath.c_str(), "wb");
    if (!pubFile || !PEM_write_PUBKEY(pubFile, pkey))
    {
        EVP_PKEY_free(pkey);
        if (pubFile)
            fclose(pubFile);
        return "Error saving the public key.";
    }
    fclose(pubFile);

    EVP_PKEY_free(pkey);
    return "Keys successfully generated for '" + user + "'.";
}

// === GetPublicKey ===
string get_public_key(const string &user)
{
    string pubKeyPath = get_key_path(user, "pub.pem");

    if (!fs::exists(pubKeyPath))
    {
        return "Public key not found for '" + user + "'.";
    }

    ifstream in(pubKeyPath);
    if (!in)
    {
        return "Error opening the public key.";
    }

    stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

// === SignDoc ===
string sign_document(const string &user, const string &document)
{
    string privKeyPath = get_key_path(user, "priv.pem");

    FILE *privKeyFile = fopen(privKeyPath.c_str(), "rb");
    if (!privKeyFile)
    {
        return "Error: could not open private key for user '" + user + "'.";
    }

    EVP_PKEY *privKey = PEM_read_PrivateKey(privKeyFile, nullptr, nullptr, nullptr);
    fclose(privKeyFile);

    if (!privKey)
    {
        return "Error: failed to read the private key.";
    }

    vector<unsigned char> digest_bytes = hex_to_bytes(document);

    vector<unsigned char> signature(EVP_PKEY_size(privKey));
    size_t sig_len = 0;

    bool success = sign_data(privKey, digest_bytes.data(), digest_bytes.size(), signature.data(), sig_len);
    EVP_PKEY_free(privKey);

    if (!success)
    {
        return "Error: signing failed.";
    }

    stringstream ss;
    ss << hex << setfill('0');
    for (unsigned int i = 0; i < sig_len; ++i)
        ss << setw(2) << static_cast<int>(signature[i]);

    return ss.str();
}

// === DeleteKeys ===
string delete_keys(const string &user)
{
    string privKeyPath = get_key_path(user, "priv.pem");
    string pubKeyPath = get_key_path(user, "pub.pem");
    const string userPath = "users/" + user + ".txt";
    const string updateUserPath = "users/" + user + "_tmp.txt";
    string temporaryPassword;

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
        return "No keys found for '" + user + "'.";
    }

    temporaryPassword = createUserFile(user + "_tmp");

    if (rename(updateUserPath.c_str(), userPath.c_str()) != 0)
    {
        // Errore nella rinominazione del file
        return "Error modifying the file.\n";
    }

    return "Keys deleted for '" + user + "'. The new password is: " + temporaryPassword;
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
        return "Error changing the temporary password.\n";
    }

    new_file << "password: " << new_password << '\n';
    new_file << "modified_password: 1\n";

    new_file.close();

    if (rename(new_path.c_str(), path.c_str()) != 0)
    {
        // Errore nella rinominazione del file
        return "Error changing the temporary password.\n";
    }

    return "Password successfully updated..\n";
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
    int ret = first_login(username);

    if (ret == 1)
    {
        return "First login detected. Please set a new password: ";
    }
    else if (ret == 0)
    {
        return "Password already modified.\n";
    }
    else
    {
        return "Error opening the file.\n";
    }
}