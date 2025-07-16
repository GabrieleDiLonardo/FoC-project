#include "user.h"
#include "utility.h"

using namespace std;

string generateTemporaryPassword() {
    const string characters =
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789";

    default_random_engine rng(static_cast<unsigned>(time(nullptr)));
    uniform_int_distribution<> dist(0, characters.size() - 1);

    string tempPassword;
    for (int i = 0; i < 10; ++i) {
        tempPassword += characters[dist(rng)];
    }
    return tempPassword;
}

string createUserFile(const string& username) {
    string tempPassword = generateTemporaryPassword();
    string hashed = hash_password(tempPassword);

    ofstream file("users/" + username + ".txt");
    if (file.is_open()) {
        file << "password: " << hashed << "\n";
        file << "modified_password: 0\n";
        file.close();
        cout << "User \"" << username << "\" created successfully.\n";
        cout << "Temporary password (to be communicated to the user): " << tempPassword << endl;
        return tempPassword;
    } else {
        return "Error creating the user file.\n";
    }
}

vector<unsigned char> readFile(const string& filename) {
    ifstream file("files/" + filename, ios::binary);
    return vector<unsigned char>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

vector<unsigned char> sha256(const vector<unsigned char>& data) {
    vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}