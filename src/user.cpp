#include "user.h"
using namespace std;

vector<unsigned char> readFile(const string& filename) {
    ifstream file("files/" + filename, ios::binary);
    return vector<unsigned char>((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
}

vector<unsigned char> sha256(const vector<unsigned char>& data) {
    vector<unsigned char> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}