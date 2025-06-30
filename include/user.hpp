#ifndef USER_HPP
#define USER_HPP

#include <string>

struct User {
    std::string username;
    std::string password;
    std::string publicKey;
    std::string encryptedPrivateKey;
};

#endif
