#ifndef DSS_SERVER_H
#define DSS_SERVER_H

#include <iostream>
#include <fstream>
#include <openssl/sha.h>
#include <string>
using namespace std;

string create_keys(const string& user);
string get_public_key(const string& user);
string sign_document(const string& user, const string& document);
string delete_keys(const string& user);
bool check_user(const string* username);
int first_login(const string *username);
string hash_password(const string &password);
int change_temporary_password(const string *username, const string *new_password);

#endif
