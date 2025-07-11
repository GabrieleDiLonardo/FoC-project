#ifndef DSS_SERVER_H
#define DSS_SERVER_H

#include <iostream>
#include <fstream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <sstream>
#include <filesystem>
#include <sys/socket.h>  // per socket, recv, send, etc.
#include <netinet/in.h>  // per sockaddr_in
#include <arpa/inet.h>   // per inet_pton, inet_addr
#include <unistd.h>      // per close()
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/opensslv.h>
#include <openssl/param_build.h> 


#include <string>
using namespace std;

string create_keys(const string& user);
string get_public_key(const string& user);
string sign_document(const string& user, const string& document);
string delete_keys(const string& user);
bool check_user(const string& username);
int first_login(const string &username);
string login(const string &username, const string &password);
string change_temporary_password(const string &username, const string &new_password);
bool check_password(const string& username, const string& password);
#endif
