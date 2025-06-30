#ifndef CLIENT_HPP
#define CLIENT_HPP

#include <string>

class DSS_Client {
public:
    DSS_Client(const std::string& serverIP, int port);
    void run();

private:
    std::string serverIP;
    int port;
    bool connectToServer();
};

#endif
