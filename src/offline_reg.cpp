#include "user.h"

int main (int argc, char* argv[])
{
    if (argc < 2)
    {
        cerr << "Please enter a user to register.\n";
        return 1;
    }

    createUserFile(argv[1]);
    return 0;
}