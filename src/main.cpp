#include "server.h"
#include <stdint.h>


int main() {
    uint16_t port = 28314;

    Server::listenForever(port);
}