#pragma once

#include <map>
#include <string>
#include <memory>
#include <mutex>
#include <list>
#include <thread>

#include "protocol.h"
#include "connectionhandler.h"

class Session;

class Server {
public:
    static int listenForever(uint16_t port);

private:
    Server();
    int listenImpl(uint16_t port);

    PacketHandlerFn createHandler();
    PacketHandlerFn joinHandler();
    
    int m_sock;
    std::mutex m_mutex;
    std::list<std::shared_ptr<ConnectionHandler>> m_handlers;
    std::map<std::string, std::shared_ptr<Session>> m_sessions;
};