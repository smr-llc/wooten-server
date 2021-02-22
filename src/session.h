#pragma once

#include <map>
#include <string>
#include <thread>
#include <vector>
#include <mutex>

#include "packethandler.h"
#include "connectionhandler.h"

class Session {
public:
    Session();
    ~Session();

    std::string sid() const;
    std::shared_ptr<PacketHandler> join(ConnectionHandler *conn, const JoinData &data);

private:
    void notify(uint8_t type, const void *data = nullptr, size_t dataLen = CONN_PKT_DATA_LEN);

    void connectionCleanup();

    PacketHandlerFn heartbeatHandler();

    std::string m_sid;

    std::mutex m_mutex;
    std::thread m_cleanupThread;
    std::map<std::string, ConnectionHandler*> m_conns;
};