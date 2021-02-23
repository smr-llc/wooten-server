#include "session.h"

#include <random>
#include <iostream>
#include <unistd.h>

Session::Session() 
{
    static const char letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(0, sizeof(letters) - 2);

    for (int i = 0; i < 4; i++) {
        m_sid.push_back(letters[dist(rng)]);
    }

    m_cleanupThread = std::thread(&Session::connectionCleanup, this);
}

Session::~Session() {
}

std::string Session::sid() const {
    return m_sid;
}

std::shared_ptr<PacketHandler> Session::join(ConnectionHandler *conn, const JoinData &data) {
    conn->setSession(m_sid, data);
    conn->sendResponse(PTYPE_JOINED, conn->joinedData(), sizeof(JoinedData));

    {
        std::lock_guard<std::mutex> guard(this->m_mutex);
        for (auto connPair : m_conns) {
            conn->sendResponse(PTYPE_JOINED, connPair.second->joinedData(), sizeof(JoinedData));
        }
        m_conns.emplace(conn->connId(), conn);
    }

    notify(PTYPE_JOINED, conn->joinedData(), sizeof(JoinedData));

    std::vector<PacketHandlerFn> funcs;
    funcs.push_back(heartbeatHandler());
    std::shared_ptr<PacketHandler> pktHandler(new PacketHandler(funcs));
    return pktHandler;
}


void Session::notify(uint8_t type, const void *data, size_t dataLen) {
    std::lock_guard<std::mutex> guard(this->m_mutex);
    for (auto connPair : m_conns) {
        connPair.second->sendResponse(type, data, dataLen);
    }
}

void Session::connectionCleanup() {
    std::vector<JoinedData> deletions;
    while (true) {
        deletions.clear();
        {
            std::lock_guard<std::mutex> guard(this->m_mutex);
            for (auto it = m_conns.cbegin(); it != m_conns.cend();) {
                if (it->second->done()) {
                    deletions.push_back(*it->second->joinedData());
                    delete it->second;
                    it = m_conns.erase(it);
                }
                else {
                    it++;
                }
            }
        }
        for (auto deletion : deletions) {
            notify(PTYPE_LEFT, &deletion, sizeof(JoinedData));
        }
        sleep(2);
    }
}


PacketHandlerFn Session::heartbeatHandler() {
    return [this](ConnectionHandler *conn, ConnPkt &pkt, bool &close) {
        if (pkt.type != PTYPE_HEARTBEAT) {
            return std::shared_ptr<PacketHandler>();
        }

        std::cout << "Received heartbeat, responding...\n";
        conn->sendResponse(PTYPE_HEARTBEAT);
        return std::shared_ptr<PacketHandler>();
    };
}