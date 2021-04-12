#pragma once

#include "protocol.h"
#include "packethandler.h"
#include <stdint.h>
#include <thread>
#include <mutex>
#include <atomic>
#include <string>

class ConnectionHandler {
public:
    ~ConnectionHandler();

    static ConnectionHandler* create(int sock, struct sockaddr_in addr, std::shared_ptr<PacketHandler> pktHandler, in_port_t udpPort);

    std::string connId() const;
    struct sockaddr_in addr() const;
    std::string addrStr() const;
    bool done() const;

    int sendErr(uint8_t type);
    int sendResponse(uint8_t type, const void *data = nullptr, size_t dataLen = CONN_PKT_DATA_LEN);
    int sendNatHolepunch();

    void setSid(std::string sid);
    void setSession(std::string sid, const JoinData &joinData);
    const JoinedData* joinedData() const;

protected:

private:
    ConnectionHandler(int sock, struct sockaddr_in addr, std::shared_ptr<PacketHandler> pktHandler);
    void handlerLoop();
    int initializeNatMapping();

    int m_sock;
    struct sockaddr_in m_udpAddr;
    struct sockaddr_in m_addr;
    std::atomic<bool> m_terminate;
    std::atomic<bool> m_done;
    std::atomic<bool> m_hasActivity;
    std::unique_ptr<std::thread> m_thread;
    std::shared_ptr<PacketHandler> m_pktHandler;
    std::string m_connId;
    std::string m_sid;
    JoinedData m_joinedData;
    std::mutex m_writeMutex;
};