#include "connectionhandler.h"

#include <unistd.h>
#include <string.h>
#include <iostream>
#include <random>
#include <poll.h>
#include <signal.h>

ConnectionHandler::ConnectionHandler(int sock, struct sockaddr_in addr, std::shared_ptr<PacketHandler> pktHandler) :
    m_sock(sock),
    m_addr(addr),
    m_terminate(false),
    m_done(false),
    m_hasActivity(false),
    m_pktHandler(pktHandler)
{
    static const char letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    std::random_device dev;
    std::mt19937 rng(dev());
    std::uniform_int_distribution<std::mt19937::result_type> dist(0, sizeof(letters) - 2);
    for (int i = 0; i < 6; i++)
    {
        this->m_connId.push_back(letters[dist(rng)]);
    }

    memset(&m_joinedData, 0, sizeof(JoinedData));
}

ConnectionHandler::~ConnectionHandler() {
    m_terminate = true;
    if (m_thread.get()) {
        m_thread->join();
    }
}

ConnectionHandler* ConnectionHandler::create(int sock, struct sockaddr_in addr, std::shared_ptr<PacketHandler> pktHandler) {
    auto handler = new ConnectionHandler(sock, addr, pktHandler);
    handler->m_thread = std::make_unique<std::thread>(&ConnectionHandler::handlerLoop, handler);
    return handler;
}

std::string ConnectionHandler::connId() const
{
    return m_connId;
}

struct sockaddr_in ConnectionHandler::addr() const {
    return m_addr;
}

std::string ConnectionHandler::addrStr() const {
    return inet_ntoa(m_addr.sin_addr);
}

bool ConnectionHandler::done() const {
    return m_done;
}

void ConnectionHandler::setSid(std::string sid) {
    m_sid = sid;
}

void ConnectionHandler::setSession(std::string sid, const JoinData &joinData) {
    setSid(sid);
    m_joinedData.port = joinData.port;
    m_joinedData.privateAddr = joinData.privateAddr;
    m_joinedData.publicAddr = m_addr.sin_addr;
    memcpy(m_joinedData.connId, m_connId.c_str(), 6);
}

const JoinedData* ConnectionHandler::joinedData() const {
    return &m_joinedData;
}

void ConnectionHandler::handlerLoop() {
    ConnPkt pkt;
    std::string sAddr = addrStr();

    sigset_t sigMask;
    sigemptyset(&sigMask);
    sigaddset(&sigMask, SIGINT);
    sigaddset(&sigMask, SIGQUIT);
    sigaddset(&sigMask, SIGHUP);

    struct pollfd pSock;
    pSock.fd = m_sock;
    pSock.events = POLLIN;

    int timeOutSeconds = 20;
    struct timespec timeOut;
	timeOut.tv_sec = timeOutSeconds;
	timeOut.tv_nsec = 0;

    while (!m_terminate) {
        m_hasActivity = false;
        int pollResult = ppoll(&pSock, 1, &timeOut, &sigMask);
        if (pollResult == -1) {
            std::cerr << "Polling client " << sAddr << " failed, errno: " << errno;
            break;
        }
        else if (pollResult == 0) {
            if (m_hasActivity) {
                continue;
            }
            std::cout << "Client " << sAddr << " timed out (no activity for " << timeOutSeconds << " seconds)\n";
            break;
        }
        
        if (pSock.revents & POLLHUP) {
            std::cout << "Client " << sAddr << " closed connection...\n";
            break;
        }
        else if (pSock.revents & POLLERR) {
            std::cerr << "FATAL: Unexpected POLLERR from client " << sAddr << "\n";
            break;
        }
        else if (pSock.revents & POLLNVAL) {
            std::cerr << "FATAL: Unexpected POLLNVAL from client " << sAddr << "\n";
            break;
        }

        memset(&pkt, 0, sizeof(ConnPkt));
        int nBytes = read(m_sock, (char*)&pkt, sizeof(ConnPkt));

        if (nBytes < 1)
        {
            std::cerr << "Unexpected error reading from connection with " << sAddr << ". errno " << errno << "\n";
            break;
        }

        if (nBytes != sizeof(ConnPkt)) {
            continue;
        }

        if (pkt.magic != MAGIC) {
            continue;
        }

        bool close = false;
        auto result = m_pktHandler->handle(this, pkt, close);
        if (close) {
            break;
        }
        if (result.get()) {
            m_pktHandler = result;
        }
    }
    std::cout << "Closing connection with " << sAddr << "...\n";
    close(m_sock);
    m_done = true;
}

int ConnectionHandler::sendErr(uint8_t type) {
    m_hasActivity = true;
    std::lock_guard<std::mutex> guard(m_writeMutex);
    ConnPkt errPkt;
    memset(&errPkt, 0, sizeof(ConnPkt));
    errPkt.magic = MAGIC;
    errPkt.type = type;
    int res = send(m_sock, &errPkt, sizeof(ConnPkt), 0);
    if (res == -1) {
        std::cerr << "Failed to send err " << type << " to " << addrStr() << ", got errno " << errno << "\n";
    }
    return res;
}


int ConnectionHandler::sendResponse(uint8_t type, const void *data, size_t dataLen) {
    m_hasActivity = true;
    std::lock_guard<std::mutex> guard(m_writeMutex);
    ConnPkt pkt;
    memset(&pkt, 0, sizeof(ConnPkt));
    pkt.magic = MAGIC;
    pkt.version = CONN_PKT_VERSION;
    pkt.type = type;
    memcpy(pkt.sid, m_sid.c_str(), 4);
    memcpy(pkt.connId, m_connId.c_str(), 6);

    if (data) {
        memcpy(pkt.data, data, dataLen);
    }

    int res = send(m_sock, &pkt, sizeof(ConnPkt), 0);
    if (res == -1) {
        std::cerr << "Failed to send response " << type << " to " << addrStr() << ", got errno " << errno << "\n";
    }
    return res;
}

int ConnectionHandler::sendNatHolepunch() {
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
    if (sock == -1)
	{
		std::cerr << "Failed to create outgoing udp socket for NAT holepunch!\n";
		return 1;	
	}

    struct sockaddr_in peerAddr;
	socklen_t peerAddrLen = sizeof(peerAddr);
	memset((char *) &peerAddr, 0, peerAddrLen);
	peerAddr.sin_family = AF_INET;
	peerAddr.sin_port = m_joinedData.port;
	memcpy(&peerAddr.sin_addr, &m_joinedData.publicAddr, sizeof(struct in_addr));

    NatHolepunchPkt pkt;
    sendto(sock,
            (char*)&pkt,
            sizeof(NatHolepunchPkt),
            0,
            (struct sockaddr *) &peerAddr,
            peerAddrLen);
}