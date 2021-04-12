#include "server.h"
#include <iostream>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "session.h"

Server::Server() :
    m_sock(0)
{
    
}

int Server::listenForever(uint16_t port) {
    Server s;
    return s.listenImpl(port);
}

int Server::listenImpl(uint16_t port) {
    m_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (m_sock < 0) {
        std::cerr << "FATAL: server failed to create TCP socket! errno: " << errno << "\n";
        return -1;
    }

    struct timeval tv;
	tv.tv_sec = 2;
	tv.tv_usec = 0;
	if (setsockopt(m_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "FATAL: failed to set receive timeout on TCP socket! errno: " << errno << "\n";
        return -1;
	}

    int enableReuse = 1;
	if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &enableReuse, sizeof(int)) < 0) {
        std::cerr << "FATAL: failed to set port re-use on TCP socket! errno: " << errno << "\n";
        return -1;
	}

    struct sockaddr_in addr;
	memset((char *) &addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	if(bind(m_sock, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        std::cerr << "FATAL: server failed to bind to port " << port << "! errno: " << errno << "\n";
        close(m_sock);
		return -1;
	}

	if (listen(m_sock, 20) == -1) {
        std::cerr << "FATAL: server failed to listen with TCP socket! errno: " << errno << "\n";
        close(m_sock);
		return -1;
	}

	struct sockaddr_in peerAddr;
	socklen_t peerAddrLen = sizeof(peerAddr);

    while (true) {
        int connSock = accept(m_sock, (struct sockaddr*)&peerAddr, &peerAddrLen);

        if (connSock < 0) {
			if (errno == EAGAIN) {
                //std::cout << "No connections...\n";
				continue;
			}
            std::cerr << "ERROR: unexpected connection accept error! errno: " << errno << "\n";
			continue;
		}

        std::vector<PacketHandlerFn> funcs;

        funcs.push_back(createHandler());
        funcs.push_back(joinHandler());

        std::shared_ptr<PacketHandler> pktHandler(new PacketHandler(funcs));
        ConnectionHandler *conn = ConnectionHandler::create(connSock, peerAddr, pktHandler, addr.sin_port);
        if (!conn) {
            continue;
        }
        std::shared_ptr<ConnectionHandler> handler(conn);
        m_handlers.push_back(handler);
    }
}

PacketHandlerFn Server::createHandler() {
    return [this](ConnectionHandler *conn, ConnPkt &pkt, bool &close) {
        if (pkt.type != PTYPE_CREATE) {
            return std::shared_ptr<PacketHandler>();
        }

        {
            std::cout << "Creating new session...\n";
            std::lock_guard<std::mutex> guard(this->m_mutex);
            std::shared_ptr<Session> s(new Session());
            m_sessions.emplace(s->sid(), s);
            std::cout << "Created session " << s->sid() << "\n";
            conn->setSid(s->sid());
            conn->sendResponse(PTYPE_CREATED);
        }

        close = true;
        return std::shared_ptr<PacketHandler>();
    };
}

PacketHandlerFn Server::joinHandler() {
    return [this](ConnectionHandler *conn, ConnPkt &pkt, bool &close) {
        if (pkt.type != PTYPE_JOIN) {
            return std::shared_ptr<PacketHandler>();
        }

        {
            std::lock_guard<std::mutex> guard(this->m_mutex);
            std::string sid(pkt.sid + '\0', 4);
            auto sessionPair = m_sessions.find(sid);
            if (sessionPair != m_sessions.end()) {
                std::cout << "Client " << conn->addrStr() << " joining session " << sid << "...\n";
                JoinData data;
                memcpy(&data, pkt.data, sizeof(JoinData));
                return sessionPair->second->join(conn, data);
            }
            else {
                conn->sendErr(PTYPE_ERR_NOT_FOUND);
                close = true;
            }
        }

        return std::shared_ptr<PacketHandler>();
    };
}