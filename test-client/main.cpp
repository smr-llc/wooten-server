#include "../src/protocol.h"

#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <errno.h>
#include <random>
#include <iostream>
#include <chrono>
#include <string.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netdb.h>

#include <poll.h>
#include <signal.h>

int getLocalIp(std::string interface, struct in_addr &addr) {
    memset(&addr, 0, sizeof(struct in_addr));

    struct ifreq ifr;
    ifr.ifr_addr.sa_family = AF_INET;
    memset(&ifr.ifr_name, 0, IFNAMSIZ);
    strncpy(ifr.ifr_name, interface.c_str(), interface.size());

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        std::cerr << "Failed to open IPv4 socket for local address detection. errno: " << errno << "\n";
        return -1;
    }
    int status = ioctl(sock, SIOCGIFADDR, &ifr);
    close(sock);
    if (status < 0) {
        std::cerr << "Failed to get address on device '" << interface << "'. errno: " << errno << "\n";
        return -1;
    }

    addr = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;

    return 0;
}

int connectToServer(struct sockaddr_in serverAddr) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "FATAL: failed to create TCP socket! errno: " << errno << "\n";
        return -1;
    }

    int udpSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udpSock == -1)
	{
		std::cerr << "FATAL: Failed to create UDP receive socket for NAT mapping, got errno " << errno << "\n";
		return -1;
	}

	struct sockaddr_in addr;
	memset((char *) &addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(43000);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if( bind(udpSock, (struct sockaddr*)&addr, sizeof(addr) ) == -1)
	{
		std::cerr << "ERROR: Failed to bind UDP receive socket for NAT mapping, got errno " << errno << "\n";
        close(udpSock);
		return -1;
	}

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 500000;
    if (setsockopt(udpSock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "ERROR: Failed to set timeout for UDP receive socket for NAT mapping\n";
        close(udpSock);
        return -1;
    }

    if (connect(sock, (struct sockaddr *) &serverAddr, sizeof(serverAddr)) != 0) {
        std::cerr << "FATAL: failed to connect TCP socket! errno: " << errno << "\n";
        close(udpSock);
        return -1;
    }

    ConnPkt recvPkt;
	struct sockaddr_in peerAddr;
    socklen_t peerAddrLen = sizeof(peerAddr);
    ConnPkt sendPkt;
    sendPkt.magic = MAGIC;
    sendPkt.version = CONN_PKT_VERSION;
    sendPkt.type = PTYPE_HOLEPUNCH;
    int tries = 0;
    while (true) {
        tries++;
        if (tries > 5) {
            break;
        }
        ssize_t nBytes = sendto(udpSock,
            (char*)&sendPkt,
            sizeof(ConnPkt),
            0,
            (struct sockaddr *) &serverAddr,
            sizeof(serverAddr));
        if (nBytes < 0) {
            std::cerr << "Failed to send NAT holepunch, got errno " << errno << "\n";
            break;
        }

        nBytes = recvfrom(udpSock, &recvPkt, sizeof(ConnPkt), 0, (struct sockaddr *) &peerAddr, &peerAddrLen);
        
        if (nBytes < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            std::cerr << "ERROR: Failed to read server UDP message, got errno " << errno << "\n";
            break;
        }

        if (nBytes != sizeof(ConnPkt)) {
            std::cerr << "WARN: Invalid server UDP message size " << nBytes << "\n";
            continue;
        }

        if (peerAddr.sin_addr.s_addr != serverAddr.sin_addr.s_addr) {
            std::cerr << "WARN: Server UDP message from unexpected IP " << inet_ntoa(peerAddr.sin_addr) << " (waiting for " << inet_ntoa(serverAddr.sin_addr) << ")\n";
            continue;
        }

        close(udpSock);
        return sock;
    }

    close(sock);
    close(udpSock);
    return -1;
}

int main(int argc, char **argv) {

    struct in_addr localIp;
    if (getLocalIp("enp68s0", localIp) != 0) {
		return -1;
    }
    std::cout << "Local network IP: " << inet_ntoa(localIp) << "\n";

    struct sockaddr_in peerAddr;
	socklen_t peerAddrLen = sizeof(peerAddr);

    struct addrinfo *addrInfo;
    int result = getaddrinfo("127.0.0.1", NULL, NULL, &addrInfo);
    if (result != 0) {
		printf("ERROR: Failed to resolve hostname into address, error: %d\n", result);
		fflush(stdout);
		return -1;
    }
    memcpy(&peerAddr, addrInfo->ai_addr, addrInfo->ai_addrlen);
	peerAddr.sin_port = htons(28314);
    freeaddrinfo(addrInfo);

	int sock;
    int nBytes;
    ConnPkt pkt;
    ConnPkt sendPkt;
    std::string sid;
    
    if (argc == 1) {
        sock = connectToServer(peerAddr);
        if (sock == -1) {
            return -1;
        }

        std::cout << "Creating session...\n";
        sendPkt.magic = MAGIC;
        sendPkt.type = PTYPE_CREATE;
        if (send(sock, (char*)&sendPkt, sizeof(ConnPkt), 0) == -1) {
            std::cerr << "FATAL: failed to send on TCP socket! errno: " << errno << "\n";
            close(sock);
            return -1;
        }

        nBytes = read(sock, &pkt, sizeof(ConnPkt));
        if (nBytes != sizeof(ConnPkt) || pkt.magic != MAGIC || pkt.type != PTYPE_CREATED) {
            std::cerr << "FATAL: bad response " << pkt.type << ", " << nBytes << "\n";
            close(sock);
            return -1;
        }
        close(sock);
        sid = std::string(pkt.sid, 4);
    }
    else {
        sid = argv[1];
    }
    
    sock = connectToServer(peerAddr);
    if (sock == -1) {
        return -1;
    }

    std::cout << "Joining Session: " << sid << "\n";
    sendPkt.magic = MAGIC;
    sendPkt.type = PTYPE_JOIN;
    JoinData data;
    data.privatePort = htons(43000);
    data.privateAddr = localIp;
    memcpy(sendPkt.sid, sid.c_str(), 4);
    memcpy(sendPkt.data, &data, sizeof(JoinData));
    if (send(sock, (char*)&sendPkt, sizeof(ConnPkt), 0) == -1) {
        std::cerr << "FATAL: failed to send on TCP socket! errno: " << errno << "\n";
		close(sock);
		return -1;
    }

    nBytes = read(sock, &pkt, sizeof(ConnPkt));
    if (nBytes != sizeof(ConnPkt) || pkt.magic != MAGIC) {
        std::cerr << "FATAL: bad response " << nBytes << "\n";
		close(sock);
		return -1;
    }
    if (pkt.type != PTYPE_JOINED) {
        std::cerr << "FATAL: bad response, type " << pkt.type << "\n";
		close(sock);
		return -1;
    }
    std::cout << "Got joined response\n";

    JoinedData joined;
    memcpy(&joined, pkt.data, sizeof(JoinedData));

    std::cout << "Private Port: " << ntohs(joined.privatePort) << "\n";
    std::cout << "Private IP: " << inet_ntoa(joined.privateAddr) << "\n";
    std::cout << "Public Port: " << ntohs(joined.publicPort) << "\n";
    std::cout << "Public IP: " << inet_ntoa(joined.publicAddr) << "\n";

    sigset_t sigMask;
    sigemptyset(&sigMask);
    sigaddset(&sigMask, SIGINT);
    sigaddset(&sigMask, SIGQUIT);
    sigaddset(&sigMask, SIGHUP);

    ConnPkt heartbeat;
    heartbeat.magic = MAGIC;
    heartbeat.version = CONN_PKT_VERSION;
    heartbeat.type = PTYPE_HEARTBEAT;
    memcpy(heartbeat.sid, sid.c_str(), 4);
    memcpy(heartbeat.connId, pkt.connId, 6);

    struct timespec timeOut;
	timeOut.tv_sec = 9;
	timeOut.tv_nsec = 0;
    while (true) {
        struct pollfd pSock;
        pSock.fd = sock;
        pSock.events = POLLIN;

        int pollResult = ppoll(&pSock, 1, &timeOut, &sigMask);
        if (pollResult == -1) {
            std::cerr << "poll errno " << errno;
            break;
        }
        
        if (pSock.revents & POLLHUP || pSock.revents & POLLRDHUP) {
            std::cerr << "FATAL: Server closed connection...\n";
            break;
        }
        else if (pSock.revents & POLLERR) {
            std::cerr << "FATAL: Unexpected POLLERR on socket, closing...\n";
            break;
        }
        else if (pSock.revents & POLLNVAL) {
            std::cerr << "FATAL: Unexpected POLLNVAL on socket, closing...\n";
            break;
        }
        
        if (pollResult > 0) {
            nBytes = read(sock, &pkt, sizeof(ConnPkt));
            if (nBytes != sizeof(ConnPkt) || pkt.magic != MAGIC) {
                std::cerr << "FATAL: bad response " << nBytes << "\n";
                break;
            }
            std::cout << "Response type: " << int(pkt.type) << "\n";
        }
        else {
            std::cout << "Sending heartbeat...\n";
            if (send(sock, (char*)&heartbeat, sizeof(ConnPkt), 0) == -1) {
                std::cerr << "FATAL: failed to send on TCP socket! errno: " << errno << "\n";
                break;
            }
        }
    }


    close(sock);
}