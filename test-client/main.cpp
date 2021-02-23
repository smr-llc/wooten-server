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
#include<netdb.h>

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

int main(int argc, char **argv) {

    struct in_addr localIp;
    if (getLocalIp("enp68s0", localIp) != 0) {
		return -1;
    }
    std::cout << "Local network IP: " << inet_ntoa(localIp) << "\n";

    struct sockaddr_in peerAddr;
	socklen_t peerAddrLen = sizeof(peerAddr);

    struct addrinfo *addrInfo;
    int result = getaddrinfo("wooten.smr.llc", NULL, NULL, &addrInfo);
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
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            std::cerr << "FATAL: failed to create TCP socket! errno: " << errno << "\n";
            return -1;
        }


        if (connect(sock, (struct sockaddr*)&peerAddr, peerAddrLen) != 0) {
            std::cerr << "FATAL: failed to connect TCP socket! errno: " << errno << "\n";
            close(sock);
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
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        std::cerr << "FATAL: failed to create TCP socket! errno: " << errno << "\n";
        return -1;
    }
    if (connect(sock, (struct sockaddr*)&peerAddr, peerAddrLen) != 0) {
        std::cerr << "FATAL: failed to connect TCP socket! errno: " << errno << "\n";
		close(sock);
		return -1;
	}

    std::cout << "Joining Session: " << sid << "\n";
    sendPkt.magic = MAGIC;
    sendPkt.type = PTYPE_JOIN;
    JoinData data;
    data.port = htons(43000);
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

    std::cout << "Port: " << ntohs(joined.port) << "\n";
    std::cout << "Private IP: " << inet_ntoa(joined.privateAddr) << "\n";
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