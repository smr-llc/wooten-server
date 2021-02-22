#pragma once

#include "protocol.h"
#include <memory>
#include <functional>
#include <vector>

class ConnectionHandler;

class PacketHandler;
typedef std::function<std::shared_ptr<PacketHandler>(ConnectionHandler *conn, ConnPkt &pkt, bool &close)> PacketHandlerFn;

class PacketHandler {
public:
    PacketHandler(std::vector<PacketHandlerFn> handlers);
    std::shared_ptr<PacketHandler> handle(ConnectionHandler *conn, ConnPkt &pkt, bool &close);

private:
    std::vector<PacketHandlerFn> m_handlers;
};
