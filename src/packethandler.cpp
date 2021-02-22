#include "packethandler.h"

PacketHandler::PacketHandler(std::vector<PacketHandlerFn> handlers) :
    m_handlers(handlers)
{

}

std::shared_ptr<PacketHandler> PacketHandler::handle(ConnectionHandler *conn, ConnPkt &pkt, bool &close) {
    if (m_handlers.size() < 1) {
        close = true;
        return std::shared_ptr<PacketHandler>();
    }

    for (auto handler : m_handlers) {
        auto result = handler(conn, pkt, close);
        if (close) {
            return std::shared_ptr<PacketHandler>();
        }
        else if (result.get()) {
            return result;
        }
    }
    return std::shared_ptr<PacketHandler>();
}