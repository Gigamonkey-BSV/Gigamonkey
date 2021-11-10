// Copyright (c) 2019-2021 Katrina Knight
// Distributed under the Open BSV software license, see the accompanying file LICENSE.
#include <boost/asio.hpp>
#include "node.hpp"

#ifndef GIGAMONKEY_NODE_MANAGER_H
#define GIGAMONKEY_NODE_MANAGER_H
namespace Gigamonkey::Bitcoin::P2P {
    class NodeManager {
    public:
        explicit NodeManager(boost::asio::io_context& io_context, int port) :
        _io_context(io_context), _acceptor(io_context,boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v6(),port)) {

        }
    private:
        boost::asio::io_context& _io_context;
        boost::asio::ip::tcp::acceptor _acceptor;
        std::vector<Node::pointer> _connections;
    };
}
#endif //GIGAMONKEY_NODE_MANAGER_H
