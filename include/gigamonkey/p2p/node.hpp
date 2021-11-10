// Copyright (c) 2019-2021 Katrina Knight
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_NODE_H
#define GIGAMONKEY_NODE_H

#include <boost/enable_shared_from_this.hpp>
#include "boost/asio.hpp"

namespace Gigamonkey::Bitcoin::P2P {
    class Node : public boost::enable_shared_from_this<Node> {
    public:
        typedef boost::shared_ptr<Node> pointer;
        static pointer create(boost::asio::io_context& io_context,bool server);
        inline boost::asio::ip::tcp::socket& socket() {
            return _socket;
        }
        void connected();
        void start(boost::asio::ip::tcp::resolver::results_type connect_to);
        void start_server();


    private:
        explicit Node(boost::asio::io_context& io_context,bool server) : _socket(io_context), _server(server) {}
        bool _server;
        boost::asio::ip::tcp::socket _socket;
    };
}

#endif //GIGAMONKEY_NODE_H
