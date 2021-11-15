// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_NODE_H
#define GIGAMONKEY_NODE_H

#include <boost/enable_shared_from_this.hpp>
#include "boost/asio.hpp"
#include "gigamonkey/p2p/messages/message.hpp"
#include "networks.hpp"

namespace Gigamonkey::Bitcoin::P2P {
    class Node : public boost::enable_shared_from_this<Node> {
    public:
        typedef boost::shared_ptr<Node> pointer;
        static pointer create(boost::asio::io_context& io_context,bool server,Networks network);
        inline boost::asio::ip::tcp::socket& socket() {
            return _socket;
        }
        void connected();

        [[noreturn]] void start(std::string address, std::string port);
        void start_server();

        Messages::Message generateVersion(bool initial);

    private:
        explicit Node(boost::asio::io_context& io_context,bool server, Networks network) : _socket(io_context), _server(server),_network(network) {}
        bool _server;
        boost::asio::ip::tcp::socket _socket;
        boost::asio::ip::tcp::iostream _stream;
        Networks _network;
        uint32_t _version;
    };
}

#endif //GIGAMONKEY_NODE_H
