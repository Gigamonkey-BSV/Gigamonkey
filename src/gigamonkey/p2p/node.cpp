// Copyright (c) 2019-2021 Katrina Knight
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include "gigamonkey/p2p/node.hpp"

namespace Gigamonkey::Bitcoin::P2P {

    Node::pointer Node::create(boost::asio::io_context &io_context, bool server) {
        return pointer(new Node(io_context,server));
    }

    void Node::start(boost::asio::ip::tcp::resolver::results_type connect_to) {
        //boost::asio::async_connect(_socket,connect_to);


    }


}

