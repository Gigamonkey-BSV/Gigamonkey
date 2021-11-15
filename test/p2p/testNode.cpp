// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "gigamonkey/p2p/node.hpp"
#include "gigamonkey/p2p/messages/message_header.hpp"
#include "gigamonkey/p2p/messages/version_message.hpp"
#include "gtest/gtest.h"
#include "gigamonkey/p2p/address.hpp"
#include "data/cross.hpp"
#include "../testUtils.h"
#include "gigamonkey/p2p/messages/message.hpp"
#include <iostream>
#include <boost/type_index.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>
#include <gmock/gmock-matchers.h>
#include <fstream>

namespace Gigamonkey::Bitcoin::P2P {
    TEST(TestNode,TestNode) {
        boost::asio::io_context ctx;
      boost::shared_ptr<Node> node=Node::create(ctx,false,Networks::TestNet);
      //node->start("167.99.91.85","18333");
    }
}

