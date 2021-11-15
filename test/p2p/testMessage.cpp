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
    class MessageTest : public ::testing::Test {

    protected:
        void SetUp() override {
            Test::SetUp();
            fullStream.clear();
            for(unsigned char chr:headerPacket)
                fullStream.push_back(chr);
            for(unsigned char chr:payloadPacket)
                fullStream.push_back(chr);
        }

    protected:
        std::vector<unsigned char> headerPacket=strToTestVector("e3e1f3e876657273696f6e00000000006800000005f178c7");
        std::vector<unsigned char> payloadPacket=strToTestVector("7f1101002500000000000000c02f6e5e00000000000000000000000000000000000000000000ffff5c183534b03c25000000000000000000000000000000000000000000000000003933dcf677284ed6122f426974636f696e2053563a312e302e322f998e090001");
                                                                     //"7f1101002500000000000000c02f6e5e00000000000000000000000000000000000000000000ffff5c183534b03c25000000000000000000000000000000000000000000000000003933dcf677284ed6122f426974636f696e2053563a312e302e322f998e09"
        std::vector<unsigned char> fullStream;

    };
    TEST_F(MessageTest,TestMessageDecode) {
        // Setup
        boost::iostreams::array_source my_vec_source(reinterpret_cast<char*>(&fullStream[0]), fullStream.size());
        boost::iostreams::stream<boost::iostreams::array_source> is(my_vec_source);
        Messages::Message msg;
        Messages::MessageHeader header{};
        is >> std::noskipws;
        is >> header;
        msg.setHead(header);
        boost::static_pointer_cast<Messages::VersionMessage>(msg.getPayload())->setInitial(true);
        is >> msg;
        std::cout << (std::string) msg;
        EXPECT_TRUE(msg.isValid());

    }
}