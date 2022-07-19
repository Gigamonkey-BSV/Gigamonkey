// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gigamonkey/p2p/messages/messageHeader.hpp"
#include "gigamonkey/p2p/messages/versionPayload.hpp"
#include "gigamonkey/p2p/networks.hpp"
#include "gtest/gtest.h"
#include "data/cross.hpp"
#include "../testUtils.h"
#include "gigamonkey/p2p/messages/message.hpp"
#include <iostream>

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
        data::bytes headerPacket=strToTestVector("e3e1f3e876657273696f6e00000000006800000005f178c7");
	  data::bytes payloadPacket=strToTestVector("7f1101002500000000000000c02f6e5e00000000000000000000000000000000000000000000ffff5c183534b03c25000000000000000000000000000000000000000000000000003933dcf677284ed6122f426974636f696e2053563a312e302e322f998e090001");
                                                                     //"7f1101002500000000000000c02f6e5e00000000000000000000000000000000000000000000ffff5c183534b03c25000000000000000000000000000000000000000000000000003933dcf677284ed6122f426974636f696e2053563a312e302e322f998e09"
																	 data::bytes fullStream;

    };
    TEST_F(MessageTest,TestMessageDecode) {
        // Setup
        Messages::MessageHeader header(headerPacket,Networks::MainNet);
		Messages::Message msg=Messages::Message::createFrom(header,payloadPacket,Networks::MainNet);

        boost::static_pointer_cast<Messages::VersionPayload>(msg.getPayload())->setInitial(true);
        std::cout << msg;
        EXPECT_TRUE(msg.isValid());
    }
}