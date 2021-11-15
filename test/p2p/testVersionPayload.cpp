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
#include <iostream>
#include <boost/type_index.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>
#include <gmock/gmock-matchers.h>
#include <fstream>


namespace Gigamonkey::Bitcoin::P2P {

class VersionPayloadTest : public ::testing::Test {

protected:
    std::vector<unsigned char> testPacket=strToTestVector("7f1101002500000000000000f1fc6d5e00000000000000000000000000000000000000000000ffff5c183534a2da010000000000000000000000000000000000ffff00000000000034ad423c6f4caf7d1e2f707974686f6e2d6d696e696e6f64652d7465737465723a302e302e332fffffffff01");
};
    TEST_F(VersionPayloadTest,TestVersionDecode) {
        // Setup
        boost::iostreams::array_source my_vec_source(reinterpret_cast<char*>(&testPacket[0]), testPacket.size());
        boost::iostreams::stream<boost::iostreams::array_source> is(my_vec_source);
        Messages::VersionMessage vp(true);

        // run
        is >> vp;
        EXPECT_EQ(vp.getVersion(),70015) << "Version version not deserialized correctly";
        EXPECT_EQ(vp.getServices(),37) << "Version Services not deserialized correctly";
        EXPECT_EQ(vp.getTimestamp(),1584266481) << "Version timestamp not deserialized correctly";
        EXPECT_EQ(vp.getNonce(),9056541416301440308) << "Version nonce not deserialized correctly";
        EXPECT_EQ(vp.getUserAgent(),"/python-mininode-tester:0.0.3/") << "Version User agent no deserialized correctly";
        EXPECT_EQ(vp.getStartHeight(),-1) << "Version start height not deserialized correctly";
        EXPECT_EQ(vp.isRelay(),true) << "Version relat not deserialized correctly";
        data::bytes view=(data::bytes)vp;
        std::cout << std::hex << view.size() << std::endl;
        std::cout << std::hex <<  view[1] << std::endl;
        std::cout << (std::string)vp;

    }
}