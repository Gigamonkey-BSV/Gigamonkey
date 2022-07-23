// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "gtest/gtest.h"
#include "data/cross.hpp"
#include "../testUtils.h"
#include "gigamonkey/p2p2/messages/messageHeader.hpp"
#include "gigamonkey/p2p2/address.hpp"
#include <iostream>
#include <boost/type_index.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>
#include <gmock/gmock-matchers.h>
#include <fstream>


namespace Gigamonkey::Bitcoin::P2P2 {


//    TEST(TestP2P,TestEndian) {
//        uint16_t test;
//        std::ifstream is ("/home/nekosune/Projects/cpp/Gigamonkey/temp.bin", std::ios::binary);
//        boost::array<unsigned char,2> portBytes{};
//        for (int i = 0; i < 2; i++)
//            is >> portBytes[i];
//        test = ( portBytes[0] << 8 | portBytes[1   ]);
//        std::cout << test;
//    }
    TEST(TestP2P,TestReadAddress) {
        // Setup Test
        data::bytes testPacket=strToTestVector("000000000000000000000000000000000000ffff5c1834568760");

        // Run test
        Address address(testPacket,true);
        EXPECT_EQ(address.getPort(),34656) << "Address Port deserialized incorrectly";
        EXPECT_EQ(address.getServices(),0) << "Address Services deserialized incorrectly";
        std::cout << address << std::endl;
//        os << address;
//        EXPECT_THAT(outPacket,::testing::ElementsAreArray(testPacket)) << "Address is not the same when deserialized then serialized";
    }

	TEST(TestP2P,TestWriteAddress) {
  // Setup Test
  data::bytes testPacket = strToTestVector("000000000000000000000000000000000000ffff5c1834568760");

  // Run test
  Address address(testPacket, true);
  data::bytes out = static_cast<bytes>(address);
  EXPECT_THAT(out, ::testing::ElementsAreArray(out.data(), 26));
}

TEST(TestP2P, TestHeaderRead) {
  // Setup test
  data::bytes testPacket = strToTestVector("e3e1f3e876657273696f6e00000000006800000005f178c7");

  // Run test
  Messages::MessageHeader header{testPacket, Networks::MainNet};
  EXPECT_THAT(header.getMagicBytes(), ::testing::ElementsAre(0xe3, 0xe1, 0xf3, 0xe8))
			<< "Header magic bytes deserialized incorrectly";
  EXPECT_EQ(header.getCommandName(), "version") << "Header command name deserialized incorrectly";
  EXPECT_EQ(header.getPayloadSize(), 0x68) << "Header Payload Size deserialized incorrectly";
  EXPECT_THAT(header.getChecksum(), ::testing::ElementsAre(0x05, 0xf1, 0x78, 0xc7))
			<< "Header Checksum deserialized incorrectly";
}
TEST(TestP2P, TestHeaderWrite) {
  // Setup test
  data::bytes testPacket = strToTestVector("e3e1f3e876657273696f6e00000000006800000005f178c7");

  // Run test
  Messages::MessageHeader header{testPacket, Networks::MainNet};
  std::cout << header << std::endl;
	data::bytes out = static_cast<bytes>(header);
	EXPECT_THAT(out,::testing::ElementsAreArray(testPacket.data(),24));
}
}