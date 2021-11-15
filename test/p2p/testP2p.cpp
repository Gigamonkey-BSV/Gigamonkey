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


    TEST(TestP2P,TestEndian) {
        uint16_t test;
        std::ifstream is ("/home/nekosune/Projects/cpp/Gigamonkey/temp.bin", std::ios::binary);
        boost::array<unsigned char,2> portBytes{};
        for (int i = 0; i < 2; i++)
            is >> portBytes[i];
        test = ( portBytes[0] << 8 | portBytes[1   ]);
        std::cout << test;
    }
    TEST(TestP2P,TestAddress) {
        // Setup Test
        std::vector<unsigned char> testPacket=strToTestVector("000000000000000000000000000000000000ffff5c1834568760");
        boost::iostreams::array_source my_vec_source(reinterpret_cast<char*>(&testPacket[0]), testPacket.size());
        boost::iostreams::stream<boost::iostreams::array_source> is(my_vec_source);
        std::vector<unsigned char> outPacket{26};
        outPacket.resize(26);
        boost::iostreams::array_sink  my_vec_sink(reinterpret_cast<char*>(&outPacket[0]), 26);
        boost::iostreams::stream<boost::iostreams::array_sink> os(my_vec_sink);

        // Run test
        Address address(true);
        is >> address;
        EXPECT_EQ(address.getPort(),34656) << "Address Port deserialized incorrectly";
        EXPECT_EQ(address.getServices(),0) << "Address Services deserialized incorrectly";
        //std::cout << static_cast<std::string>(address) << std::endl;
        os << address;
        EXPECT_THAT(outPacket,::testing::ElementsAreArray(testPacket)) << "Address is not the same when deserialized then serialized";
    }

    TEST(TestP2P,TestHeaderRead) {
        // Setup test
        std::vector<unsigned char> testPacket=strToTestVector("e3e1f3e876657273696f6e00000000006800000005f178c7");
        boost::iostreams::array_source my_vec_source(reinterpret_cast<char*>(&testPacket[0]), testPacket.size());
        boost::iostreams::stream<boost::iostreams::array_source> is(my_vec_source);
        std::vector<unsigned char> outPacket{24};
        outPacket.resize(24);
        boost::iostreams::array_sink  my_vec_sink(reinterpret_cast<char*>(&outPacket[0]), 24);
        boost::iostreams::stream<boost::iostreams::array_sink> os(my_vec_sink);

        // Run test
        Messages::MessageHeader header{};
        is >> header;
        EXPECT_THAT(header.getMagicBytes(),::testing::ElementsAre(0xe3,0xe1,0xf3,0xe8))<< "Header magic bytes deserialized incorrectly";
        EXPECT_EQ(header.getCommandName(),"version") << "Header command name deserialized incorrectly";
        EXPECT_EQ(header.getPayloadSize(),0x68) << "Header Payload Size deserialized incorrectly";
        EXPECT_THAT(header.getChecksum(),::testing::ElementsAre(0x05,0xf1,0x78,0xc7)) << "Header Checksum deserialized incorrectly";
        os << header;
        EXPECT_THAT(outPacket,::testing::ElementsAreArray(testPacket)) << "Header is not the same when serialised then deserialized";
    }
}