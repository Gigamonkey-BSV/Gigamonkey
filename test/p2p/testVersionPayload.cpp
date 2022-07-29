// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gigamonkey/p2p/messages/versionPayload.hpp"
#include "gtest/gtest.h"
#include "data/cross.hpp"
#include "../testUtils.h"
#include "gigamonkey/p2p/messages/blankPayload.hpp"
#include <iostream>
#include <boost/type_index.hpp>
#include <boost/iostreams/device/array.hpp>
#include <boost/iostreams/stream.hpp>
#include <gmock/gmock-matchers.h>
#include <fstream>


namespace Gigamonkey::Bitcoin::P2P {

class VersionPayloadTest : public ::testing::Test {

protected:
		data::bytes testPacket=strToTestVector("7f1101002500000000000000f1fc6d5e00000000000000000000000000000000000000000000ffff5c183534a2da010000000000000000000000000000000000ffff00000000000034ad423c6f4caf7d1e2f707974686f6e2d6d696e696e6f64652d7465737465723a302e302e332fffffffff01");
};
    TEST_F(VersionPayloadTest,TestVersionDecode) {
        // run
  		Messages::VersionPayload vp(testPacket,testPacket.size(),Networks::MainNet);
        EXPECT_EQ(vp.getVersion(),70015) << "Version version not deserialized correctly";
        EXPECT_EQ(vp.getServices(),37) << "Version Services not deserialized correctly";
        EXPECT_EQ(vp.getTimestamp(),1584266481) << "Version timestamp not deserialized correctly";
        EXPECT_EQ(vp.getNonce(),9056541416301440308) << "Version nonce not deserialized correctly";
        EXPECT_EQ(vp.getUserAgent(),"/python-mininode-tester:0.0.3/") << "Version User agent no deserialized correctly";
        EXPECT_EQ(vp.getStartHeight(),-1) << "Version start height not deserialized correctly";
        EXPECT_EQ(vp.isRelay(),true) << "Version relay not deserialized correctly";
        std::cout << vp;

    }

	TEST_F(VersionPayloadTest,TestVersionEncode) {
  Messages::VersionPayload vp(testPacket,testPacket.size(),Networks::MainNet);
  data::bytes temp= static_cast<bytes>(vp);
  EXPECT_THAT(temp,::testing::ElementsAreArray(testPacket.data(),testPacket.size()));
	}

	TEST_F(VersionPayloadTest,TestReaderAndWriter) {
		Messages::MessagePayload *temp = new Messages::VersionPayload(0,Networks::MainNet);
		data::bytes_reader reader(testPacket.begin(),testPacket.end());
	}
	TEST_F(VersionPayloadTest,TestReaders) {
		Messages::MessagePayload *temp = new Messages::VersionPayload(0,Networks::MainNet);
		lazy_bytes_writer temp2;
		auto ver=dynamic_cast<Messages::VersionPayload*>(temp);
		ver->setVersion(99999);
		ver->setUserAgent("/Gigamonkey:1.1/");
		(*boost::dynamic_pointer_cast<UUIDAssociationId>(ver->getAssocId())).generateRandom();
		temp2 << *temp;
		auto out=(data::bytes)temp2;
		std::cout << out;
		delete(temp);
		Messages::MessagePayload *temp3 =new Messages::BlankPayload(0,Networks::MainNet);

		lazy_bytes_writer temp4;
		temp4 << *temp3;
		auto out2=(data::bytes)temp4;
		std::cout << out2;
	}
}