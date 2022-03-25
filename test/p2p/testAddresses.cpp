// Copyright (c) 2022 Katrina Knight
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

	auto testPacket=strToTestVector("000000000000000000000000000000000000ffff5c183534a2da");

	TEST(TestPeerAddress,TestOne) {
		Address temp(true);
		auto temp2 = bytes_reader(testPacket.data(), testPacket.data()+testPacket.size());
		temp2 >> temp;
		EXPECT_EQ(temp.getPort(),41690) << "Port read incorrectly";
		EXPECT_EQ(temp.getServices(),0) << "Services read incorrectly";
		EXPECT_EQ(temp.getTimestamp(),0) << "Timestamp read incorrectly";
	}
}