// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "gtest/gtest.h"
#include "gigamonkey/p2p/node.hpp"
#include "../testUtils.h"
#include "gigamonkey/p2p/messages/versionPayload.hpp"
#include <iostream>


namespace Gigamonkey::Bitcoin::P2P {


    TEST(TestNode,TestNode) {
        boost::asio::io_context ctx;
        data::bytes payload=strToTestVector("7F11010001000000000000008C86C1B643A7C116000000000000000000000000000000000000FFFF7F000001480C000000000000000000000000000000000000FFFF00000000000000000000000000000C2F476967616D6F6E6B65792F0000000000");
  		data::bytes head=strToTestVector("DAB5BFFA76657273696F6E0000000000620000008CDF7CFD");

		// DAB5BFFA 76657273696F6E0000000000 62000000 8CDF7CFD 7F11010001000000000000008C86C1B643A7C116000000000000000000000000000000000000FFFF7F000001480C000000000000000000000000000000000000FFFF00000000000000000000000000000C2F476967616D6F6E6B65792F0000000000
		// 7F110100
		// 0100000000000000
		// 8C86C1B643A7C116
		// 		0000000000000000
		// 		00000000000000000000FFFF7F000001
		// 		480C
		// 		0000000000000000
		// 		00000000000000000000FFFF00000000
		// 		0000
		// 		0000000000000000
		// 		0C
		// 		2F476967616D6F6E6B65792F
		// 		00000000
		// 		00
		std::cout << payload.size() << std::endl;
		Messages::VersionPayload payloadObj(payload,payload.size(),Networks::RegTest);
		Messages::MessageHeader headerObj(head,Networks::RegTest);
		std::cout << "Head: " << headerObj << " body: "<< payloadObj << std::endl;
      boost::shared_ptr<Node> node=Node::create(ctx,false,P2P::Networks::RegTest);

	  node->connect("127.0.0.1","18444");
      //node->start("167.99.91.85","18333");
	  ctx.run();
    }
}

