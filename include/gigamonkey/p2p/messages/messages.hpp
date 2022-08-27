// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_P2P_MESSAGES_MESSAGES_HPP_
#define GIGAMONKEY_P2P_MESSAGES_MESSAGES_HPP_
#include <boost/shared_ptr.hpp>
#include "messagePayload.hpp"
#include "versionPayload.hpp"
#include "unknownPayload.hpp"
#include "blankPayload.hpp"
#include "pingPayload.hpp"
namespace Gigamonkey::Bitcoin::P2P::Messages {
	struct Deleter {
	  public:
		void operator()(MessagePayload *ptr) {
			std::cout << "deleting Message << '\n'";
		}
	};
	boost::shared_ptr<MessagePayload> makePayload(const std::string &payloadName, data::bytes input, Networks network) {
		if (payloadName == "version") {
			return boost::shared_ptr<VersionPayload>(new VersionPayload(input, input.size(),network));
		} else if(payloadName == "verack") {
			return boost::shared_ptr<BlankPayload>(new BlankPayload(input,input.size(),network));
		}
		else if(payloadName == "ping" || payloadName=="pong") {
			return boost::shared_ptr<PingPayload>(new PingPayload(input,input.size(), network));
		}
		else {
			return boost::shared_ptr<UnknownPayload>(new UnknownPayload(input,input.size(), network));
		}

	}

	boost::shared_ptr<MessagePayload> makePayload(const std::string &payloadName, Networks network) {
		if (payloadName == "version") {
			return boost::shared_ptr<VersionPayload>(new VersionPayload(0,network), Deleter());
		} else if (payloadName == "verack") {
			return boost::shared_ptr<BlankPayload>(new BlankPayload(0,network));
		} else if(payloadName == "ping" || payloadName=="pong") {
			return boost::shared_ptr<PingPayload>(new PingPayload( 0,network));
		} else {
			return boost::shared_ptr<UnknownPayload>(new UnknownPayload(0,network));
		}
	}
}
#endif //GIGAMONKEY_P2P2_MESSAGES_MESSAGES_HPP_
