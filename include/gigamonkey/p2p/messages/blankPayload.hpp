// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_P2P_MESSAGES_BLANKPAYLOAD_HPP_
#define GIGAMONKEY_P2P_MESSAGES_BLANKPAYLOAD_HPP_

#include <utility>

#include "messagePayload.hpp"
namespace Gigamonkey::Bitcoin::P2P::Messages {
	class BlankPayload: public MessagePayload {
	  public:
		explicit BlankPayload(int size,Networks network): MessagePayload(size,network){};
		BlankPayload(data::bytes data,int size,Networks network): MessagePayload(data,size,network){};
		explicit operator data::bytes() override {
			return {};
		}
		reader &read(reader &stream) override {
			std::cout << "Reading blank" << std::endl;
			// TODO: Finish this function
			return stream;
		}
		writer &write(writer &stream) const override {
			std::cout << "Writing blank" << std::endl;
			// TODO: Finish this function
			return stream;
		}
		~BlankPayload() override = default;
	};
}
#endif //GIGAMONKEY_P2P_MESSAGES_BLANKPAYLOAD_HPP_
