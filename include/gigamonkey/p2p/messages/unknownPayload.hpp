// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_P2P_MESSAGES_UNKNOWNPAYLOAD_HPP_
#define GIGAMONKEY_P2P_MESSAGES_UNKNOWNPAYLOAD_HPP_

#include "messagePayload.hpp"
namespace Gigamonkey::Bitcoin::P2P::Messages {
	class UnknownPayload : public MessagePayload {

	  private:
		Networks _network;
		data::bytes _data;
	  public:
		explicit UnknownPayload(int size,Networks network) : MessagePayload(size,network), _network(network) {};
		UnknownPayload(const data::bytes &data, int size,Networks network) : MessagePayload(data,size, network),
																	_data(data),
																	_network(network) {}
		data::bytes getData() { return _data; }
		explicit operator data::bytes() override {
			return this->_data;
		}

		reader &read(reader &stream) override {
			_data.resize(getSize());
			stream >> _data;

			return stream;
		}
		writer &write(writer &stream) const override {
			stream << _data;
			return stream;
		}

		~UnknownPayload() override = default;

	};
}
#endif //GIGAMONKEY_P2P_MESSAGES_UNKNOWNPAYLOAD_HPP_
