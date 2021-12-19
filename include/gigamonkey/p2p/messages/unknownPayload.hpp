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
  explicit UnknownPayload(Networks network) : MessagePayload(network), _network(network) {};
  UnknownPayload(const data::bytes &data, Networks network) : MessagePayload(data, network),
															  _data(data),
															  _network(network) {}
  data::bytes getData() { return _data; }
  explicit operator data::bytes() override {
	  return this->_data;
  }

};
}
#endif //GIGAMONKEY_P2P_MESSAGES_UNKNOWNPAYLOAD_HPP_
