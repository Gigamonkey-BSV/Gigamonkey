// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "gigamonkey/p2p/messages/message.hpp"

#include <utility>
#include "gigamonkey/p2p/messages/messages.hpp"
namespace Gigamonkey::Bitcoin::P2P::Messages {

Message Message::create(const std::string& commandName,Networks network) {
	Message msg(network);
	msg._header.setMagicBytes(getMagicNum(network));
	msg._header.setCommandName(commandName);
	msg.setupBlankPayload();
	bool test = (bool)msg._payload;
	std::cout << test << std::endl;
  	return msg;
}

Message::Message(Messages::MessageHeader header, Networks network): _header(header) {

}


Message::operator data::bytes() {
  auto header=static_cast<data::bytes>(_header);
  auto body=static_cast<data::bytes>(*_payload);
  data::bytes output(header.size()+body.size());
  std::copy(header.begin(), header.end(),output.begin());
  std::copy(body.begin(),body.end(),output.begin()+header.size());
  return output;
}
Message Message::createFrom(MessageHeader header, data::bytes input, Networks network) {
  Message msg=Message(header, network);
  msg._payload=makePayload(header.getCommandName(),std::move(input),network);
  return msg;
}

void Message::setupHeader() {
	auto payloadBytes = static_cast<data::bytes>(*this->getPayload());
	_header.setPayloadSize(payloadBytes.size());
	Gigamonkey::checksum check= checksum(payloadBytes);
	_header.setChecksum(check);
}
bool Message::isValid() {
  auto payloadBytes = static_cast<data::bytes>(*this->getPayload());
  Gigamonkey::checksum check= checksum(payloadBytes);
  return payloadBytes.size() == _header.getPayloadSize() && check == _header.getChecksum();
}
ostream &operator<<(ostream &os, const Message &message) {
  os << "_header: " << message._header << " _payload: " << message._payload;
  return os;
}
Message::Message(Networks network) : _header(network){


}
void Message::setupBlankPayload() {
  _payload= makePayload(_header.getCommandName(),_network);

}

}