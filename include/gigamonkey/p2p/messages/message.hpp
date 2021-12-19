// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_P2P_MESSAGES_MESSAGE_HPP_
#define GIGAMONKEY_P2P_MESSAGES_MESSAGE_HPP_

#include <boost/shared_ptr.hpp>
#include <ostream>
#include "messageHeader.hpp"
#include "messagePayload.hpp"
namespace Gigamonkey::Bitcoin::P2P::Messages {
/**
 * P2P Message
 */
class Message {
 private:
  Messages::MessageHeader _header;
  boost::shared_ptr<Messages::MessagePayload> _payload;
  Networks _network;
 public:
  [[nodiscard]] MessageHeader getHeader() {
	return _header;
  }

  /**
   * Gets payload
   * @return
   */
  boost::shared_ptr<MessagePayload> getPayload() {
	return _payload;
  }

  /**
   * Sets the header up
   */
  void setupHeader();

  void setupBlankPayload();

  Networks getNetwork() {
	return _network;
  }

  void setNetwork(Networks network) {
	_network=network;
  }
  bool isValid();

  static Message create(const std::string& commandName,Networks network);
  static Message createFrom(MessageHeader header,data::bytes input,Networks network);
  Message(Messages::MessageHeader header,Networks network);
  explicit Message(Networks network);
  explicit operator data::bytes();
  friend ostream &operator<<(ostream &os, const Message &message);
};
}
#endif //GIGAMONKEY_P2P2_MESSAGES_MESSAGE_HPP_
