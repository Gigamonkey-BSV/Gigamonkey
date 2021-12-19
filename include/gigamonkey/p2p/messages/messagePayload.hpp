// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef GIGAMONKEY_P2P_MESSAGES_MESSAGEPAYLOAD_HPP_
#define GIGAMONKEY_P2P_MESSAGES_MESSAGEPAYLOAD_HPP_
#include "data/cross.hpp"
#include "gigamonkey/p2p/networks.hpp"
namespace Gigamonkey::Bitcoin::P2P::Messages {
/**
 * Payload abstract class
 */
class MessagePayload {
 public:
  MessagePayload(data::bytes input, Networks network) {};
  MessagePayload(Networks network) {};
  virtual explicit operator data::bytes() = 0;
};
}
#endif //GIGAMONKEY_P2P2_MESSAGES_MESSAGEPAYLOAD_HPP_
