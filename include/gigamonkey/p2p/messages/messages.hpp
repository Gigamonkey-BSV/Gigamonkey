// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_P2P_MESSAGES_MESSAGES_HPP_
#define GIGAMONKEY_P2P_MESSAGES_MESSAGES_HPP_
#include <boost/shared_ptr.hpp>
#include "messagePayload.hpp"
#include "versionPayload.hpp"
#include "unknownPayload.hpp"
namespace Gigamonkey::Bitcoin::P2P::Messages {
struct Deleter
{
 public:
  void operator()(MessagePayload* ptr)
  {
	std::cout << "deleting Message << '\n'";
  }
};
boost::shared_ptr<MessagePayload> makePayload(const std::string &payloadName, data::bytes input, Networks network) {
  if (payloadName == "version") {
	return boost::shared_ptr<VersionPayload>(new VersionPayload(input, network));
  }
  else {
	return boost::shared_ptr<UnknownPayload>(new UnknownPayload(input,network));
  }

}

boost::shared_ptr<MessagePayload> makePayload(const std::string &payloadName, Networks network) {
  if (payloadName == "version") {
	return boost::shared_ptr<VersionPayload>(new VersionPayload(network),Deleter());
  }
  else {
	return boost::shared_ptr<UnknownPayload>(new UnknownPayload(network));
  }
}
}
#endif //GIGAMONKEY_P2P2_MESSAGES_MESSAGES_HPP_
