// Copyright (c) 2022 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_P2P_ABSTRACTADDRESSMANAGER_HPP_
#define GIGAMONKEY_P2P_ABSTRACTADDRESSMANAGER_HPP_

#include <string>
#include <list>
#include <boost/heap/priority_queue.hpp>
#include "data/encoding/endian/arithmetic.hpp"
#include "address.hpp"
namespace Gigamonkey::Bitcoin::P2P {
	struct NodeAddress {
		std::string IpAddress{};
		data::uint16_big port{};
		data::uint64_little services{};
		data::int32_little timestamp{};
	};

	class AbstractAddressManager {
	  public:
		virtual std::list<NodeAddress> getAddresses()=0;
		virtual NodeAddress getNextAddress(int index, data::uint64 required_services)=0;
		virtual void addAddress(Address address)=0;
	};
}
#endif //GIGAMONKEY_P2P_ABSTRACTADDRESSMANAGER_HPP_
