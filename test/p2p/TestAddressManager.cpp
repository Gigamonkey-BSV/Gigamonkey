// Copyright (c) 2022 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.



#include <list>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "data/types.hpp"
#include "TestAddressManager.hpp"
namespace Gigamonkey::Bitcoin::P2P {
	std::list<NodeAddress> TestAddressManager::getAddresses() {
		std::list<NodeAddress> ret(addresses.size());
		std::copy(addresses.begin(), addresses.end(),ret.begin());
		return ret;
	}
	NodeAddress TestAddressManager::getNextAddress(int index,data::uint64 required_services) {
		return *(addresses.begin()+index);
	}
	void TestAddressManager::addAddress(Address address) {
		auto ip=address.getIP();
		char ipstr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, ip.begin(), ipstr, sizeof(ipstr));
		addresses.push(NodeAddress{std::string(ipstr),address.getPort(),address.getServices(),address.getTimestamp()});
	}
}
