// Copyright (c) 2022 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_TEST_P2P_TESTADDRESSMANAGER_HPP_
#define GIGAMONKEY_TEST_P2P_TESTADDRESSMANAGER_HPP_
#include <gigamonkey/p2p/AbstractAddressManager.hpp>

namespace Gigamonkey::Bitcoin::P2P {

	struct DescendingOrderAddress {
		bool operator()(const NodeAddress & lhs, const NodeAddress & rhs) {
			return lhs.timestamp > rhs.timestamp;
		}
	};

	class TestAddressManager : public AbstractAddressManager {
	  public:
		boost::heap::priority_queue<NodeAddress,boost::heap::compare<DescendingOrderAddress>> addresses;
		std::list<NodeAddress> getAddresses() override;
		NodeAddress getNextAddress(int index, data::uint64 required_services) override;
		void addAddress(Address address) override;
	};
}
#endif //GIGAMONKEY_TEST_P2P_TESTADDRESSMANAGER_HPP_
