// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <netinet/in.h>
#include <arpa/inet.h>
#include "gigamonkey/p2p/address.hpp"
namespace Gigamonkey::Bitcoin::P2P {

	Address::Address(bool initial) {
		_initial = initial;
	}
	Address::Address(data::bytes input, bool initial) {
		_initial = initial;
		auto cur = input.begin();
		if (!initial) {
			std::copy(cur, cur + _timestamp.size(), _timestamp.begin());
			cur = cur + _timestamp.size();
		}
		std::copy(cur, cur + _services.size(), _services.begin());
		cur += _services.size();
		std::copy(cur, cur + 16, std::begin(_ip));
		cur += 16;
		std::copy(cur, cur + _port.size(), _port.begin());
		cur += _port.size();
	}
	Address::operator data::bytes() {
		data::bytes output(_initial ? 26 : 30);
		auto cur = output.begin();
		if (!_initial) {
			std::copy(_timestamp.begin(), _timestamp.end(), cur);
			cur += _timestamp.size();
		}
		std::copy(_services.begin(), _services.end(), cur);
		cur += _services.size();
		std::copy(std::begin(_ip), std::end(_ip), cur);
		cur += 16;
		std::copy(_port.begin(), _port.end(), cur);
		cur += _port.size();
		return output;
	}
	void Address::setIP(int a, int b, int c, int d) {
		_ip[0] = _ip[1] = _ip[2] = _ip[3] = _ip[4] = _ip[5] = _ip[6] = _ip[7] = _ip[8] = _ip[9] = 0x00;
		_ip[10] = 0xff;
		_ip[11] = 0xff;
		_ip[12] = a;
		_ip[13] = b;
		_ip[14] = c;
		_ip[15] = d;
	}
	void Address::setIP(boost::array<unsigned char, 16> ip) {
		std::copy(ip.begin(), ip.end(), _ip.begin());
	}
	boost::array<unsigned char, 16> Address::getIP() {
		return _ip;
	}
	data::uint16_big Address::getPort() const {
		return _port;
	}
	void Address::setPort(data::uint16_big port) {
		_port = port;
	}
	bool Address::isInitial() const {
		return _initial;
	}
	void Address::setInitial(bool initial) {
		_initial = initial;
	}
	data::uint64_little Address::getServices() const {
		return _services;
	}
	void Address::setServices(data::uint64_little services) {
		_services = services;

	}
	data::int32_little Address::getTimestamp() const {
		return _timestamp;
	}
	void Address::setTimestamp(data::int32_little timestamp) {
		_timestamp = timestamp;
	}
	std::ostream &operator<<(std::ostream &os, const Address &address) {
		char ipstr[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, address._ip.begin(), ipstr, sizeof(ipstr));
		os << "services: " << address._services << " timestamp: " << address._timestamp << " ip: " << ipstr
		   << " port: " << address._port << " initial_: " << address._initial;
		return os;

	}

}
