// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_P2P_ADDRESS_HPP_
#define GIGAMONKEY_P2P_ADDRESS_HPP_
#include <boost/array.hpp>
#include <ostream>
#include "data/encoding/endian/arithmetic.hpp"
#include "data/cross.hpp"
namespace Gigamonkey::Bitcoin::P2P {

/**
 * Class representing a BSV p2p Address
 */
	class Address {
	  public:

		/**
		 * Constructs a blank address
		 */
		Address() : Address(false) {};

		/**
		 * Constructs a blank address
		 * @param initial is this part of the initial version
		 */
		explicit Address(bool initial);

		/**
		 * Constructs an address from input
		 * @param input input to construct from
		 * @param initial is this part of the initial version
		 */
		Address(data::bytes input, bool initial);

		/**
		 * Constructs an address from input
		 * @param input
		 */
		explicit Address(data::bytes input) : Address(input, false) {};

		/**
		 * Address in bytes
		 * @return byte array of address
		 */
		explicit operator data::bytes();

		/**
			   * Sets an IPv4 address into the address
			   * @param a First Byte
			   * @param b Second Byte
			   * @param c Third Byte
			   * @param d Fourth Byte
			   */
		void setIP(int a, int b, int c, int d);

		/**
		 * Sets an IPv6 address into the address
		 * @param ip IPv6 address to use
		 */
		void setIP(boost::array<unsigned char, 16> ip);

		/**
		 * Gets the IP array
		 * @return Array of IP in IPV6 format
		 */
		[[nodiscard]] boost::array<unsigned char, 16> getIP();

		/**
		 * gets Port the address is set to use
		 * @return port the address uses
		 */
		[[nodiscard]] data::uint16_big getPort() const;

		/**
		 * Sets the port the address is to use
		 * @param port port the address uses
		 */
		void setPort(data::uint16_big port);

		/**
		 * Is this address in the initial message?
		 * @return true if address is part of the initial version handshake
		 */
		[[nodiscard]] bool isInitial() const;

		/**
		 * Sets if this address is in the initial message
		 * @param initial true if part of the initial version handshake, false otherwise
		 */
		void setInitial(bool initial);

		/**
		 * Gets the services field for this address
		 * @return uint64 containing a bitmasked selection of the services
		 */
		[[nodiscard]] data::uint64_little getServices() const;

		/**
		 * Sets the services field for this address
		 * @param services uint64 containing a bitmasked selection of the services
		 */
		void setServices(data::uint64_little services);

		/**
		 * Current timestamp for the address
		 * @return timestamp in unix time format
		 */
		[[nodiscard]] data::int32_little getTimestamp() const;

		/**
		 * Current timestamp for the address
		 * @param timestamp timestamp in unix time format
		 */
		void setTimestamp(data::int32_little timestamp);

		friend std::ostream &operator<<(std::ostream &os, const Address &address);
	  private:
		data::uint64_little _services{};
		data::int32_little _timestamp{};
		boost::array<unsigned char, 16> _ip{};
		data::uint16_big _port{};
		bool _initial;
	};
}
#endif //GIGAMONKEY_P2P2_ADDRESS_HPP_
