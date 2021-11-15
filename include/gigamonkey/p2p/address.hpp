// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_ADDRESS_HPP
#define GIGAMONKEY_ADDRESS_HPP

#include <cstdint>
#include <istream>
#include <boost/array.hpp>
#include "data/encoding/endian/arithmetic.hpp"

namespace Gigamonkey::Bitcoin::P2P
{
    /**
     * Class representing an address type
     */
    class Address {
    public:
        /**
         * Constructs a default non-initial address
         */
        Address();

        /**
         * Constructs an address with an initial setting
         * @param initial Whether this address is in the initial version packet or not.
         */
        explicit Address(bool initial);


        /**
         * Sets an IPv4 address into the address
         * @param a First Byte
         * @param b Second Byte
         * @param c Third Byte
         * @param d Fourth Byte
         */
        void setIP(int a,int b,int c,int d);

        /**
         * Sets an IPv6 address into the address
         * @param ip IPv6 address to use
         */
        void setIP(boost::array<unsigned char,16> ip);

        /**
         * Gets the IP array
         * @return Array of IP in IPV6 format
         */
        [[nodiscard]] boost::array<unsigned char,16> getIP();

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

        /**
         * Input Stream Operator to decode an Address from stream
         * @param in Input Stream
         * @param d Address
         * @return Input Stream
         */
        friend std::istream& operator>> (std::istream& in, Address& d);

        /**
         * Output Stream Operator to encode an Address into stream
         * @note This does not output a human friendly string
         * @param out Output Stream
         * @param d Address
         * @return Output Stream
         */
        friend std::ostream& operator<< (std::ostream& out, Address& d);

        /**
         * Converts an Address to a human friendly string
         * @return String containing the address.
         */
        explicit operator std::string() const;

    private:
        data::uint64_little _services{};
        data::int32_little _timestamp{};
        boost::array<unsigned char,16> _ip{};
        data::uint16_big _port{};
        bool _initial;

    };
}
#endif //GIGAMONKEY_ADDRESS_HPP
