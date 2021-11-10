// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_MESSAGEHEADER_HPP
#define GIGAMONKEY_MESSAGEHEADER_HPP

#include <boost/array.hpp>
#include <iostream>

namespace Gigamonkey::Bitcoin::P2P::Messages
{
    /**
     * Message Header
     * Every message will have a header consisting of these 4 items
     */
    class MessageHeader {
    public:

        /**
         * Gets the Magic bytes this header used
         * @return An array of 4 magic bytes
         */
        [[nodiscard]] const boost::array<unsigned char, 4> &getMagicBytes() const;

        /**
         * Sets the Magic bytes this header uses
         * @param magicBytes Array of 4 magic bytes
         */
        void setMagicBytes(const boost::array<unsigned char, 4> &magicBytes);

        /**
         * Gets the command name of the message the header is for.
         * @return Command name as a std::string
         */
        [[nodiscard]] const std::string getCommandName() const;

        /**
         * Sets the command name of the message the header is for
         * @param name Command name as a std::string
         */
        void setCommandName(std::string name);

        /**
         * Gets the size of the payload of the message
         * @return Size of the payload of the message in bytes
         */
        [[nodiscard]] uint32_t getPayloadSize() const;

        /**
         * Sets the size of the payload of the message
         * @param payloadSize Size of the payload of the message in bytes
         */
        void setPayloadSize(uint32_t payloadSize);

        /**
         * Gets the Checksum of the message payload
         * @return 4 bytes containing the checksum of the message payload
         */
        [[nodiscard]] const boost::array<unsigned char, 4> &getChecksum() const;

        /**
         * Sets the Checksum of the message payload
         * @param checksum 4 byte array containing the checksum of the message payload
         */
        void setChecksum(const boost::array<unsigned char, 4> &checksum);

        /**
         * Input Stream Operator to decode a Message Header from stream
         * @param in Input Stream
         * @param d Message Header
         * @return Input Stream
         */
        friend std::istream& operator>> (std::istream& in, MessageHeader& d);

        /**
         * Output Stream Operator to encode a Message Header into stream
         * @note This does not output a human friendly string
         * @param out Output Stream
         * @param d Message Header
         * @return Output Stream
         */
        friend std::ostream& operator<< (std::ostream& out, MessageHeader& d);

        /**
         * Converts a Message Header to a human friendly string
         * @return String containing the message header.
         */
        explicit operator std::string() const;

    private:
        boost::array<unsigned char, 4> _magicBytes;
        char _commandName[12];
        uint32_t _payloadSize;
        boost::array<unsigned char,4> _checksum;
    };
}
#endif //GIGAMONKEY_MESSAGEHEADER_HPP
