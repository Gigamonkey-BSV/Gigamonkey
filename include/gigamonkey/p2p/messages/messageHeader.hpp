// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef GIGAMONKEY_P2P_MESSAGES_MESSAGEHEADER_HPP_
#define GIGAMONKEY_P2P_MESSAGES_MESSAGEHEADER_HPP_

#include <ostream>
#include "data/cross.hpp"
#include "gigamonkey/p2p/networks.hpp"
#include "gigamonkey/p2p/checksum.hpp"
namespace Gigamonkey::Bitcoin::P2P::Messages {
class MessageHeader {
 public:
  friend ostream &operator<<(ostream &os, const MessageHeader &header);
  /**
   * Constructs a message header
   * @param input Input bytes
   * @param network Network message is on
   */
  MessageHeader(data::bytes input,Networks network);

  explicit MessageHeader(Networks network);

  /**
   * Converts message Header to bytes
   * @return bytes form of Message Header
   */
  explicit operator data::bytes();

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
  [[nodiscard]] std::string getCommandName() const;

  /**
   * Sets the command name of the message the header is for
   * @param name Command name as a std::string
   */
  void setCommandName(std::string name);

  /**
   * Gets the size of the payload of the message
   * @return Size of the payload of the message in bytes
   */
  [[nodiscard]] data::uint32_little getPayloadSize() const;

  /**
   * Sets the size of the payload of the message
   * @param payloadSize Size of the payload of the message in bytes
   */
  void setPayloadSize(data::uint32_little payloadSize);

  /**
   * Gets the Checksum of the message payload
   * @return 4 bytes containing the checksum of the message payload
   */
  [[nodiscard]] const Gigamonkey::checksum &getChecksum() const;

  /**
   * Sets the Checksum of the message payload
   * @param checksum 4 byte array containing the checksum of the message payload
   */
  void setChecksum(const Gigamonkey::checksum &checksum);
 private:
  boost::array<unsigned char, 4> _magicBytes;
  char _commandName[12];
  data::uint32_little _payloadSize;
  Gigamonkey::checksum _checksum;
  Networks _network;
};
}
#endif //GIGAMONKEY_P2P2_MESSAGES_MESSAGEHEADER_HPP_
