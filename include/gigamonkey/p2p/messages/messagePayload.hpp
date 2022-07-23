// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#ifndef GIGAMONKEY_P2P_MESSAGES_MESSAGEPAYLOAD_HPP_
#define GIGAMONKEY_P2P_MESSAGES_MESSAGEPAYLOAD_HPP_
#include "data/cross.hpp"
#include "gigamonkey/p2p/networks.hpp"
#include "gigamonkey/types.hpp"
namespace Gigamonkey::Bitcoin::P2P::Messages {
/**
 * Payload abstract class
 */
	class MessagePayload {
	  public:
		MessagePayload(const data::bytes& input, int size,Networks network) :_size(size){};
		MessagePayload(int size,Networks network): _size(size) {};
		virtual ~MessagePayload() =default;
		virtual explicit operator data::bytes() = 0;
		virtual reader &read(reader &stream) = 0;
		virtual writer &write(writer &stream) const = 0;

		[[nodiscard]] int getSize() const { return _size;}
		void setSize(int size) { _size = size;}

		/**
		 * Reads an address from a stream
		 * @param stream Stream to read from
		 * @param message_payload Message to read into
		 * @return stream
		 */
		friend reader &operator>>(reader &stream, MessagePayload &message_payload) {
			return message_payload.read(stream);
		}

		/**
		 * Writes an AssociationID to stream
		 * @param stream Stream to write to
		 * @param message_payload MessagePayload to write
		 * @return Stream
		 */
		friend writer &operator<<(writer &stream, const MessagePayload &message_payload){
			return message_payload.write(stream);
		}

	  private:
		int _size;
	};
}
#endif //GIGAMONKEY_P2P_MESSAGES_MESSAGEPAYLOAD_HPP_
