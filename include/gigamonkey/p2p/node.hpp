// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef GIGAMONKEY_NODE_HPP
#define GIGAMONKEY_NODE_HPP

#include <boost/enable_shared_from_this.hpp>
#include <queue>
#include "gigamonkey/p2p/messages/message.hpp"
#include "gigamonkey/p2p/networks.hpp"
#include <boost/asio.hpp>

namespace Gigamonkey::Bitcoin::P2P {
/**
 * Node connecting to the p2p
 */
	class Node : public boost::enable_shared_from_this<Node> {
	  private:
		std::queue<Messages::Message> _incoming;
		std::queue<Messages::Message> _outgoing;
		boost::asio::io_context &_context;
		bool _server{};
		boost::asio::ip::tcp::socket _socket;
		Networks _network;
		data::bytes _content{24};
		bool _connected = false;
		bool _connecting = false;
		std::string _error{};
		int32_t _version;
	  public:

		boost::asio::ip::tcp::socket &getSocket() {
			return _socket;
		}

		/**
		 * Constructs a node
		 * @param context IO context for the server
		 * @param network network node is meant for
		 */
		Node(boost::asio::io_context &context, bool server, Networks network)
			: _server(server), _context(context), _socket(_context), _network(network) {}

		/**
		 * Gets the last incoming message.
		 * @warning Pops the message off the queue
		 * @return message
		 */
		inline Messages::Message getLastIncoming() {
			auto front = _incoming.front();
			_incoming.pop();
			return front;
		}

		Messages::Message generateVersion(bool initial);

		void connect(std::string address, std::string port);

		void connected(const boost::system::error_code &ec);

		void readHeader(const boost::system::error_code &ec, std::size_t bytes_transferred);
		void readPayload(const boost::system::error_code &ec,
						 std::size_t bytes_transferred,
						 Messages::MessageHeader header);
		void processMessages();
		static boost::shared_ptr<Node> create(boost::asio::io_context &context, bool b, Networks networks);

	};
}
#endif //GIGAMONKEY_NODE_HPP
