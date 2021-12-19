// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/bind/bind.hpp>
#include "gigamonkey/p2p/node.hpp"
#include "gigamonkey/p2p/messages/versionPayload.hpp"
#include "gigamonkey/p2p/constants.hpp"
namespace Gigamonkey::Bitcoin::P2P {


Messages::Message Node::generateVersion(bool initial) {
  Messages::Message msg=Messages::Message::create("version",_network);
  bool test=(bool)msg.getPayload();
  boost::shared_ptr<Messages::VersionPayload> version=boost::static_pointer_cast<Messages::VersionPayload>(msg.getPayload());
  version->setInitial(initial);
  version->setVersion(GIGAMONKEY_P2P_VERSION);
  version->setServices(1 << 0);
  version->getAddressFrom().setIP(0,0,0,0);
  version->getAddressFrom().setPort(0);
  version->setTimestamp(std::chrono::system_clock::now().time_since_epoch().count());
  if( getSocket().is_open()) {
	version->getAddressTo().setPort(getSocket().remote_endpoint().port());
	auto addr = getSocket().remote_endpoint().address();
	boost::asio::ip::address_v6 ip6addr;
	if(addr.is_v4())
	  ip6addr=boost::asio::ip::address_v6::v4_mapped(addr.to_v4());
	else
	  ip6addr=addr.to_v6();
	auto tmp = ip6addr.to_bytes();
	boost::array<unsigned char, 16> newIp{};
	for (int i = 0; i < 16; i++)
	  newIp[i] = tmp[i];
	version->getAddressTo().setIP(newIp);
  }
  else {
	version->getAddressTo().setPort(0);
	version->getAddressTo().setIP(0,0,0,0);
  }
  version->setUserAgent(GIGAMONKEY_P2P_USER_AGENT);
  msg.setupHeader();
  return msg;
}
void Node::connect(std::string address, std::string port) {
  _connecting= true;
  _error= "";
  boost::asio::ip::tcp::resolver resolver(_context);
  boost::asio::ip::tcp::resolver::results_type endpoints = resolver.resolve(address, port);
  _socket.async_connect(endpoints->endpoint(),[this](const boost::system::error_code& ec) {connected(ec);});

}
void Node::connected(const boost::system::error_code& ec) {
  if(ec.failed())
  {
	_connecting= false;
	_error=ec.message();
	return;
  }
	Messages::Message msg= generateVersion(true);
  data::bytes temp= static_cast<bytes>(msg);
  std::string res;
  boost::algorithm::hex(temp.begin(), temp.end(), back_inserter(res));
  std::cout << "msg:" << res << std::endl;
  boost::asio::const_buffer buffer(temp.data(),temp.size());
	_socket.async_send(buffer,[this](const boost::system::error_code& ec,
					   std::size_t bytes_transferred){
	  std::cout << "sent " << bytes_transferred << std::endl;

	  _content.resize(24);
	  boost::asio::mutable_buffer response_(_content.data(), _content.size());
	  boost::asio::async_read(_socket,response_,boost::asio::transfer_exactly(24),[this](const boost::system::error_code& ec,
																						  std::size_t bytes_transferred) { this->readHeader(ec,bytes_transferred);});
	});
}
boost::shared_ptr<Node> Node::create(boost::asio::io_context& context, bool server, Networks network) {
  return boost::shared_ptr<Node>(new Node(context,server,network));
}
void Node::readHeader(const boost::system::error_code &ec, std::size_t bytes_transferred) {
  if(ec.failed())
  {
	_connected = false;
	_connecting = false;
	_error=ec.message();
	return;
  }
  if(bytes_transferred!=24) {
	_connected = false;
	_connecting = false;
	_error="header size mismatch";
	return;
  }
  Messages::MessageHeader header(this->_content,_network);
  _content.resize(header.getPayloadSize());
  boost::asio::mutable_buffer response_(_content.data(), _content.size());
  boost::asio::async_read(_socket,response_,boost::asio::transfer_exactly(header.getPayloadSize()),[this, header](const boost::system::error_code& ec,
																								 std::size_t bytes_transferred) { this->readPayload(ec,bytes_transferred,header);});

}
void Node::readPayload(const boost::system::error_code &ec,
					   std::size_t bytes_transferred,
					   Messages::MessageHeader header) {
  if(ec.failed())
  {
	_connected = false;
	_connecting = false;
	_error=ec.message();
	return;
  }

  if(bytes_transferred != header.getPayloadSize()) {
	_connected = false;
	_connecting = false;
	_error="payload size mismatch";
	return;
  }
  Messages::Message msg = Messages::Message::createFrom(header,_content,_network);
  _incoming.push(msg);
  _content.resize(24);
  boost::asio::mutable_buffer response_(_content.data(), _content.size());
  boost::asio::async_read(_socket,response_,boost::asio::transfer_exactly(24),[this, header](const boost::system::error_code& ec,
																												  std::size_t bytes_transferred) { this->readHeader(ec,bytes_transferred);});
	processMessages();
}
void Node::processMessages() {
  if(!_error.empty()) {
	std::cout << _error << std::endl;
  }
	while(!_incoming.empty()){
	  auto msg = _incoming.front();
	  std::cout << "Recieved " << msg << std::endl;
	  std::cout.flush();
	  _incoming.pop();
	}
}
}
