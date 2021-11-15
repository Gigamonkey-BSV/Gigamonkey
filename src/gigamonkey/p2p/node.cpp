// Copyright (c) 2019-2021 Katrina Knight
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include "gigamonkey/p2p/node.hpp"
#include "gigamonkey/p2p/messages/message_header.hpp"
#include "gigamonkey/p2p/messages/version_message.hpp"

#include <utility>

namespace Gigamonkey::Bitcoin::P2P {

    Node::pointer Node::create(boost::asio::io_context &io_context, bool server,Networks network) {
        return pointer(new Node(io_context,server,network));
    }

    [[noreturn]] void Node::start(std::string address, std::string port) {
        _stream.connect(std::move(address),std::move(port));
        if(!_server) {
            Messages::Message msg= generateVersion(true);
            _stream << msg;
        }
        while(_stream.peek()!=EOF) {
            Messages::Message incoming(_network);
            Messages::MessageHeader header(_network);
            _stream >> header;
            incoming.setHead(header);
            _stream >> incoming;
            std::cout << "Recieved: " << (std::string)incoming << std::endl;
        }
    }

    Messages::Message Node::generateVersion(bool initial) {
        Messages::Message msg=Messages::Message::create("version",_network);
        boost::shared_ptr<Messages::VersionMessage> version=boost::static_pointer_cast<Messages::VersionMessage>(msg.getPayload());
        version->setInitial(initial);
        version->setVersion(GIGAMONKEY_P2P_VERSION);
        version->setServices(1 << 0);
        version->getAddressFrom().setIP(0,0,0,0);
        version->getAddressFrom().setPort(0);
        version->setTimestamp(std::chrono::system_clock::now().time_since_epoch().count());
        if(_stream.good() && _stream.socket().is_open()) {
            version->getAddressTo().setPort(_stream.socket().remote_endpoint().port());
            auto addr = _stream.socket().remote_endpoint().address();
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
        return msg;
    }


}

