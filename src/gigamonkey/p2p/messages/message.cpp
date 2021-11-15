// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sstream>
#include <utility>
#include "gigamonkey/p2p/messages/message.hpp"
#include "gigamonkey/p2p/messages/messages.hpp"

namespace Gigamonkey::Bitcoin::P2P::Messages {

    std::istream &operator>>(std::istream &in, Message &d) {
        d.payload->setSize(d.getHead().getPayloadSize());
        //U payload;
        in >> *d.payload.get();
        //d.setPayload(payload);
        return in;
    }

    std::ostream &operator<<(std::ostream &out, Message &d) {
        d.setupHeader();
        out << d.getHead();
        out << d.getPayload();
        return out;
    }

    Message::operator std::string() {
        std::stringstream ss;
        ss << "Header: " << (std::string)getHead() << " Body: " << (std::string)*(getPayload()) << std::endl;
        return ss.str();
    }


    void Message::setupHeader() {
        auto payloadBytes = (data::bytes)*getPayload();
        head.setPayloadSize(payloadBytes.size());
        Gigamonkey::checksum check= checksum(payloadBytes);
        head.setChecksum(check);
    }


    bool Message::isValid() {
        auto payloadBytes = (data::bytes)*getPayload();
        Gigamonkey::checksum check= checksum(payloadBytes);
        return head.getPayloadSize() == payloadBytes.size() && check == head.getChecksum();
    }

    void Message::setupPayload() {
        payload=makePayload(getName());
    }

    Message Message::create(string commandName, Networks network) {
        Message msg(network);
        msg.setNetwork(network);
        msg.getHead().setMagicBytes(getMagicNum(network));
        msg.getHead().setCommandName(std::move(commandName));
        msg.setupPayload();
        return msg;
    }

    Networks Message::getNetwork() const {
        return network;
    }

    void Message::setNetwork(Networks network) {
        Message::network = network;
    }


}