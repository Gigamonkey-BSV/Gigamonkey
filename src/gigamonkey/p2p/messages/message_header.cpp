// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/p2p/messages/message_header.hpp>
#include <sstream>
#include "gigamonkey/p2p/messages/utils.hpp"

namespace Gigamonkey::Bitcoin::P2P::Messages
{

    const boost::array<unsigned char, 4> &MessageHeader::getMagicBytes() const {
        return _magicBytes;
    }

    void MessageHeader::setMagicBytes(const boost::array<unsigned char, 4> &magicBytes) {
        _magicBytes = magicBytes;
    }

    const std::string MessageHeader::getCommandName() const {
        return std::string(_commandName);
    }

    data::uint32_little MessageHeader::getPayloadSize() const {
        return _payloadSize;
    }

    void MessageHeader::setPayloadSize(data::uint32_little payloadSize) {
        _payloadSize = payloadSize;
    }

    const Gigamonkey::checksum &MessageHeader::getChecksum() const {
        return _checksum;
    }

    void MessageHeader::setChecksum(const Gigamonkey::checksum &checksum) {
        _checksum = checksum;
    }

    std::istream &operator>>(std::istream &in,MessageHeader &d) {
        bool valid=true;
        int cur=0;
        boost::array<unsigned char,4> magic= getMagicNum(d._network);
        do {
            unsigned char tmp;
            in >> tmp;
            if(tmp!=magic[cur]) {
                cur=0;
                valid=false;
            }
            else {
                cur++;
                valid=true;
            }
        } while(!valid);
        char commandName[12];
        for(auto & i : commandName)
            in >> i;
        data::uint32_little payloadSize{};
        decode(in,payloadSize);
        Gigamonkey::checksum check{};
        decode(in,check);
        d.setMagicBytes(magic);
        d.setCommandName(std::string(commandName));
        d.setPayloadSize(payloadSize);
        d.setChecksum(check);
        return in;
    }

    std::ostream& operator<< (std::ostream& out, const MessageHeader& d) {
        for(int i=0;i<4;i++)
            out << static_cast<unsigned char>(d.getMagicBytes()[i]);
        std::string commandName=d.getCommandName();
        for(int i=0;i<12;i++)
            if(i<commandName.length()) [[likely]]
                out << static_cast<unsigned char>(commandName[i]);
            else [[unlikely]]
                out << static_cast<unsigned char>(0);
        unsigned char* size;
        data::uint32_little payload_size=d.getPayloadSize();
        encode(out,payload_size);
        Gigamonkey::checksum check=d.getChecksum();
        encode(out,check);
        return out;
    }

    void MessageHeader::setCommandName(std::string name) {
        for(int i=0;i<12;i++)
        {
            if(name.length()>i) [[likely]]
                _commandName[i]=name[i];
            else [[unlikely]]
                _commandName[i]=0x00;
        }
    }

    MessageHeader::operator std::string() const {
        std::stringstream str;
        str << "Magic bytes: ";
        for(unsigned char i: _magicBytes) {
            str << std::hex << (unsigned int) i << ", ";
        }
        str << " Command Name: " << _commandName << " Payload Size: "
            << _payloadSize << " Checksum: " ;
        for(unsigned char i:_checksum)
            str << std::hex << (unsigned int) i << ", ";
        return str.str();
    }

    MessageHeader::MessageHeader(Networks network) : _network(network) {}
}
