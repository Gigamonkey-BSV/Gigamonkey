// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/p2p/messages/message_header.hpp>
#include <sstream>

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

    uint32_t MessageHeader::getPayloadSize() const {
        return _payloadSize;
    }

    void MessageHeader::setPayloadSize(uint32_t payloadSize) {
        _payloadSize = payloadSize;
    }

    const boost::array<unsigned char, 4> &MessageHeader::getChecksum() const {
        return _checksum;
    }

    void MessageHeader::setChecksum(const boost::array<unsigned char, 4> &checksum) {
        _checksum = checksum;
    }

    std::istream &operator>>(std::istream &in,MessageHeader &d) {
        boost::array<unsigned char,4> magic{};
        for(int i=0;i<4;i++)
            in >> magic[i];
        char commandName[12];
        for(auto & i : commandName)
            in >> i;
        boost::array<unsigned char,4> pay{};
        for(int i=0;i<4;i++)
            in >> pay[i];
        uint32_t payloadSize = (pay[3] << 24 | pay[2] << 16 | pay[1] << 8 | pay[0]);
        boost::array<unsigned char,4> check{};
        for(int i=0;i<4;i++)
            in >> check[i];
        d.setMagicBytes(magic);
        d.setCommandName(std::string(commandName));
        d.setPayloadSize(payloadSize);
        d.setChecksum(check);
        return in;
    }

    std::ostream& operator<< (std::ostream& out, MessageHeader& d) {
        for(int i=0;i<4;i++)
            out << static_cast<unsigned char>(d.getMagicBytes()[i]);
        std::string commandName=d.getCommandName();
        for(int i=0;i<12;i++)
            if(i<commandName.length()) [[likely]]
                out << static_cast<unsigned char>(commandName[i]);
            else [[unlikely]]
                out << static_cast<unsigned char>(0);
        unsigned char* size;
        uint32_t payload_size=d.getPayloadSize();
        size=(unsigned char*)&payload_size;
        for(int i=0;i<4;i++){
            unsigned char tmp = size[i];

            out << tmp;
        }
        for(int i=0;i<4;i++)
            out << static_cast<unsigned char>(d.getChecksum()[i]);
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
}
