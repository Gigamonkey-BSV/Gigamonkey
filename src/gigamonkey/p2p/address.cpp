// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/p2p/address.hpp>
#include <sstream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "data/encoding/endian/endian.hpp"
#include "data/cross.hpp"
#include <gigamonkey/p2p/messages/utils.hpp>
namespace Gigamonkey::Bitcoin::P2P
{
    Address::Address() {
        _initial=false;
    }

    std::istream &operator>>(std::istream &in, Address &d) {
        if(!d.isInitial()) {
            data::int32_little time;
            Messages::decode(in,time);
            d.setTimestamp(time);
        }

        data::uint64_little services;
        Messages::decode(in,services);
        d.setServices(services);
        boost::array<unsigned char,16> ip{};
        for(int i=0;i<16;i++) {
            in >> ip[i];
        }
        d.setIP(ip);
        data::uint16_big port{};
        Messages::decode(in,port);
        d.setPort(port);
        return in;
    }

    std::ostream &operator<<(std::ostream &out, Address &d) {
        if(!d.isInitial()) {

            data::int32_little timestamp=d.getTimestamp();
            Messages::encode(out,timestamp);
        }
        data::uint64_little services_num=d.getServices();
        Messages::encode(out,services_num);

        auto ips=d.getIP();
        for(auto ipByte : ips)
            out << ipByte;
        data::uint16_big port_num=d.getPort();
        Messages::encode(out,port_num);
        return out;
    }

    Address::operator std::string() const {
        std::stringstream str;
        char ipstr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6,_ip.begin(),ipstr,sizeof(ipstr));
        str << "services: " << _services << " timestamp: " << _timestamp << " ip: " << ipstr
           << " port: " << _port << " initial_: " << _initial;

        return str.str();
    }

    Address::Address(bool initial) {
        _initial=initial;
    }

    void Address::setIP(int a, int b, int c, int d) {
        _ip[0]=_ip[1]=_ip[2]=_ip[3]=_ip[4]=_ip[5]=_ip[6]=_ip[7]=_ip[8]=_ip[9]=0x00;
        _ip[10] = 0xff;
        _ip[11] = 0xff;
        _ip[12]=a;
        _ip[13]=b;
        _ip[14]=c;
        _ip[15]=d;
    }

    void Address::setIP(boost::array<unsigned char, 16> ip) {
        std::copy(ip.begin(),  ip.end(),_ip.begin());
    }

    data::uint64_little Address::getServices() const {
        return _services;
    }

    void Address::setServices(data::uint64_little services) {
        _services = services;
    }

    data::int32_little Address::getTimestamp() const {
        return _timestamp;
    }

    void Address::setTimestamp(data::int32_little timestamp) {
        _timestamp = timestamp;
    }

    data::uint16_big Address::getPort() const {
        return _port;
    }

    void Address::setPort(data::uint16_big port) {
        _port = port;
    }

    bool Address::isInitial() const {
        return _initial;
    }

    void Address::setInitial(bool initial) {
        _initial = initial;
    }

    boost::array<unsigned char,16> Address::getIP() {
        return _ip;
    }
}

