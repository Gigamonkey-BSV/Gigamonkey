// Copyright (c) 2021 Katrina Knight
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/p2p/address.hpp>
#include <sstream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "data/encoding/endian/endian.hpp"

namespace Gigamonkey::Bitcoin::P2P
{
    Address::Address() {
        _initial=false;
    }

    std::istream &operator>>(std::istream &in, Address &d) {
        if(!d.isInitial()) {
            boost::array<unsigned char,4> timeBytes{};
            for (int i = 0; i < 4; i++)
                in >> timeBytes[i];
            int32_t time = (timeBytes[3] << 24 | timeBytes[2] << 16 | timeBytes[1] << 8 | timeBytes[0]);
            d.setTimestamp(time);
        }
        boost::array<unsigned char,8> servicesBytes{};
        for (int i = 0; i < 8; i++)
            in >> servicesBytes[i];
        uint64_t services = (servicesBytes[7] << 56 |servicesBytes[6] << 48 |servicesBytes[5] << 40 |servicesBytes[4] << 32 | servicesBytes[3] << 24 | servicesBytes[2] << 16 | servicesBytes[1] << 8 | servicesBytes[0]);
        d.setServices(services);
        boost::array<unsigned char,16> ip{};
        for(int i=0;i<16;i++) {
            in >> ip[i];
        }
        d.setIP(ip);
        //data::uint16_big port;

        //in >> port;
        boost::array<unsigned char,2> portBytes{};
        for (int i = 0; i < 2; i++)
            in >> portBytes[i];
        uint16_t port = ( portBytes[0] << 8 | portBytes[1   ]);
        d.setPort(port);
        return in;
    }

    std::ostream &operator<<(std::ostream &out, Address &d) {
        if(!d.isInitial()) {
            unsigned char* initial;
            int32_t initial_num=d.getTimestamp();
            initial=(unsigned char*)&initial_num;
            for(int i=0;i<4;i++){
                unsigned char tmp = initial[i];
                out << tmp;
            }
        }
        unsigned char* services;
        uint64_t services_num=d.getServices();
        services = (unsigned char*)&services_num;
        for(int i=0;i<8;i++){
            unsigned char tmp = services[i];
            out << tmp;
        }
        auto ips=d.getIP();
        for(auto ipByte : ips)
            out << ipByte;

        unsigned char* port;
        int16_t port_num=d.getPort();
        port=(unsigned char*)&port_num;
        out << port[1];
        out << port[0];
        //out << d.getPort();
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

    uint64_t Address::getServices() const {
        return _services;
    }

    void Address::setServices(uint64_t services) {
        _services = services;
    }

    int32_t Address::getTimestamp() const {
        return _timestamp;
    }

    void Address::setTimestamp(int32_t timestamp) {
        _timestamp = timestamp;
    }

    uint16_t Address::getPort() const {
        return _port;
    }

    void Address::setPort(uint16_t port) {
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

