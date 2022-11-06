// Copyright (c) 2022 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_P2P
#define GIGAMONKEY_P2P_P2P

#include <gigamonkey/p2p/header_string.hpp>

namespace Gigamonkey::Bitcoin::p2p {
    
    // message types
    struct ping;
    struct pong;
    struct version;
    struct verack;
    struct addr;
    struct getaddr;
    struct inv;
    struct getdata;
    struct getheaders;
    struct headers;
    struct getblocks;
    struct notfound;
    struct reject;
    
    data::reader<byte> &operator>>(data::reader<byte> &, ping &);
    data::reader<byte> &operator>>(data::reader<byte> &, pong &);
    data::reader<byte> &operator>>(data::reader<byte> &, version &);
    data::reader<byte> &operator>>(data::reader<byte> &, verack &);
    data::reader<byte> &operator>>(data::reader<byte> &, addr &);
    data::reader<byte> &operator>>(data::reader<byte> &, getaddr &);
    data::reader<byte> &operator>>(data::reader<byte> &, addr &);
    data::reader<byte> &operator>>(data::reader<byte> &, inv &);
    data::reader<byte> &operator>>(data::reader<byte> &, getdata &);
    data::reader<byte> &operator>>(data::reader<byte> &, headers &);
    data::reader<byte> &operator>>(data::reader<byte> &, getheaders &);
    data::reader<byte> &operator>>(data::reader<byte> &, getblocks &);
    data::reader<byte> &operator>>(data::reader<byte> &, notfound &);
    data::reader<byte> &operator>>(data::reader<byte> &, reject &);
    
    data::writer<byte> &operator<<(data::writer<byte> &, ping &);
    data::writer<byte> &operator<<(data::writer<byte> &, pong &);
    data::writer<byte> &operator<<(data::writer<byte> &, version &);
    data::writer<byte> &operator<<(data::writer<byte> &, verack &);
    data::writer<byte> &operator<<(data::writer<byte> &, addr &);
    data::writer<byte> &operator<<(data::writer<byte> &, getaddr &);
    data::writer<byte> &operator<<(data::writer<byte> &, addr &);
    data::writer<byte> &operator<<(data::writer<byte> &, inv &);
    data::writer<byte> &operator<<(data::writer<byte> &, getdata &);
    data::writer<byte> &operator<<(data::writer<byte> &, headers &);
    data::writer<byte> &operator<<(data::writer<byte> &, getheaders &);
    data::writer<byte> &operator<<(data::writer<byte> &, getblocks &);
    data::writer<byte> &operator<<(data::writer<byte> &, notfound &);
    data::writer<byte> &operator<<(data::writer<byte> &, reject &);
    
    template <typename message>
    constexpr const message_type_string &message_type();
    
    template const message_type_string &message_type<ping>();
    template const message_type_string &message_type<pong>();
    template const message_type_string &message_type<version>();
    template const message_type_string &message_type<verack>();
    template const message_type_string &message_type<addr>();
    template const message_type_string &message_type<getaddr>();
    template const message_type_string &message_type<inv>();
    template const message_type_string &message_type<getdata>();
    template const message_type_string &message_type<getheaders>();
    template const message_type_string &message_type<headers>();
    template const message_type_string &message_type<transaction>();
    template const message_type_string &message_type<block>();
    template const message_type_string &message_type<getblocks>();
    template const message_type_string &message_type<notfound>();
    template const message_type_string &message_type<reject>();
}
