
// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_ADDR
#define GIGAMONKEY_P2P_ADDR

#include <gigamonkey/p2p/empty.hpp>
#include <gigamonkey/p2p/command.hpp>
#include <gigamonkey/p2p/var_int.hpp>
#include <gigamonkey/p2p/net_address.hpp>

namespace Gigamonkey::Bitcoin::p2p {

    struct getaddr : empty {
        constexpr static command Command = command::getaddr;
    };

    struct addr {
        var_int Count;
        list<last_seen_net_address> Addresses;

        constexpr static command Command {"addr"};
        size_t serialized_size () const;
    };

    writer &operator << (writer &w, const addr &h);

    // older versions of the protocol would use this.
    struct addr_old {
        var_int Count;
        list<net_address> Addresses;

        constexpr static command Command {"addr"};
        size_t serialized_size () const;
    };

    writer &operator << (writer &w, const addr_old &h);

    writer inline &operator << (writer &w, const addr &h) {
        w << Count;
        for (const auto &addr : Addresses) w << addr;
        return w;
    }

    writer inline &operator << (writer &w, const addr_old &h) {
        w << Count;
        for (const auto &addr : Addresses) w << addr;
        return w;
    }

    size_t inline addr::serialized_size () const {
        return Count.size () + size (Addresses) * last_seen_net_address::serialized_size ();
    }

    size_t inline addr_old::serialized_size () const {
        return Count.size () + size (Addresses) * net_address::serialized_size ();
    }

}

#endif

