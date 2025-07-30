
// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_NET_ADDRESS
#define GIGAMONKEY_P2P_NET_ADDRESS

#include <data/net/URL.hpp>
#include <gigamonkey/timestamp.hpp>

namespace Gigamonkey::Bitcoin::p2p {

    enum class service : uint64 {
        NODE_NETWORK = 1,
        NODE_GETUTXO = 2,
        NODE_BLOOM = 4,
        NODE_NETWORK_LIMITED = 1024
    };

    struct endpoint {
        uint_little<16> IPAddress;
        uint16_little Port;

        endpoint () : IPAddress {0}, Port {0} {}
        endpoint (const uint_little<16> &ip_address, uint16_little port): IPAddress {ip_address}, Port {port} {}
        endpoint (const data::net::IP::TCP::endpoint &e): endpoint {e.address (), e.port ()} {}
        endpoint (const data::net::IP::address &addr, uint16 port) : endpoint {} {
            if (!addr.valid ()) return;

            Port = port;

            bytes b = bytes (addr);
            std::copy (b.begin (), b.end (), IPAddress.end () - b.size ());
        }

        static size_t serialized_size () {
            return 18;
        }
    };

    std::strong_ordering operator <=> (const endpoint &, const endpoint &);
    bool operator == (const endpoint &, const endpoint &);

    writer inline &operator << (writer &w, const endpoint &h);

    struct net_address {
        service Service;
        endpoint Endpoint;

        net_address (): Service {0}, Endpoint {0} {}
        net_address (const service &x, const endpoint &e) : Service {x}, Endpoint {e} {}

        static size_t serialized_size () {
            return 26;
        }
    };

    writer &operator << (writer &w, const net_address &h);

    struct last_seen_net_address : net_address {
        Bitcoin::timestamp LastSeen;

        static size_t serialized_size () {
            return 30;
        }
    };

    writer &operator << (writer &w, const last_seen_net_address &h);

    std::strong_ordering inline operator <=> (const endpoint &a, const endpoint &b) {
        auto cmp_ip_addrs = a.IPAddress <=> b.IPAddress;
        return cmp_ip_addrs == std::strong_ordering::equal ? a.Port <=> b.Port : cmp_ip_addrs;
    }

    bool inline operator == (const endpoint &a, const endpoint &b) {
        return a.IPAddress == b.IPAddress && a.Port == b.Port;
    }

    writer inline &operator << (writer &w, const endpoint &h) {
        return w << h.IPAddress << h.Port;
    }

    writer inline &operator << (writer &w, const net_address &h) {
        return w << uint64_little {uint64 (h.Service)} << h.Endpoint;
    }

    writer inline &operator << (writer &w, const last_seen_net_address &h) {
        return w << static_cast<net_address> (h) << h.LastSeen;
    }

}

#endif

