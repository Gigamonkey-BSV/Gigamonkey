
// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_VERSION
#define GIGAMONKEY_P2P_VERSION

#include <gigamonkey/p2p/empty.hpp>
#include <gigamonkey/p2p/command.hpp>
#include <gigamonkey/p2p/net_address.hpp>
#include <gigamonkey/p2p/var_int.hpp>
#include <gigamonkey/timestamp.hpp>

namespace Gigamonkey::Bitcoin::p2p {

    template <uint32 min_protocol_version> struct version_message;
    template <> struct version_message<0>;
    template <> struct version_message<106>;
    template <> struct version_message<70001>;

    writer &operator << (writer &w, const version_message<0> &h);
    writer &operator << (writer &w, const version_message<106> &h);
    writer &operator << (writer &w, const version_message<70001> &h);

    using version = version_message<70001>;

    struct verack : empty {
        constexpr static command Command {"verack"};
    };

    template <> struct version_message<0> {
        constexpr static command Command {"version"};

        int32_little Version;
        service Services;
        Bitcoin::timestamp Timestamp;
        net_address Receive;

        version_message (int32_little v, service x, Bitcoin::timestamp t, net_address a): Version {v}, Services {x}, Timestamp {t}, Receive {a} {}

        int64 serialized_size () const {
            return 46;
        }
    };

    template <> struct version_message<106> : version_message<0> {
        net_address From;

        // this is supposed to be a random number.
        uint32_little Nonce;
        bytes UserAgent;
        int32_little StartHeight;

        version_message (int32_little v, service x, Bitcoin::timestamp t, net_address a):
            version_message<0> {v, x, t, a}, From {}, Nonce {}, UserAgent {}, StartHeight {} {}

        version_message (int32_little v, service x, Bitcoin::timestamp t, net_address ar,
            net_address af, uint32_little n, string ua, int32_little h):
            version_message<0> {v, x, t, ar}, From {af}, Nonce {n}, UserAgent {ua}, StartHeight {h} {}

        int64 serialized_size () const {
            return 84 + var_string::size (UserAgent.size ());
        }
    };

    template <> struct version_message<70001> : version_message<106> {
        byte Relay;

        version_message (int32_little v, service x, Bitcoin::timestamp t, net_address a):
            version_message<106> {v, x, t, a}, Relay {} {}

        version_message (int32_little v, service x, Bitcoin::timestamp t, net_address ar,
            net_address af, uint32_little n, string ua, int32_little h):
            version_message<106> {v, x, t, ar, af, n, ua, h}, Relay {} {}

        version_message (int32_little v, service x, Bitcoin::timestamp t, net_address ar,
            net_address af, uint32_little n, string ua, int32_little h, byte r):
            version_message<106> {v, x, t, ar, af, n, ua, h}, Relay {r} {}

        int64 serialized_size () const {
            return 85 + var_string::size (this->UserAgent.size ());
        }
    };

    writer inline &operator << (writer &w, const version_message<0> &h) {
        return w << h.Version << uint64_little {uint64 (h.Services)} << h.Timestamp << h.Receive;
    }

}

#endif
