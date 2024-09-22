
// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_PINGPONG
#define GIGAMONKEY_P2P_PINGPONG

#include <gigamonkey/types.hpp>
#include <gigamonkey/command.hpp>

namespace Gigamonkey::Bitcoin::p2p {

    struct ping_pong {
        uint64_little Nonce;
        size_t serialized_size () const {
            return 8;
        }
    };

    writer &operator << (writer &w, const ping_pong &h);

    struct ping : ping_pong {
        constexpr static command Command ("ping");
    };

    struct pong : ping_pong {
        constexpr static command Command ("pong");
    };

    writer inline &operator << (writer &w, const ping_pong &h) {
        return w << h.Nonce;
    }

}

#endif


