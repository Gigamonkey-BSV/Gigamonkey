
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

    template <writer W>
    W &operator << (W &w, const ping_pong &h);

    struct ping : ping_pong {
        constexpr static command Command ("ping");
    };

    struct pong : ping_pong {
        constexpr static command Command ("pong");
    };

    template <writer W>
    W inline &operator << (W &w, const ping_pong &h) {
        return w << h.Nonce;
    }

}

#endif


