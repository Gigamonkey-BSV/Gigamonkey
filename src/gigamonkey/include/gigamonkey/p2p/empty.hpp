
// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_EMPTY
#define GIGAMONKEY_P2P_EMPTY

#include <gigamonkey/types.hpp>

namespace Gigamonkey::Bitcoin::p2p {

    struct empty {
        size_t serialized_size () const {
            return 0;
        }
    };

    writer &operator << (writer &w, const empty &h) {
        return w;
    }

}

#endif

