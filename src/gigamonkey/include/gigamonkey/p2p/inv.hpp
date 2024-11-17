
// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_INV
#define GIGAMONKEY_P2P_INV

#include <gigamonkey/hash.hpp>

namespace Gigamonkey::Bitcoin::p2p {

    struct inv_item {
        enum type uint32 {
            ERROR = 0,
            MSG_TX = 1,
            MSG_BLOCK = 2,
            MSG_FILTERED_BLOCK = 3,
            MSG_CMPCT_BLOCK = 4
        };

        type Type;
        digest256 Digest;
    };

    writer &operator << (writer &w, const inv_vector &h);

    struct inv_message {
        list<inv_item> Inventory;

        size_t serialized_size () const {
            return var_int::size (Inventory.size ()) + Inventory.size () * 36;
        }
    };

    writer &operator << (writer &w, const inv_message &h);

    struct inv : inv_message {
        constexpr static command Command ("inv");
    };

    struct getdata : inv_message {
        constexpr static command Command ("getdata");
    };

    struct notfound : empty {
        constexpr static command Command ("notfound");
    };

    writer inline &operator << (writer &w, const inv_vector &h) {
        return w << uint32_little {h.Type} << h.Digest;
    }

    writer inline &operator << (writer &w, const inv_message &h) {
        w << var_int {Inventory.size ()};
        for (const inv_item &i : Inventory) w << i;
        return w;
    }

}

#endif

