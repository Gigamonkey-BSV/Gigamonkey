
// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_GET
#define GIGAMONKEY_P2P_GET

#include <gigamonkey/p2p/command.hpp>

namespace Gigamonkey::Bitcoin::p2p {

    struct get {
        int32_little Version;
        list<digest256> Locators;
        digest256 Stop;

        size_t serialized_size () const {
            return var_int::size (Locators.size ()) + 36 + 32 * Locators.size ();
        }
    };

    writer &operator << (writer &w, const get &h) {
        w << Version << var_int {Locators.size ()};
        return w << Stop;
    }

    struct getblocks : get {
        constexpr static command Command ("getblocks");
    };

    struct getheaders : get {
        constexpr static command Command ("getheaders");
    };

    struct header {
        constexpr static command Command ("header");
        size_t serialized_size () const;
    };

    writer &operator << (writer &w, const header &h);

}

#endif

