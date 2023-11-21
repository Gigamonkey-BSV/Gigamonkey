// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/address.hpp>
#include <gigamonkey/p2p/checksum.hpp>

namespace Gigamonkey::Bitcoin {

    address address::encode (char prefix, const digest160 &d) {

        address addr {};
        static_cast<string &> (addr) = std::move (base58::check {byte (prefix), bytes_view {d}}.encode ());
        return addr;

    }
    
    address::decoded address::decode (string_view s) {

        if (s.size () > 35 || s.size () < 5) return {};
        base58::check b58 (s);
        if (!b58.valid ()) return {};

        decoded d;

        d.Prefix = type (b58.version ());
        if (!valid_prefix (d.Prefix)) return {};
        if (b58.payload ().size () > 20) return {};
        std::copy (b58.payload ().begin (), b58.payload ().end (), d.Digest.begin ());

        return d;

    }
}
