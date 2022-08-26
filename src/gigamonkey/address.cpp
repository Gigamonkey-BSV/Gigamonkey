// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/address.hpp>
#include <data/encoding/base58.hpp>

namespace Gigamonkey::Bitcoin {
    
   address::address(string_view s) : address{} {
        if (s.size() > 35 || s.size() < 5) return;
        base58::check b58(s);
        if (!b58.valid()) return;
        Prefix = type(b58.version());
        if (!valid_prefix(Prefix)) return;
        if (b58.payload().size() > 20) return;
        std::copy(b58.payload().begin(), b58.payload().end(), Digest.begin());
    }
}
