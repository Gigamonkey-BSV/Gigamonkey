
// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/p2p/version.hpp>

namespace Gigamonkey::Bitcoin::p2p {

    writer &operator << (writer &w, const version_message<106> &h) {
        w << static_cast<const version_message<0> &> (h);
        if (h.Version <= 105) return w;
        return w << h.From << h.Nonce << var_string {h.UserAgent} << h.StartHeight;
    }

    writer &operator << (writer &w, const version_message<70001> &h) {
        w << static_cast<const version_message<106> &> (h);
        if (h.Version <= 70000) return w;
        return w << h.Relay;
    }

}

