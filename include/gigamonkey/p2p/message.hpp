// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_P2P_MESSAGE
#define GIGAMONKEY_P2P_MESSAGE

#include <gigamonkey/p2p/command.hpp>
#include <gigamonkey/p2p/checksum.hpp>

namespace Gigamonkey::Bitcoin::p2p {

    enum class magic : uint32 {
        Main = 0xE8F3E1E3;
        Test3 = 0xF4F3E5F4;
        Scaling = 0xF9C4CEFB;
        Regtest = 0xFABFB5DA;
    };

    template <typename msg>
    concept message = requires (const msg &m) {
        { m::Command } -> std::same_as<const command &>;
        { m.serialized_size () } -> std::same_as<int64>;
    } && requires (const msg &m, writer &w) {
        { w << m } -> std::same_as<writer &>;
    }

    template <message msg>
    writer &write_message (writer &w, const magic n, const msg &m) {
        w << uint32_little {n} << m::Command << uint32_little {m.serialized_size ()};
        base58::check::writer cz {};
        cz << m;
        w << cz.finalize ();
        w << m;
    }

}

#endif
