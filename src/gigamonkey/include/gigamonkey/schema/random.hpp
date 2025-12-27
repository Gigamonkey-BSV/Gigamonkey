// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_RANDOM
#define GIGAMONKEY_SCHEMA_RANDOM

#include "keysource.hpp"
#include <data/random.hpp>

namespace Gigamonkey {
    struct bitcoind_entropy final : data::random::entropy {
        byte_array<32> Data;
        uint32 Position;
        bitcoind_entropy () : Data {}, Position {32} {}
        void read (byte *, size_t) final override;
    };
}

namespace Gigamonkey::Bitcoin {
    
    class random_key_source final : public key_source {
        data::random::entropy &Random;
        net Network;
        bool Compressed;
        
    public:
        
        secret next () override {
            secret x;
            do {
                Random >> x.Secret.Value;
            } while (!x.valid ());
            x.Network = Network;
            x.Compressed = Compressed;
            return x;
        }
        
        random_key_source (data::random::entropy &r, net net = net::Main, bool compressed = true) :
            Random {r}, Network {net}, Compressed {compressed} {}
    };

}

#endif

