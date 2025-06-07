// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_RANDOM
#define GIGAMONKEY_SCHEMA_RANDOM

#include "keysource.hpp"
#include <data/crypto/random.hpp>

namespace Gigamonkey {
    struct bitcoind_random : data::crypto::random {
        void get (byte*, size_t) override;
    };
    
    class bitcoind_entropy : public bitcoind_random, public data::crypto::entropy {
        bytes get (size_t s) override {
            bytes b (s);
            bitcoind_random::get (b.data (), s);
            return b;
        }
    };
}

namespace Gigamonkey::Bitcoin {
    
    class random_key_source final : public key_source {
        data::crypto::random &Random;
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
        
        random_key_source (data::crypto::random &r, net net = net::Main, bool compressed = true) :
            Random {r}, Network {net}, Compressed {compressed} {}
    };

}

#endif

