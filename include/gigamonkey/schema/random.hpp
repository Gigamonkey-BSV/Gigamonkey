// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_RANDOM
#define GIGAMONKEY_SCHEMA_RANDOM

#include <gigamonkey/spendable.hpp>
#include <data/crypto/random.hpp>

namespace Gigamonkey {
    struct bitcoind_random : data::crypto::random {
        void get(byte*, size_t) override;
    };
    
    class bitcoind_entropy : public bitcoind_random, public data::crypto::entropy {
        bytes get(size_t s) override {
            bytes b(s);
            bitcoind_random::get(b.data(), s);
            return b;
        }
    };
}

namespace Gigamonkey::Bitcoin {
    
    class random_keysource final : public keysource {
        ptr<data::crypto::random> Random;
        
    public:
        secret First;
        
        static ptr<keysource> make(ptr<data::crypto::random> r) {
            return std::static_pointer_cast<keysource>(std::make_shared<random_keysource>(r));
        }
        
        secret first() const override {
            return First;
        }
        
        ptr<keysource> rest() const override {
            return make(Random);
        }
        
        random_keysource(ptr<data::crypto::random> r) : Random{r}, First{} {
            do {*r >> First.Secret.Value; } while (!First.valid());
        }
    };

}

#endif

