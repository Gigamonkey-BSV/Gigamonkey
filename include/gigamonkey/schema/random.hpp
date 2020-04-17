// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_RANDOM
#define GIGAMONKEY_SCHEMA_RANDOM

#include <gigamonkey/wallet.hpp>
#include <random.h>

namespace Gigamonkey::Bitcoin {
    
    struct random_keysource final : keysource {
        secret First;
        
        static secret get() {
            secret x;
            do {
                GetStrongRandBytes(x.Secret.Value.data(), 32);
            } while (!x.valid());
            return x;
        } 
        
        random_keysource() : First{get()} {}
        
        secret first() const override {
            return First;
        }
        
        ptr<keysource> rest() const override {
            return std::make_shared<random_keysource>();
        }
    };

}

#endif

