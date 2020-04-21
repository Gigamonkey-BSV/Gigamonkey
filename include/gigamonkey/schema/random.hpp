// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_RANDOM
#define GIGAMONKEY_SCHEMA_RANDOM

#include <gigamonkey/spendable.hpp>

namespace Gigamonkey::Bitcoin {
    
    struct random_keysource final : keysource {
        secret First;
        
        static secret get();
        
        static ptr<keysource> make() {
            return std::make_shared<random_keysource>();
        }
        
        secret first() const override {
            return First;
        }
        
        ptr<keysource> rest() const override {
            return make();
        }
        
        random_keysource() : First{get()} {}
    };

}

#endif

