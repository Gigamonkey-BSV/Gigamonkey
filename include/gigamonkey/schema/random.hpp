// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCHEMA_RANDOM
#define GIGAMONKEY_SCHEMA_RANDOM

#include <gigamonkey/wallet.hpp>
#include <random.h>

namespace Gigamonkey::Bitcoin {
    
    struct random_keysource : keysource {
        secret next() override {
            secret x{};
            GetStrongRandBytes(x.Secret.Value.data(), 32);
            return x;
        }
    };

}

#endif

