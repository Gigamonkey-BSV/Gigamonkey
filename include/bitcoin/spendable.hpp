// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SPENDABLE
#define GIGAMONKEY_SPENDABLE

#include "keys.hpp"
#include "script.hpp"

namespace gigamonkey::bitcoin {
    
    struct spendable {
        prevout Prevout;
        virtual bytes redeem(vertex, index i, sighash::directive) const = 0;
    };
    
    struct pay_to_pubkey final : spendable {
        secret Secret;
        virtual bytes redeem(vertex, index, sighash::directive) const override;
    };
    
    struct pay_to_address final : spendable {
        secret Secret;
        virtual bytes redeem(vertex, index, sighash::directive) const override;
    };
    
}

#endif

