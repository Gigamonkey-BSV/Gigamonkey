// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SPENDABLE
#define GIGAMONKEY_SPENDABLE

#include "redeem.hpp"
#include "timechain.hpp"
#include <gigamonkey/script.hpp>

namespace Gigamonkey::Bitcoin {
    
    struct redeem_pay_to_pubkey final : redeemer {
        secret Secret;
        virtual bytes redeem(const input_index& tx, sighash::directive d) const override {
            return pay_to_pubkey::redeem(Secret.sign(tx, d));
        }
    };
    
    struct redeem_pay_to_address final : redeemer {
        secret Secret;
        pubkey Pubkey;
        virtual bytes redeem(const input_index& tx, sighash::directive d) const override {
            return pay_to_address::redeem(Secret.sign(tx, d), Pubkey);
        }
    };
    
    struct change {
        virtual ptr<redeemer> operator++(int) const = 0;
    };
    
}

#endif

