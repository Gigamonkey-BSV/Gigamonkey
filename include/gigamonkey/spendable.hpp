// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SPENDABLE
#define GIGAMONKEY_SPENDABLE

#include "signature.hpp"
#include "timechain.hpp"
#include <gigamonkey/script.hpp>

namespace Gigamonkey::Bitcoin {
    
    struct redeemer {
        virtual bytes redeem(const vertex& v, index i, sighash::directive d) const = 0;
    };
    
    struct redeem_pay_to_pubkey final : redeemer {
        secret Secret;
        virtual bytes redeem(const vertex& v, index i, sighash::directive d) const override {
            return pay_to_pubkey::redeem(sign(v, i, d, Secret));
        }
    };
    
    struct redeem_pay_to_address final : redeemer {
        secret Secret;
        pubkey Pubkey;
        virtual bytes redeem(const vertex& v, index i, sighash::directive d) const override {
            return pay_to_address::redeem(sign(v, i, d, Secret), Pubkey);
        }
    };
    
    struct change {
        virtual ptr<redeemer> operator++(int) const = 0;
    };
    
    struct spendable {
        prevout Prevout;
        ptr<redeemer> Redeemer;
        
        satoshi value() const {
            return Gigamonkey::output::value(Prevout.Output);
        }
        
        bool valid() const {
            return Prevout.valid() && Redeemer != nullptr;
        } 
    };
    
}

#endif

