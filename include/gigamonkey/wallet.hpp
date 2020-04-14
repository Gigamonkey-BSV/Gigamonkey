// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WALLET
#define GIGAMONKEY_WALLET

#include "redeem.hpp"

namespace Gigamonkey::Bitcoin {
    
    using fee_calculator = satoshi (*)(uint32 size, uint32 sigops);
    
    inline satoshi one_satoshi_per_byte(uint32 size, uint32 sigops) {
        return size;
    }
    
    struct to_address {
        satoshi Value;
        address Address;
    };
    
    struct to_pubkey {
        satoshi Value;
        pubkey Pubkey;
    };
    
    struct paymail {
        string Name;
        string Host;
    };
    
    struct to_paymail {
        satoshi Value;
        paymail Paymail;
    };
    
    struct funds {
        list<spendable> Entries;
        satoshi Value;
        bool Valid;
        
        funds() : Entries{}, Value{0}, Valid{true} {}
        funds(list<spendable> e, satoshi a, bool v) : Entries{e}, Value{a}, Valid{v} {}
        
        funds insert(spendable s) const {
            return {Entries << s, Value + s.Prevout.Output.Value, Valid && s.valid()};
        }
    };
    
    struct keysource {
        virtual secret next() = 0;
    };
    
    struct wallet {
        enum spend_policy {all, fifo, random};
        
        spend_policy Policy;
        funds Funds;
        keysource& Change;
        
        wallet(spend_policy policy, funds f, keysource& c) : Policy{policy}, Funds{f}, Change{c} {}
        
        bool value() const {
            return Funds.Value;
        }
        
        // payments can be outputs, to_address, to_pubkey, or to_paymail. 
        template <typename ... X> 
        bytes spend(X ... payments);
    };
    
}

#endif


