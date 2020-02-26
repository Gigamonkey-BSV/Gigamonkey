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
    
    struct wallet {
        enum spend_policy {unset, all, fifo, random};
        
        spend_policy Policy;
        funds Funds;
        change* Change;
        
        wallet() : Policy{unset}, Funds{}, Change{nullptr} {}
        wallet(spend_policy policy, funds f, change* c) : Policy{policy}, Funds{f}, Change{c} {}
        
        bool valid() const {
            return Funds.valid() && Change != nullptr && Policy != unset;
        }
        
        bool value() const {
            return Funds.Value;
        }
        
        struct spent;
        
        // payments can be outputs, to_address, or to_pubkey
        template <typename ... X> 
        spent spend(X ... payments) const;
    };
    
    struct wallet::spent {
        bytes Transaction;
        wallet Remainder;
        
        bool valid() const {
            return Gigamonkey::transaction::valid(Transaction) && Remainder.valid();
        }
        
        spent(bytes t, wallet w) : Transaction{t}, Remainder{w} {}
        friend struct wallet;
    private :
        spent() : Transaction{}, Remainder{} {}
    };
    
}

#endif


