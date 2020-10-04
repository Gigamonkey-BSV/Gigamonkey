// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_REDEEM
#define GIGAMONKEY_REDEEM

#include "timechain.hpp"
#include "script.hpp"
#include "wif.hpp"

namespace Gigamonkey::Bitcoin::redemption {
    
    class element {
        const secret* Secret;
        sighash::directive Directive;
        bytes Script;
        
    public:
        element(const secret* s, sighash::directive d) : Secret{s}, Directive{d}, Script{} {}
        element(const bytes& s) : Secret{nullptr}, Script{s} {}
        
        bool valid() const {
            return (Secret == nullptr) || (Script.size() == 0);
        }
        
        bytes redeem(const input_index& tx, bool dummy_signature = false) const {
            return Secret == nullptr ? Script : 
                compile(Bitcoin::program{} << push_data(dummy_signature ? signature{} : Secret->sign(tx, Directive)));
        };
        
        uint32 expected_size() const {
            return Secret == nullptr ? Script.size() : DerSignatureExpectedSize;
        };
    };
    
    using incomplete = list<element>;
    
    bytes redeem(incomplete x, const input_index& tx, bool dummy_signature = false);
    
    uint32 expected_size(incomplete x);
}

namespace Gigamonkey::Bitcoin {
    
    struct redeemable {
        // create a redeem script. 
        virtual redemption::incomplete redeem(sighash::directive) const = 0;
        virtual uint32 expected_size() const = 0;
        virtual uint32 sigops() const = 0;
    };
    
    struct prevout {
        output Output;
        outpoint Outpoint;
        
        bool valid() const {
            return Output.valid() && Outpoint != outpoint::coinbase();
        }
    };
    
    struct spendable {
        ptr<redeemable> Redeemer;
        prevout Prevout;
        uint32_little Sequence;
        
        bool valid() const {
            return Prevout.valid();
        } 
        
        spendable(ptr<redeemable> r, prevout p, uint32_little s = 0) : Redeemer{r}, Prevout{p}, Sequence{s} {}
    };
    
    struct vertex {
        list<prevout> Previous;
        transaction Transaction;
        
        satoshi spent() const;
        
        satoshi sent() const;
        satoshi fee() const;
        size_t size() const;
        
        bool valid() const;
        
        uint32 sigops() const;
    };
    
    vertex redeem(list<data::entry<spendable, sighash::directive>> prev, list<output> out, int32_little locktime);
    
    inline vertex redeem(list<data::entry<spendable, sighash::directive>> prev, list<output> out) {
        return redeem(prev, out, 0);
    }
    
    inline satoshi vertex::sent() const {
        return Transaction.sent();
    }
    
    inline satoshi vertex::fee() const {
        return spent() - sent();
    }
    
    inline size_t vertex::size() const {
        return Transaction.serialized_size();
    }
    
}

#endif
