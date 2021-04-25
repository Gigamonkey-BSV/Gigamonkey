// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_REDEEM
#define GIGAMONKEY_REDEEM

#include <gigamonkey/ledger.hpp>
#include <gigamonkey/script/script.hpp>
#include <gigamonkey/wif.hpp>

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
        
        bytes redeem(bytes_view tx, index i, bool dummy_signature = false) const {
            return Secret == nullptr ? Script : 
                compile(Bitcoin::program{} << push_data(dummy_signature ? signature{} : Secret->sign(tx, i, Directive)));
        };
        
        uint32 expected_size() const {
            return Secret == nullptr ? Script.size() : signature::MaxSignatureSize;
        };
    };
    
    using incomplete = list<element>;
    
    bytes redeem(incomplete x, bytes_view tx, index i, bool dummy_signature = false);
    
    uint32 expected_size(incomplete x);
}

namespace Gigamonkey::Bitcoin {
    
    struct redeemable {
        // create a redeem script. 
        virtual redemption::incomplete redeem(sighash::directive) const = 0;
        virtual uint32 expected_size() const = 0;
        virtual uint32 sigops() const = 0;
    };
    
    struct spendable : ledger::prevout {
        ptr<redeemable> Redeemer;
        uint32_little Sequence;
        
        spendable(const ledger::prevout& p, ptr<redeemable> r, uint32_little s = 0) : 
            ledger::prevout{p}, Redeemer{r}, Sequence{s} {}
        
        bool valid() const {
            return ledger::prevout::valid() && Redeemer != nullptr; 
        }
        
        satoshi value() const {
            return ledger::prevout::Value.Value;
        }
        
        outpoint reference() const {
            return ledger::prevout::Key;
        }
        
    };
    
    ledger::vertex redeem(list<data::entry<spendable, sighash::directive>> prev, list<output> out, uint32_little locktime);
    
    ledger::vertex inline redeem(list<data::entry<spendable, sighash::directive>> prev, list<output> out) {
        return redeem(prev, out, 0);
    }
    
    std::ostream inline &operator<<(std::ostream &o, const spendable& x) {
        return o << "{" << static_cast<ledger::prevout>(x) << ", " << ", " << x.Sequence << "}";
    };
    
}

#endif
