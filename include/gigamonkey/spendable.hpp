// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SPENDABLE
#define GIGAMONKEY_SPENDABLE

#include "timechain.hpp"
#include <gigamonkey/script.hpp>
#include "redeem.hpp"

namespace Gigamonkey::Bitcoin {
    
    struct keysource {
        virtual secret first() const = 0;
        virtual ptr<keysource> rest() const = 0;
    };
    
    enum output_pattern : uint32 {
        pay_to_pubkey = 1, 
        pay_to_address = 2
    };
    
    struct change {
        bytes OutputScript;
        ptr<redeemable> Redeemer;
    };
    
    template <output_pattern p>
    change create_redeemable_output_script(ptr<keysource>&);
    
    struct redeem_pay_to_pubkey final : redeemable {
        secret Secret;
        
        redeem_pay_to_pubkey(const secret& s) : Secret{s} {}
        
        redemption::incomplete 
        redeem(sighash::directive d) const override {
            return {redemption::element{&Secret, d}};
        }
        
        uint32 expected_size() const override {
            return DerSignatureExpectedSize + 1;
        };
    };
    
    struct redeem_pay_to_address final : redeemable {
        secret Secret;
        pubkey Pubkey;
        
        redeem_pay_to_address(const secret& s, const pubkey& p) : Secret{s}, Pubkey{p} {}
        
        redemption::incomplete 
        redeem(sighash::directive d) const override {
            return {redemption::element{&Secret, d}, compile(program{} << push_data(Pubkey))};
        }
        
        uint32 expected_size() const override {
            return DerSignatureExpectedSize + Pubkey.size() + 2;
        };

    };
    
}

namespace Gigamonkey::Bitcoin::patterns {
    template<output_pattern p> struct output;
    
    template<> struct output<pay_to_pubkey> {
        static change create(ptr<keysource>& k) {
            secret s = k->first();
            k = k->rest();
            return change{pay_to_pubkey::script(s.to_public()),
                std::make_shared<redeem_pay_to_pubkey>(s)};
        }
    };
    
    template<> struct output<pay_to_address> {
        static change create(ptr<keysource>& k) {
            secret s = k->first();
            k = k->rest();
            return change{pay_to_address::script(s.address().Digest), 
                std::make_shared<redeem_pay_to_address>(s, s.to_public())};
        }
    };
}

namespace Gigamonkey::Bitcoin {
    
    template <output_pattern p>
    change create_redeemable_output_script(ptr<keysource>& k) {
        return patterns::output<p>::create(k);
    }
    
}

#endif

