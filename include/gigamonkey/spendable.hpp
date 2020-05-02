// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SPENDABLE
#define GIGAMONKEY_SPENDABLE

#include "redeem.hpp"

namespace Gigamonkey::Bitcoin {
    
    struct keysource {
        virtual secret first() const = 0;
        virtual ptr<keysource> rest() const = 0;
    };
    
    struct change {
        bytes OutputScript;
        ptr<redeemable> Redeemer;
    };
    
    struct output_pattern {
        virtual change create_redeemable(ptr<keysource>&) const = 0;
    };
    
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
        
        uint32 sigops() const override {
            return 1;
        }
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
        
        uint32 sigops() const override {
            return 1;
        }

    };
    
    struct pay_to_pubkey_pattern : output_pattern {
        change create_redeemable(ptr<keysource>& k) const override {
            secret s = k->first();
            k = k->rest();
            return change{pay_to_pubkey::script(s.to_public()),
                std::make_shared<redeem_pay_to_pubkey>(s)};
        };
    };
    
    struct pay_to_address_pattern : output_pattern {
        change create_redeemable(ptr<keysource>& k) const override {
            secret s = k->first();
            k = k->rest();
            return change{pay_to_address::script(s.address().Digest), 
                std::make_shared<redeem_pay_to_address>(s, s.to_public())};
        };
    };
    
}

#endif

