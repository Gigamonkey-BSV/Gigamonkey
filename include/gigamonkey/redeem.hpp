// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_REDEEM
#define GIGAMONKEY_REDEEM

#include <gigamonkey/ledger.hpp>
#include <gigamonkey/script/pattern.hpp>
#include <gigamonkey/wif.hpp>

namespace Gigamonkey {
    
    // an output that we know how to spend. 
    struct spendable {
        using directive = Bitcoin::sighash::directive;
        using document = Bitcoin::sighash::document;
        
        // information required to redeem an output. 
        struct redeemer {
            // This information must be provided in the event that a signature is required. 
            // However, not all input scripts have signatures. Therefore, we can't assume that
            // a key is here either or that any signature is created. 
            virtual bytes redeem(const document&, directive) const = 0;
            virtual uint32 expected_size() const = 0;
            virtual uint32 sigops() const = 0;
            
            virtual ~redeemer() {}
        };
        
        prevout Previous;
        ptr<redeemer> Redeemer;
        
        spendable(const prevout& p, ptr<redeemer> r) : Previous{p}, Redeemer{r} {}
        
        Bitcoin::input operator()(const Bitcoin::incomplete::transaction tx, index i, directive d) const {
            if (Redeemer == nullptr) return {};
            Bitcoin::incomplete::input in = tx.Inputs[i];
            if (Previous.Key != in.Reference) return {};
            return in.complete(Redeemer->redeem(document{
                Previous.Value.Value, 
                // TODO This isn't correct since the script isn't always the same as the script code. 
                Previous.Value.Script, 
                tx, i}, d));
        }
        
        Bitcoin::satoshi value() const {
            return Previous.Value.Value;
        }
        
        Bitcoin::outpoint reference() const {
            return Previous.Key;
        }
        
        bool valid() const {
            return Redeemer != nullptr;
        }
        
    };
    
    ledger::vertex redeem(list<spendable> prev, list<Bitcoin::output> out, uint32_little locktime = 0);
    
    // extra information required with spendable necessary to generate a transaction. 
    struct spend_instructions {
        uint32_little Sequence;
        Bitcoin::sighash::directive Directive;
        
        spend_instructions() : Sequence{Bitcoin::input::Finalized}, Directive{Bitcoin::sighash::all} {}
        spend_instructions(uint32_little x, Bitcoin::sighash::directive d) : Sequence{x}, Directive{d} {}
    };
    
    using spend_order = std::pair<spendable, spend_instructions>;
    
    ledger::vertex redeem(list<spend_order> prev, list<Bitcoin::output> out, uint32_little locktime = 0);

    ledger::vertex inline redeem(
        list<spendable> prev, 
        spend_instructions apply_to_all, 
        list<Bitcoin::output> out, 
        uint32_little locktime = 0) {
        return redeem(data::for_each([apply_to_all](spendable p) -> spend_order {
            return {p, apply_to_all};
        }, prev), out, locktime);
    }

    ledger::vertex inline redeem(
        list<spendable> prev, 
        list<Bitcoin::output> out, 
        uint32_little locktime) {
        return redeem(prev, spend_instructions{}, out, locktime);
    }
    
    struct redeem_pay_to_pubkey final : spendable::redeemer {
        Bitcoin::secret Secret;
        
        redeem_pay_to_pubkey(const Bitcoin::secret& s) : Secret{s} {}
        
        bytes redeem(const Bitcoin::sighash::document& document, Bitcoin::sighash::directive d) const override {
            return pay_to_pubkey::redeem(Secret.sign(document, d));
        }
        
        uint32 expected_size() const override {
            return Bitcoin::signature::MaxSignatureSize + 1;
        };
        
        uint32 sigops() const override {
            return 1;
        }
    };
    
    struct redeem_pay_to_address final : spendable::redeemer {
        Bitcoin::secret Secret;
        Bitcoin::pubkey Pubkey;
        
        redeem_pay_to_address(const Bitcoin::secret& s, const Bitcoin::pubkey& p) : Secret{s}, Pubkey{p} {}
        
        bytes redeem(const Bitcoin::sighash::document& document, Bitcoin::sighash::directive d) const override {
            return pay_to_address::redeem(Secret.sign(document, d), Pubkey);
        }
        
        uint32 expected_size() const override {
            return Bitcoin::signature::MaxSignatureSize + Pubkey.size() + 2;
        };
        
        uint32 sigops() const override {
            return 1;
        }

    };
    
    std::ostream inline &operator<<(std::ostream &o, const spendable& x) {
        return o << "spendable{" << x.Previous << "}";
    };
    
}

#include <gigamonkey/schema/keysource.hpp>

namespace Gigamonkey {
    
    struct change {
        bytes OutputScript;
        ptr<spendable::redeemer> Redeemer;
    };
    
    struct output_pattern {
        virtual change create_redeemable(ptr<keysource>&) const = 0;
        virtual ~output_pattern() {}
    };
    
    struct pay_to_pubkey_pattern final : output_pattern {
        pay_to_pubkey_pattern() : output_pattern{} {}
        change create_redeemable(ptr<keysource>& k) const override {
            Bitcoin::secret s = k->first();
            k = k->rest();
            return change{pay_to_pubkey::script(s.to_public()),
                std::make_shared<redeem_pay_to_pubkey>(s)};
        };
    };
    
    struct pay_to_address_pattern final : output_pattern {
        pay_to_address_pattern() : output_pattern{} {}
        change create_redeemable(ptr<keysource>& k) const override {
            Bitcoin::secret s = k->first();
            k = k->rest();
            return change{pay_to_address::script(s.address().Digest), 
                std::make_shared<redeem_pay_to_address>(s, s.to_public())};
        };
    };
    
}

#endif
