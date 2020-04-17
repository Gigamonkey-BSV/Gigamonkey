// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WALLET
#define GIGAMONKEY_WALLET

#include "spendable.hpp"

namespace Gigamonkey::Bitcoin {
    
    struct fee {
        double FeePerByte;
        double FeePerSigop;
        
        satoshi calculate(uint32 size, uint32 sigops) const {
            return FeePerByte * size + FeePerSigop * sigops;
        }
    } OneSatoshiPerByte{1, 0};
    
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
    
    struct wallet {
        enum spend_policy {unset, all, fifo, random};
        
        spend_policy Policy;
        funds Funds;
        ptr<keysource> Keys;
        
        fee Fee;
        
        ptr<output_pattern> Change;
        
        wallet() : Policy{unset}, Funds{}, Change{nullptr} {}
        wallet(spend_policy policy, funds fun, ptr<keysource> k, fee f, ptr<output_pattern> c) : 
            Policy{policy}, Funds{fun}, Keys{k}, Fee{f}, Change{c} {}
        
        bool valid() const {
            return Policy != unset && data::valid(Funds) && Change != nullptr;
        }
        
        bool value() const {
            return Funds.Value;
        }
        
        struct spent;
        
        template <typename ... X> 
        spent spend(X ... payments) const;
        
    private:
        output pay(const output& o) {
            return o;
        }
        
        static satoshi value(list<output>);
        
        static list<output_pattern::change> make_change(ptr<output_pattern>, ptr<keysource>, uint32 num);
        
        struct selected {
            list<data::entry<spendable, sighash::directive>> Selected;
            funds Remainder;
            ptr<keysource> Keys;
        };
        
        static selected select(funds, satoshi, spend_policy, fee);
    };
        
    struct wallet::spent {
        bytes Transaction;
        wallet Remainder;
        
    private:
        spent() : Transaction{}, Remainder{} {}
        spent(const bytes& t, const wallet& r) : Transaction{t}, Remainder{r} {}
        
        friend struct wallet;
    };
    
    template <typename ... X> 
    wallet::spent wallet::spend(X ... payments) const {
        if (!valid()) return spent{};
        list<output> outputs{payments...};
        satoshi to_spend = value(outputs);
        if (to_spend > value()) return {};
        
        // step 1. generate change scripts
        list<output_pattern::change> change = make_change(Change, Keys, 2);
        
        // step 2. Select inputs to redeem. 
        selected x = select(Funds, to_spend, Policy, Fee);
        
        // step 3. determine fee.
        
        // step 4. setup outputs.
        
        // step 5. create tx
        bytes tx = redeem(x.Selected, outputs);
        if (!Gigamonkey::transaction::valid(tx)) return {};
        return spent{tx, wallet{}};
    }
    
}

#endif


