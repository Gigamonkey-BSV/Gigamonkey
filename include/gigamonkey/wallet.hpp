// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WALLET
#define GIGAMONKEY_WALLET

#include "redeem.hpp"
#include "fees.hpp"

namespace Gigamonkey {
    
    struct funds {
        list<spendable> Entries;
        Bitcoin::satoshi Value;
        bool Valid;
        
        funds() : Entries{}, Value{0}, Valid{true} {}
        funds(list<spendable> e) : funds{funds{}.insert(e)} {}
        
        funds insert(spendable s) const {
            return funds(Entries << s, Value + s.value(), Valid && s.valid());
        }
        
        funds insert(list<spendable> s) const {
            if (s.empty()) return *this;
            return insert(s.first()).insert(s.rest());
        }
        
    private:
        funds(list<spendable> e, Bitcoin::satoshi value, bool valid) : Entries{e}, Value{value}, Valid{valid} {}
    };
    
    // pay to script. 
    Bitcoin::output inline pay(Bitcoin::satoshi value, const bytes& script) {
        return {value, script};
    }
    
    // pay to address. 
    Bitcoin::output inline pay(Bitcoin::satoshi value, const Bitcoin::address& addr) {
        return {value, pay_to_address::script(addr.Digest)};
    }
    
    // pay to pubkey. 
    Bitcoin::output inline pay(Bitcoin::satoshi value, const Bitcoin::pubkey& pub) {
        return {value, pay_to_pubkey::script(pub)};
    }
    
    struct wallet {
        enum spend_policy {unset, all, fifo, random};
        
        funds Funds;
        spend_policy Policy;
        ptr<keysource> Keys;
        
        ptr<output_pattern> Change;
        
        Bitcoin::satoshi Dust;
        
        wallet() : Funds{}, Policy{unset}, Keys{nullptr}, Change{nullptr}, Dust{} {}
        wallet(funds fun, spend_policy policy, ptr<keysource> k, ptr<output_pattern> c, Bitcoin::satoshi d) : 
            Funds{fun}, Policy{policy}, Keys{k}, Change{c}, Dust{d} {}
        
        bool valid() const {
            return Policy != unset && data::valid(Funds) && Change != nullptr && Keys != nullptr;
        }
        
        struct spent;
        
        spent spend(satoshi_per_byte fee, list<Bitcoin::output> = {}) const;
    };
    
    struct wallet::spent {
        ledger::vertex Transaction;
        
        // these are new funds that will mature as soon as the tx is processed. 
        funds Change;
        
        // this is what remains in our wallet. 
        wallet Remainder;
        
        bool valid() const {
            return Transaction.valid() && Change.Valid && Remainder.valid();
        }
        
    private:
        spent() : Transaction{}, Change{}, Remainder{} {}
        spent(const ledger::vertex& v, funds x, const wallet& r) : Transaction{v}, Change{x}, Remainder{r} {}
        
        friend struct wallet;
    };
    
    std::ostream inline &operator<<(std::ostream &o, satoshi_per_byte v) {
        return o << "(" << v.Satoshis << "sats / " << v.Bytes << "byte)";
    }
    
    std::ostream inline &operator<<(std::ostream &o, funds f) {
        if (f.Valid) return o << "funds{" << f.Value << " sats, " << f.Entries << "}";
        else return o << "funds{}";
    }
    
    bool inline operator==(const satoshi_per_byte &a, const satoshi_per_byte &b) {
        return a.Satoshis == b.Satoshis && a.Bytes == b.Bytes;
    }
    
}

#endif


