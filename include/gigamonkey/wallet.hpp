// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WALLET
#define GIGAMONKEY_WALLET

#include "redeem.hpp"

namespace Gigamonkey::Bitcoin {
    
    struct satoshi_per_byte {
        satoshi Satoshis;
        uint64 Bytes;
        
        bool valid() const {
            return Bytes != 0;
        }
        
        satoshi_per_byte() : Satoshis{0}, Bytes{0} {}
        satoshi_per_byte(satoshi x, uint64 b) : Satoshis{x}, Bytes{b} {}
        
        explicit operator double() const {
            return double(Satoshis) / double(Bytes);
        }
    };
    
    satoshi operator*(satoshi_per_byte fee, uint64 size);
    
    struct fee {
        satoshi_per_byte Data;
        satoshi_per_byte Standard;
        
        fee() : Data{}, Standard{} {}
        fee(satoshi_per_byte d, satoshi_per_byte x) : Data{d}, Standard{x} {}
    };
    
    struct funds {
        list<spendable> Entries;
        satoshi Value;
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
        funds(list<spendable> e, satoshi value, bool valid) : Entries{e}, Value{value}, Valid{valid} {}
    };
    
    output inline pay(satoshi value, const bytes& script) {
        return output{value, script};
    }
    
    output inline pay(satoshi value, const address& addr) {
        return output{value, pay_to_address::script(addr.Digest)};
    }
    
    output inline pay(
        satoshi value, const pubkey& pub) {
        return output{value, pay_to_pubkey::script(pub)};
    }
    
    struct paymail {
        string Name;
        string Host;
        explicit operator string() const;
    };
    
    output inline pay(satoshi value, paymail p) {
        throw method::unimplemented{"pay to paymail"};
    }
    
    struct wallet {
        enum spend_policy {unset, all, fifo, random};
        
        funds Funds;
        spend_policy Policy;
        ptr<keysource> Keys;
        
        fee Fee;
        
        ptr<output_pattern> Change;
        
        satoshi Dust;
        
        wallet() : Funds{}, Policy{unset}, Keys{nullptr}, Fee{}, Change{nullptr}, Dust{} {}
        wallet(funds fun, spend_policy policy, ptr<keysource> k, fee f, ptr<output_pattern> c, satoshi d) : 
            Funds{fun}, Policy{policy}, Keys{k}, Fee{f}, Change{c}, Dust{d} {}
        
        bool valid() const {
            return Policy != unset && data::valid(Funds) && Change != nullptr && Keys != nullptr;
        }
        
        struct spent;
        
        spent spend(list<output>) const;
    };
    
    struct wallet::spent {
        ledger::vertex Transaction;
        
        // these are new funds that will mature as soon as the tx is processed. 
        funds Change;
        
        // this is what remains in our wallet. 
        wallet Remainder;
        
        bool valid() const {
            return Transaction != nullptr && Change.Valid && Remainder.valid();
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
    
}

#endif


