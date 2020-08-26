// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_WALLET
#define GIGAMONKEY_WALLET

#include "spendable.hpp"

namespace Gigamonkey::Bitcoin {
    
    struct fee {
        double FeePerByte;
        double FeePerSigop;
        
        satoshi calculate(size_t size, uint32 sigops) const {
            return FeePerByte * size + FeePerSigop * sigops;
        }
        bool sufficient(const vertex& t) const {
            return t.fee() >= calculate(t.size(), t.sigops());
        }
        
    };
    
    struct funds {
        list<spendable> Entries;
        satoshi Value;
        bool Valid;
        
        funds() : Entries{}, Value{0}, Valid{true} {}
        funds(list<spendable> e) : funds{funds{}.insert(e)} {}
        
        funds insert(spendable s) const {
            return {Entries << s, Value + s.Prevout.Output.Value, Valid && s.valid()};
        }
        
        funds insert(list<spendable> s) const {
            if (s.empty()) return {};
            return insert(s.first()).insert(s.rest());
        }
        
        struct selected;
        
        selected select_next() const;
        selected select_random() const;
        
    private:
        funds(list<spendable> e, satoshi value, bool valid) : Entries{e}, Value{value}, Valid{valid} {}
    };
    
    struct funds::selected {
        spendable Selected;
        funds Remainder;
    };
    
    inline funds::selected funds::select_next() const {
        throw method::unimplemented{"funds::select_next"};
    }
    
    inline funds::selected funds::select_random() const {
        throw method::unimplemented{"funds::select_random"};
    }
    
    struct payment {
        satoshi Value;
        bytes Script;
        
        explicit operator output() {
            return output{Value, Script};
        }
        
        payment(output o) : Value{o.Value}, Script{o.Script} {}
        
        payment(satoshi value, const bytes& script) : Value{value}, Script{script} {}

        payment(satoshi value, const address& addr) : Value{value}, Script{pay_to_address::script(addr.Digest)} {}

        payment(satoshi value, const pubkey& pub) : Value{value}, Script{pay_to_pubkey::script(pub)} {}
        
        payment(satoshi value, std::string paymail) {
            throw method::unimplemented{"payment::payment(paymail)"};
        }
        
    };
    
    struct wallet {
        enum spend_policy {unset, all, fifo, random};
        
        funds Funds;
        spend_policy Policy;
        ptr<keysource> Keys;
        
        fee Fee;
        
        ptr<output_pattern> Change;
        
        satoshi Dust;
        
        wallet() : Funds{}, Policy{unset}, Keys{nullptr}, Fee{0, 0}, Change{nullptr}, Dust{} {}
        wallet(funds fun, spend_policy policy, ptr<keysource> k, fee f, ptr<output_pattern> c, satoshi d) : 
            Funds{fun}, Policy{policy}, Keys{k}, Fee{f}, Change{c}, Dust{d} {}
        
        bool valid() const {
            return Policy != unset && data::valid(Funds) && Change != nullptr && Keys != nullptr;
        }
        
        struct spent;
        
        spent spend(list<payment>) const;
    };
    
    struct wallet::spent {
        vertex Vertex;
        wallet Remainder;
        
        bool valid() const {
            return Vertex.valid() && Remainder.valid();
        }
        
    private:
        spent() : Vertex{}, Remainder{} {}
        spent(const vertex& v, const wallet& r) : Vertex{v}, Remainder{r} {}
        
        friend struct wallet;
    };
    
}

#endif


