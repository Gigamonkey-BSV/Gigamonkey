// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_REDEEM
#define GIGAMONKEY_REDEEM

#include "timechain.hpp"
#include "wif.hpp"
#include "spendable.hpp"

namespace Gigamonkey::Bitcoin {
    
    struct prevout {
        bytes Output;
        uint<36> Outpoint;
        
        bool valid() const {
            return Gigamonkey::output::valid(Output) && Gigamonkey::outpoint::valid(slice<36>(Outpoint));
        }
    };
    
    struct vertex {
        list<prevout> Prevout;
        int32_little Version;
        list<output> Outputs;
        uint32_little Locktime;
        
        vertex(list<prevout> p, int32_little v, list<output> o, uint32_little l) : 
            Prevout{p}, Version{v}, Outputs{o}, Locktime{l} {}
        
        input_index operator[](index i) const;
        
    private:
        // Put cached data here.
    };
    
    digest<32> signature_hash(const vertex& v, index i, sighash::directive d);
    
    inline signature sign(const vertex& v, index i, sighash::directive d, const secp256k1::secret& s) {
        return signature{secp256k1::sign(s, signature_hash(v, i, d)), d};
    }
    
    inline bool verify(const signature& x, const vertex& v, index i, sighash::directive d, const secp256k1::pubkey& p) {
        return secp256k1::verify(p, signature_hash(v, i, d), x.raw());
    }
    
    struct redeemer {
        virtual bytes redeem(const input_index& tx, sighash::directive d) const = 0;
    };
    
    struct spendable {
        prevout Prevout;
        ptr<redeemer> Redeemer;
        
        satoshi value() const {
            return Gigamonkey::output::value(Prevout.Output);
        }
        
        bool valid() const {
            return Prevout.valid() && Redeemer != nullptr;
        } 
    };
    
    struct funds {
        list<spendable> Entries;
        satoshi Value;
        bool Valid;
        
        funds() : Entries{}, Value{0}, Valid{true} {}
        funds(list<spendable> e, satoshi a, bool v) : Entries{e}, Value{a}, Valid{v} {}
        
        funds insert(spendable s) const {
            return {Entries << s, Value + s.value(), Valid && s.valid()};
        }
    };
    /*
    inline bytes redeem(funds f, int32_little version, list<output> outputs, uint32_little locktime, sighash::directive d) {
        const vertex v{data::for_each([](const spendable& s) -> prevout {
            return s.Prevout;
        }, f.Entries), version, outputs, locktime};
        return transaction{version, 
            data::for_each([&v](uint32 i, const spendable& s) -> bytes {
            s.redeem(v, i, d)}, f.Entries), outputs, locktime}.write();
    }*/
}

#endif
