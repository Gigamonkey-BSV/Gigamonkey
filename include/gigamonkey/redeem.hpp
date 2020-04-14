// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_REDEEM
#define GIGAMONKEY_REDEEM

#include "timechain.hpp"
#include "wif.hpp"

namespace Gigamonkey::Bitcoin {
    
    struct redeemer {
        // create a redeem script. 
        virtual bytes redeem(const input_index& tx, sighash::directive d) const = 0;
    };
    
    struct prevout {
        output Output;
        outpoint Outpoint;
        
        bool valid() const {
            return Output.valid() && Outpoint.valid();
        }
    };
    
    struct spendable {
        prevout Prevout;
        redeemer& Redeemer;
        
        bool valid() const {
            return Prevout.valid();
        } 
    };
    
    transaction redeem(list<spendable> prev, list<output> out, uint32_little locktime);
    
    inline transaction redeem(list<spendable> prev, list<output> out) {
        return redeem(prev, out, 0);
    }
    
    // TODO this can go in the cpp file. 
    struct vertex {
        list<spendable> Prevout;
        int32_little Version;
        list<output> Outputs;
        uint32_little Locktime;
        
        vertex(list<spendable> p, int32_little v, list<output> o, uint32_little l) : 
            Prevout{p}, Version{v}, Outputs{o}, Locktime{l} {}
        
        input_index operator[](index i) const;
        
    private:
        // Put cached data here.
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
