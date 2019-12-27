// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_REDEEM
#define GIGAMONKEY_REDEEM

#include "signature.hpp"
#include "spendable.hpp"

namespace gigamonkey::bitcoin {
    
    struct funds {
        queue<spendable> Entries;
        satoshi Value;
        bool Valid;
        
        funds() : Entries{}, Value{0}, Valid{true} {}
        
        funds insert(spendable s) const {
            return {Entries << s, Value + s.value(), Valid && s.valid()};
        }
    };
    
    inline bytes redeem(funds f, int32_little version, list<output> outputs, int32_little locktime, sighash::directive d) {
        const vertex v{data::for_each([](const spendable& s)->prevout{return s.Prevout;}, f), version, outputs, locktime};
        return transaction{version, data::for_each([&v](uint32 i, const spendable& s)->bytes{s.redeem(v, i, d)}, f.Entries), outputs, locktime}.write();
    }
}

#endif
