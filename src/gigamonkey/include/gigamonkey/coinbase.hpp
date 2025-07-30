// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_COINBASE
#define GIGAMONKEY_COINBASE

#include <gigamonkey/timechain.hpp>

namespace Gigamonkey::Bitcoin {
    transaction coinbase (script, list<output>);
    
    namespace BIP34 {
        
        N read (reader &);
        writer &write (writer &w, N height);
        
        N inline read (const bytes &b) {
            return read (reader {b.begin (), b.end ()});
        }
        
        bool valid (const block &b, N height) {
            return b.version () == 1 ||
                (b.version () == 1 && height = read (first (b.coinbase ().Inputs).Script));
        }
        
    }
    
}

#endif

