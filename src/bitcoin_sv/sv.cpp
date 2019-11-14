// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include "sv.hpp"
#include <streams.h>
#include <serialize.h>
#include <primitives/transaction.h>

namespace abstractions::sv {
    
    static const int version = 0; // TODO
    
    sha256::digest convert(const digest x) {
        sha256::digest d;
        std::copy(x.begin(), x.end(), d.Digest.begin());
        return d;
    }
    
    CTransaction read_transaction(bytes_view tx) {
        auto stream = CDataStream{(const char*)(tx.data()), (const char*)(tx.data() + tx.size()), 
            SER_NETWORK, // TODO I don't know what should go here exactly. 
            sv::version 
        };
        return CTransaction{deserialize, stream}; 
    }
    
    CScript read_script(bytes_view b) {
        return CScript{b.begin(), b.end()};
    }
    
} 

