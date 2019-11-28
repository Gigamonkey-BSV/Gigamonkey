// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_BITCOIN
#define BITCOIN_BITCOIN

#include "keys.hpp"

namespace gigamonkey::bitcoin {
    
    struct output{
        satoshi Value;
        bytes Script;
    };
    
    using input = bytes;
    using transaction = bytes;
    
    // The message that is to be signed to redeem a transaction. 
    bytes spend_order(uint32 sig_hash_type, const output&, const transaction&, index);
    
    // create a valid signature for a transaction. 
    inline signature sign(const secret& s, uint32 sig_hash_type, const output& previous, const transaction& redeemed, index input) {
        return sign(s, sig_hash_type, signature_hash(spend_order(sig_hash_type, previous, redeemed, input)));
    }
    
    // verify a script. 
    bool verify(const output&, const input&, const transaction&, index);
    
    // verify a script ignoring signature checking. 
    bool verify(output, input);
    
}

#endif
