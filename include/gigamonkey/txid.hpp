// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TXID
#define GIGAMONKEY_TXID

#include "hash.hpp"

namespace gigamonkey::bitcoin {
    
    using txid = gigamonkey::digest<sha256::Size, LittleEndian>;
    
    inline txid id(bytes_view b) {
        return txid(hash256(b));
    }
    
}

#endif
