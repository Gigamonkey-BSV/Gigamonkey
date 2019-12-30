// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work.hpp>

namespace gigamonkey::work {
    
    bool satisfied(order o, nonce n) {}
    
    // roughly 1/16 odds. 
    const target minimum{32, 0x000fffff};
    
    nonce work(order o) {
        if (o.Target < minimum) throw std::invalid_argument{"minimum target"};
        nonce n = 0;
        while (true) {
            if (candidate{o, n}.valid()) return n;
            n++;
        }
    }
    
}

