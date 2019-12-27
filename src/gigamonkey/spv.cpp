// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/spv.hpp>

namespace gigamonkey::bitcoin {
        
    headers headers::attach(const bitcoin::header& h) {
        list<header> prev = Headers[h.Previous];
        if (data::empty(prev)) return {};
        ordered_list<chain> chains = Chains;
        list<chain> chx{};
        chain next;
        while(true) {
            if (data::empty(chains)) {
                next = chain{prev}.add(h);
                chains = Chains;
                break;
            }
            if (chains.first().Chain == prev) {
                next = chains.first().add(h);
                chains = chains.rest();
                while (!data::empty(chx)) {
                    chains = chains.insert(chx.first());
                    chx = chx.rest();
                }
                break;
            }
        }
        return headers{chains.insert(next), Headers.insert(next.Chain.first().Hash, next)};
    }
    
}
