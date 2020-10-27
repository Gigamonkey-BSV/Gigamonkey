// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_STRATUM_DIFFICULTY
#define GIGAMONKEY_STRATUM_DIFFICULTY

#include <gigamonkey/work/target.hpp>

namespace Gigamonkey::Stratum {
    
    // stratum uses an int value to represent difficulty
    // even though it can theoretically take on any value. 
    struct difficulty : nonzero<uint64> {
        using nonzero<uint64>::nonzero;
        
        explicit difficulty(const uint256&);
        explicit difficulty(const work::compact& t) : difficulty{t.expand()} {}
        explicit difficulty(const work::difficulty& d) : nonzero<uint64>{static_cast<uint64>(double(d))} {}
        
        explicit operator uint256() const;

    };
}

#endif
