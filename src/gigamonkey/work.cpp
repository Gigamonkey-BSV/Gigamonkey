// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/proof.hpp>
#include <gigamonkey/hash.hpp>

#include <sv/arith_uint256.h>

namespace Gigamonkey::work {
    
    proof cpu_solve(const puzzle& p, const solution& initial) {
        uint256 target = p.Candidate.Target.expand();
        if (target == 0) return {};
        // This is for test purposes only. Therefore we do not
        // accept difficulties that are above the ordinary minimum. 
        if (p.Candidate.Target.difficulty() > difficulty::minimum()) return {}; 
        proof pr{p, initial};
        while(!pr.valid()) pr.Solution.Share.Nonce++;
        return pr;
    }
    
    // copied from arith_uint256.cpp and therefore probably works. 
    uint256 expand(const compact& c) {
        uint32 compact = c;
        uint256 expanded;
        int nSize = compact >> 24;
        uint32_t nWord = compact & 0x007fffff;
        if (nSize <= 3) {
            nWord >>= 8 * (3 - nSize);
            expanded = nWord;
        } else {
            expanded = nWord;
            expanded <<= 8 * (nSize - 3);
        }
        
        // negative 
        if (nWord != 0 && (compact & 0x00800000) != 0) return 0;
        
        // overflow
        if (nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) ||
                           (nWord > 0xffff && nSize > 32))) return 0;
        
        return expanded;
    }
    
}

