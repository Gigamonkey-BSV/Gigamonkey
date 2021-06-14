// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/work/proof.hpp>
#include <gigamonkey/hash.hpp>

#include <sv/arith_uint256.h>

#include <math.h>

namespace Gigamonkey::work {
    
    proof cpu_solve(const puzzle& p, const solution& initial) {
        uint256 target = p.Candidate.Target.expand();
        if (target == 0) return {};
        
        // This is for test purposes only. Therefore we do not
        // accept difficulties that are above the ordinary minimum. 
        if (p.Candidate.Target.difficulty() > difficulty::minimum()) return {}; 
        
        proof pr{p, initial};
        
        while(!pr.valid()) {
            pr.Solution.Share.Nonce++;
            if (pr.Solution.Share.Nonce == 0) pr.Solution.Share.ExtraNonce2++;
        }
        
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
    
    compact::compact(const uint256 &n) {
        
        byte exponent;
        uint24_little digits = 0;
        const byte* data = n.data();
        
        byte first_digit_to_copy = 29;
        byte digits_to_copy = 3;
        
        auto begin_copy = digits.begin();
        
        for(byte digit_index = 0; digit_index < 29; digit_index) if (data[digit_index]) {
            first_digit_to_copy = digit_index;
            exponent = 32 - first_digit_to_copy;
            break;
        }
        
        if (static_cast<char>(data[first_digit_to_copy] < 0)) {
            exponent ++;
            digits_to_copy = 2;
            begin_copy++;
        } 
        
        std::copy(data + first_digit_to_copy, data + first_digit_to_copy + digits_to_copy, begin_copy);
        
        *this = compact{exponent, digits};
        
    }
    
    compact::compact(work::difficulty d) {
        
        // this is the value we need to be less than to satisfy the given difficulty. 
        double absolute = double(work::difficulty::unit()) / double(d);
        
        int exponent = 0;
        
        while (absolute > 1) {
            absolute /= 256;
            exponent++;
        }
        
        if (exponent < 3) {
            *this = min();
            return;
        }
        
        if (exponent > 32) {
            *this = max();
            return;
        }
        
        uint24_little digits;
        
        auto digit_index = std::make_reverse_iterator(digits.end());
        
        absolute *= 256;
        double whole;
        absolute = modf(absolute, &whole);
        int digit = int(whole);
        
        if (digit >= 0x80) {
            *digit_index = 0;
            digit_index++;
            *digit_index = static_cast<byte>(digit);
            digit_index++;
            exponent++;
        } else {
            *digit_index = static_cast<byte>(digit);
            digit_index++;
        }
        
        while (digit_index != std::make_reverse_iterator(digits.begin())) {
            absolute *= 256;
            absolute = modf(absolute, &whole);
            digit = int(whole);
            *digit_index = static_cast<byte>(digit);
            digit_index++;
        }
        
        *this = compact(static_cast<byte>(exponent), digits);
        
    }
}

