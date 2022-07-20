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
        
        proof pr{p, initial};
        
        while(!pr.valid()) {
            pr.Solution.Share.Nonce++;
            if (pr.Solution.Share.Nonce == 0) {
                if (pr.Solution.Share.ExtraNonce2[-1] == 0xff) throw std::logic_error{"we don't know how to increment extra_nonce_2"};
                ++pr.Solution.Share.ExtraNonce2[-1];
            }
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
        if (nWord != 0 && (compact & 0x00800000) != 0) {
            std::cout << "    negative number!!!!!" << std::endl;
            return 0;
        }
        
        // overflow
        if (nWord != 0 && ((nSize > 34) || (nWord > 0xff && nSize > 33) ||
                           (nWord > 0xffff && nSize > 32))) return 0;
        
        return expanded;
    }
    
    compact::compact(const uint256 &n) {
        std::cout << "getting compact from uint256 " << n << std::endl;
        byte exponent;
        uint24_little digits = 0;
        const byte* data = n.data();
        
        byte first_digit_to_copy = 29;
        byte digits_to_copy = 3;
        
        auto begin_copy = digits.end() - 1;
        
        for(byte digit_index = 31; digit_index > 2; digit_index--) if (data[digit_index]) {
            first_digit_to_copy = digit_index;
            exponent = first_digit_to_copy + 1;
            break;
        }
        
        if (data[first_digit_to_copy] & 0x80) {
            exponent ++;
            digits_to_copy = 2;
            begin_copy--;
        } 
        
        for (int i = 0; i < digits_to_copy; i++) {
            *begin_copy = data[first_digit_to_copy - i];
            begin_copy--;
        }
        
        *this = compact{exponent, digits};
        
    }
    
    compact::compact(work::difficulty d) {
        
        // this is the value we need to be less than to satisfy the given difficulty. 
        float64 absolute = float64(work::difficulty::unit()) / float64(d);
        
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
        float64 whole;
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
    
    difficulty::operator uint256() const {
        if (!valid()) return 0;
        
        float64 val = float64(unit()) / Value;
        int exp;
        float64 mantissa = frexp(val, &exp);
        uint64 mantissa_bits;
        
        std::copy((byte*)(&mantissa), (byte*)(&mantissa) + 8, (byte*)(&mantissa_bits));
        mantissa_bits = (mantissa_bits & 0x000fffffffffffff) + 0x0010000000000000;
        
        return uint256(mantissa_bits) << (exp - standard_binary_interchange_format_mantissa_bits<64>() - 1);
    }
        
}

