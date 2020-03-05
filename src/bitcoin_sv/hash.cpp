#include <gigamonkey/hash.hpp>
#include <hash.h>

#include "arith_uint256.h"

namespace Gigamonkey::Bitcoin {
    
    digest256 hash256(bytes_view b) {
        ::uint256 u{::Hash(b.begin(), b.end())};
        Gigamonkey::uint256 x;
        std::copy(u.begin(), u.end(), x.begin());
        return digest256{x};
    } 
    
    digest160 hash160(bytes_view b) {
        ::uint160 u = ::Hash160(b.begin(), b.end());
        Gigamonkey::uint160 x;
        std::copy(u.begin(), u.end(), x.begin());
        return digest160{x};
    }

    digest256 hash256(string_view b) {
        ::uint256 u = ::Hash(b.begin(), b.end());
        Gigamonkey::uint256 x;
        std::copy(u.begin(), u.end(), x.begin());
        return digest256{x};
    }
    
    digest160 hash160(string_view b) {
        ::uint160 u = ::Hash160(b.begin(), b.end());
        Gigamonkey::uint160 x;
        std::copy(u.begin(), u.end(), x.begin());
        return digest160{x};
    }
    
}


