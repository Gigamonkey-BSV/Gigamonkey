// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_HASH
#define GIGAMONKEY_HASH

#include "types.hpp"

#include "arith_uint256.h"

namespace Gigamonkey {
    
    template <size_t size> struct digest : nonzero<uint<size>> {
        
        digest() : nonzero<uint<size>>{} {}
        
        explicit digest(const uint<size>& u) : nonzero<uint<size>>{u} {}
        explicit digest(string_view s) : nonzero<uint<size>>{uint<size>{s}} {}
        explicit digest(const nonzero<uint32_little>& n) : nonzero<uint32_little>{n} {}
        explicit digest(const slice<size>& x) : digest{uint<size>(x)} {}
        explicit digest(const base_uint<size * 8>& b);
        
        operator bytes_view() const {
            return bytes_view(nonzero<uint<size>>::Value);
        }
        
        explicit operator N() const;
    };

    using digest160 = digest<20>;
    using digest256 = digest<32>;
    using digest512 = digest<64>;
    
    digest160 ripemd160(bytes_view b);
    digest256 sha256(bytes_view b);
    
    digest160 ripemd160(string_view b);
    digest256 sha256(string_view b);
    
    namespace Bitcoin {
    
        digest160 hash160(bytes_view b);
        digest256 hash256(bytes_view b);
        
        inline digest<20> address_hash(bytes_view b) {
            return hash160(b);
        }
        
        inline digest<32> signature_hash(bytes_view b) {
            return hash256(b);
        }
    
    }
    
}

template <size_t size> 
inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::digest<size>& s) {
    return o << "digest{" << s.Digest << "}";
}

template <size_t size> 
inline Gigamonkey::bytes_writer operator<<(Gigamonkey::bytes_writer w, const Gigamonkey::digest<size>& s) {
    return w << s.Value;
}

template <size_t size> 
inline Gigamonkey::bytes_reader operator>>(Gigamonkey::bytes_reader r, Gigamonkey::digest<size>& s) {
    return r >> s.Value;
}

#endif
