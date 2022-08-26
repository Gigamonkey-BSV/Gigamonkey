// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_HASH
#define GIGAMONKEY_HASH

#include "number.hpp"
#include <data/crypto/hash/hash.hpp>

namespace Gigamonkey {
    
    // a hash digest. 
    template <size_t size> using digest = data::crypto::digest<size>;
    
    using digest128 = digest<16>;
    using digest160 = digest<20>;
    using digest224 = digest<28>;
    using digest256 = digest<32>;
    using digest320 = digest<40>;
    using digest384 = digest<48>;
    using digest448 = digest<56>;
    using digest512 = digest<64>;
    
    template <size_t size> 
    inline writer &operator<<(writer &w, const digest<size> &s) {
        return w << bytes_view(s);
    }
    
    template <size_t size> 
    inline reader &operator>>(reader &r, digest<size> &s) {
        r.read(s.data(), size);
        return r;
    }
    
    // supported hash functions.
    digest160 SHA1(bytes_view);
    digest160 SHA1(string_view);
    
    digest224 SHA2_224(bytes_view);
    digest224 SHA2_224(string_view);
    digest256 SHA2_256(bytes_view);
    digest256 SHA2_256(string_view);
    digest384 SHA2_384(bytes_view);
    digest384 SHA2_384(string_view);
    digest512 SHA2_512(bytes_view);
    digest512 SHA2_512(string_view);
    
    template <size_t size> digest<size> SHA3(bytes_view);
    template <size_t size> digest<size> SHA3(string_view);
    
    digest224 SHA3_224(bytes_view);
    digest224 SHA3_224(string_view);
    digest256 SHA3_256(bytes_view);
    digest256 SHA3_256(string_view);
    digest384 SHA3_384(bytes_view);
    digest384 SHA3_384(string_view);
    digest512 SHA3_512(bytes_view);
    digest512 SHA3_512(string_view);
    
    digest128 RIPEMD_128(bytes_view);
    digest128 RIPEMD_128(string_view);
    digest160 RIPEMD_160(bytes_view);
    digest160 RIPEMD_160(string_view);
    digest256 RIPEMD_256(bytes_view);
    digest256 RIPEMD_256(string_view);
    digest320 RIPEMD_320(bytes_view);
    digest320 RIPEMD_320(string_view);
    
    digest256 inline double_SHA2_256(bytes_view b) {
        return SHA2_256(SHA2_256(b));
    }
    
    namespace Bitcoin {
    
        // bitcoin hash functions. 
        digest160 inline Hash160(bytes_view b) {
            return RIPEMD_160(SHA2_256(b));
        }
        
        digest256 inline Hash256(bytes_view b) {
            return double_SHA2_256(b);
        }
        
        digest160 Hash160(string_view b);
        digest256 Hash256(string_view b);
        
        digest160 inline address_hash(bytes_view b) {
            return Hash160(b);
        }
        
        digest256 inline signature_hash(bytes_view b) {
            return Hash256(b);
        }
    
    }
    
    digest160 inline SHA1(string_view b) {
        return SHA1(bytes_view{(const byte*)(b.data()), b.size()});
    }
    
    digest224 inline SHA2_224(string_view b) {
        return SHA2_224(bytes_view{(const byte*)(b.data()), b.size()});
    }
    
    digest256 inline SHA2_256(string_view b) {
        return SHA2_256(bytes_view{(const byte*)(b.data()), b.size()});
    }
    
    digest384 inline SHA2_384(string_view b) {
        return SHA2_384(bytes_view{(const byte*)(b.data()), b.size()});
    }
    
    digest512 inline SHA2_512(string_view b) {
        return SHA2_512(bytes_view{(const byte*)(b.data()), b.size()});
    }
    
    digest224 inline SHA3_224(string_view b) {
        return SHA3_224(bytes_view{(const byte*)(b.data()), b.size()});
    }
    
    digest256 inline SHA3_256(string_view b) {
        return SHA3_256(bytes_view{(const byte*)(b.data()), b.size()});
    }
    
    digest384 inline SHA3_384(string_view b) {
        return SHA3_384(bytes_view{(const byte*)(b.data()), b.size()});
    }
    
    digest512 inline SHA3_512(string_view b) {
        return SHA3_512(bytes_view{(const byte*)(b.data()), b.size()});
    }
    
    digest128 inline RIPEMD_128(string_view b) {
        return RIPEMD_128(bytes_view{(const byte*)(b.data()), b.size()});
    }
    
    digest160 inline RIPEMD_160(string_view b) {
        return RIPEMD_160(bytes_view{(const byte*)(b.data()), b.size()});
    }
    
    digest256 inline RIPEMD_256(string_view b) {
        return RIPEMD_256(bytes_view{(const byte*)(b.data()), b.size()});
    }
    
    digest320 inline RIPEMD_320(string_view b) {
        return RIPEMD_320(bytes_view{(const byte*)(b.data()), b.size()});
    }
    
    namespace Bitcoin {
        
        digest160 inline Hash160(string_view b) {
            return Hash160(bytes_view{(const byte*)(b.data()), b.size()});
        }
        
        digest256 inline Hash256(string_view b) {
            return Hash256(bytes_view{(const byte*)(b.data()), b.size()});
        }
    
    }
    
    namespace Bitcoin {
        using Hash256_writer = data::crypto::hash::Bitcoin<32>;
        using Hash160_writer = data::crypto::hash::Bitcoin<20>;
    }
    
    template <size_t size> using SHA2_writer = data::crypto::hash::SHA2<size>;
    template <size_t size> using SHA3_writer = data::crypto::hash::SHA3<size>;
    template <size_t size> using RIPEMD_writer = data::crypto::hash::RIPEMD<size>;
    
    using SHA2_224_writer = SHA2_writer<28>;
    using SHA2_256_writer = SHA2_writer<32>;
    using SHA2_384_writer = SHA2_writer<48>;
    using SHA2_512_writer = SHA2_writer<64>;
    
    using SHA3_224_writer = SHA3_writer<28>;
    using SHA3_256_writer = SHA3_writer<32>;
    using SHA3_384_writer = SHA3_writer<48>;
    using SHA3_512_writer = SHA3_writer<64>;
    
    using RIPEMD_128_writer = RIPEMD_writer<16>;
    using RIPEMD_160_writer = RIPEMD_writer<20>;
    using RIPEMD_256_writer = RIPEMD_writer<32>;
    using RIPEMD_320_writer = RIPEMD_writer<40>;
    
    digest160 inline SHA1(bytes_view b) {
        return data::crypto::hash::calculate<data::crypto::hash::SHA1>(b);
    }
    
    digest224 inline SHA2_224(bytes_view b) {
        return data::crypto::hash::calculate<SHA2_224_writer>(b);
    }
    
    digest256 inline SHA2_256(bytes_view b) {
        return data::crypto::hash::calculate<SHA2_256_writer>(b);
    }
    
    digest384 inline SHA2_384(bytes_view b) {
        return data::crypto::hash::calculate<SHA2_384_writer>(b);
    }
    
    digest512 inline SHA2_512(bytes_view b) {
        return data::crypto::hash::calculate<SHA2_512_writer>(b);
    }
    
    digest224 inline SHA3_224(bytes_view b) {
        return data::crypto::hash::calculate<SHA3_224_writer>(b);
    }
    
    digest256 inline SHA3_256(bytes_view b) {
        return data::crypto::hash::calculate<SHA3_256_writer>(b);
    }
    
    digest384 inline SHA3_384(bytes_view b) {
        return data::crypto::hash::calculate<SHA3_384_writer>(b);
    }
    
    digest512 inline SHA3_512(bytes_view b) {
        return data::crypto::hash::calculate<SHA3_512_writer>(b);
    }
    
    digest128 inline RIPEMD_128(bytes_view b) {
        return data::crypto::hash::calculate<RIPEMD_128_writer>(b);
    }
    
    digest160 inline RIPEMD_160(bytes_view b) {
        return data::crypto::hash::calculate<RIPEMD_160_writer>(b);
    }
    
    digest256 inline RIPEMD_256(bytes_view b) {
        return data::crypto::hash::calculate<RIPEMD_256_writer>(b);
    }
    
    digest320 inline RIPEMD_320(bytes_view b) {
        return data::crypto::hash::calculate<RIPEMD_320_writer>(b);
    }
    
}

#endif
