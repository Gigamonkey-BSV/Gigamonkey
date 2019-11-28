// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_HASH
#define GIGAMONKEY_HASH

#include "types.hpp"

namespace gigamonkey {

    namespace sha256 {
        const size_t size = 32;
        
        bool hash(uint<size, little_endian>&, bytes_view);
        bool hash(uint<size, big_endian>&, bytes_view);
    }

    namespace ripemd160 {
        const size_t size = 20;
        
        bool hash(uint<size, little_endian>&, bytes_view);
        bool hash(uint<size, big_endian>&, bytes_view);
    }
    
    template <size_t size, boost::endian::order o> struct digest {
        uint<size, o> Digest; 
        
        digest() : Digest{} {}
        digest(uint<size, o> u) : Digest{u} {}
        
        operator bytes_view() const {
            return bytes_view{Digest.Array.data(), size};
        }
        
        // Zero represents invalid. 
        bool valid() const {
            return Digest != 0;
        }
        
        bool operator==(const digest& d) const {
            return Digest == d.Digest;
        }
        
        bool operator!=(const digest& d) const {
            return Digest != d.Digest;
        }
        
        bool operator<(const digest& d) const {
            return Digest < d.Digest;
        }
        
        bool operator<=(const digest& d) const {
            return Digest <= d.Digest;
        }
        
        bool operator>(const digest& d) const {
            return Digest > d.Digest;
        }
        
        bool operator>=(const digest& d) const {
            return Digest >= d.Digest;
        }
        
    };

    namespace bitcoin {
        
        template <size_t size> using digest = gigamonkey::digest<size, little_endian>;
        template <size_t size> using digest_b = gigamonkey::digest<size, big_endian>;
    
        inline digest<20> ripemd160(bytes_view b) {
            digest<20> digest;
            if (!gigamonkey::ripemd160::hash(digest.Digest, b)) return digest<20>{};
            return digest;
        }
        
        inline digest<32> sha256(bytes_view b) {
            digest<32> digest;
            if (!gigamonkey::sha256::hash(digest.Digest, b)) return digest<32>{};
            return digest;
        }
    
        inline digest<32> double_sha256(bytes_view b) {
            return sha256(sha256(b));
        }
        
        inline digest<20> hash160(bytes_view b) {
            return ripemd160(sha256(b));
        }
        
        inline digest<32> hash256(bytes_view b) {
            return double_sha256(b);
        }
        
        inline digest<20> address_hash(bytes_view b) {
            return hash160(b);
        }
        
        inline digest_b<32> signature_hash(bytes_view b) {
            return 0 // TODO
        }
        
    }
    
}

template <size_t size> 
inline std::ostream& operator<<(std::ostream& o, gigamonkey::bitcoin::digest<size>& s) {
    return o << "digest{" << s.Digest << "}";
}

#endif
