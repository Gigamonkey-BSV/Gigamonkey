// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_HASH
#define GIGAMONKEY_HASH

#include "types.hpp"

namespace gigamonkey {

    namespace sha256 {
        const size_t Size = 32;
        
        void hash(uint<Size, LittleEndian>&, bytes_view);
    }

    namespace ripemd160 {
        const size_t Size = 20;
        
        void hash(uint<Size, LittleEndian>&, bytes_view);
    }
    
    template <size_t size> struct digest {
        uint<size, LittleEndian> Digest; 
        
        digest() : Digest{} {}
        digest(slice<32>);
        digest(const uint<size, LittleEndian>& u) : Digest{u} {}
        
        operator bytes_view() const {
            return bytes_view{Digest.Array.data(), size};
        }
        
        // Zero represents invalid even though it is theoretically
        // possible for a hash digest to come out all zeros. 
        bool valid() const {
            return Digest != 0;
        }
        
        digest& operator=(const digest&);
        
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
    
        inline digest<20> ripemd160(bytes_view b) {
            digest<20> digest;
            gigamonkey::ripemd160::hash(digest.Digest, b);
            return digest;
        }
        
        inline digest<32> sha256(bytes_view b) {
            digest<32> digest;
            gigamonkey::sha256::hash(digest.Digest, b);
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
        
        inline digest<32> signature_hash(bytes_view b) {
            return hash256(b);
        }
        
    }
    
}

template <size_t size> 
inline std::ostream& operator<<(std::ostream& o, const gigamonkey::digest<size>& s) {
    return o << "digest{" << s.Digest << "}";
}

template <size_t size> 
gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer, const gigamonkey::digest<size>& s);

template <size_t size> 
gigamonkey::bytes_reader operator>>(gigamonkey::bytes_reader, gigamonkey::digest<size>& s);

#endif
