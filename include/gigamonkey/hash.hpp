// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_HASH
#define GIGAMONKEY_HASH

#include "types.hpp"

namespace gigamonkey {

    namespace sha256 {
        const size_t Size = 32;
        
        void hash(uint<Size, LittleEndian>&, bytes_view);
        void hash(uint<Size, BigEndian>&, bytes_view);
    }

    namespace ripemd160 {
        const size_t Size = 20;
        
        void hash(uint<Size, LittleEndian>&, bytes_view);
        void hash(uint<Size, BigEndian>&, bytes_view);
    }
    
    template <size_t size, boost::endian::order e> struct digest {
        constexpr static endian Opposite = gigamonkey::opposite_endian(e);
        
        uint<size, e> Digest; 
        
        digest() : Digest{} {}
        digest(slice<32>);
        digest(const uint<size, e>& u) : Digest{u} {}
        digest(const uint<size, Opposite>& u) : Digest{u} {}
        
        operator bytes_view() const {
            return bytes_view{Digest.Array.data(), size};
        }
        
        explicit operator digest<size, Opposite>() const {
            return digest<size, Opposite>{Digest};
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
    
        inline digest<20, BigEndian> ripemd160(bytes_view b) {
            digest<20, BigEndian> digest;
            gigamonkey::ripemd160::hash(digest.Digest, b);
            return digest;
        }
        
        inline digest<32, BigEndian> sha256(bytes_view b) {
            digest<32, BigEndian> digest;
            gigamonkey::sha256::hash(digest.Digest, b);
            return digest;
        }
    
        inline digest<32, BigEndian> double_sha256(bytes_view b) {
            return sha256(sha256(b));
        }
        
        inline digest<20, BigEndian> hash160(bytes_view b) {
            return ripemd160(sha256(b));
        }
        
        inline digest<32, BigEndian> hash256(bytes_view b) {
            return double_sha256(b);
        }
        
        inline digest<20, BigEndian> address_hash(bytes_view b) {
            return hash160(b);
        }
        
        inline digest<32, BigEndian> signature_hash(bytes_view b) {
            return hash256(b);
        }
        
    }
    
}

template <size_t size> 
inline std::ostream& operator<<(std::ostream& o, const gigamonkey::digest<size, gigamonkey::BigEndian>& s) {
    return o << "digest{" << s.Digest << "}";
}

template <size_t size> 
inline std::ostream& operator<<(std::ostream& o, const gigamonkey::digest<size, gigamonkey::LittleEndian>& s) {
    using namespace gigamonkey;
    return o << digest<size, BigEndian>{s};
}

template <size_t size> 
gigamonkey::bytes_writer operator<<(gigamonkey::bytes_writer, const gigamonkey::digest<size, gigamonkey::LittleEndian>& s);

template <size_t size> 
gigamonkey::bytes_reader operator>>(gigamonkey::bytes_reader, gigamonkey::digest<size, gigamonkey::LittleEndian>& s);

#endif
