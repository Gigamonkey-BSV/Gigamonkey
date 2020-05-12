// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_HASH
#define GIGAMONKEY_HASH

#include "types.hpp"
#include <data/encoding/integer.hpp>

#include "arith_uint256.h"

namespace Gigamonkey {
    
    template <size_t size, unsigned int bits = 8 * size> struct uint : base_uint<bits> {
        uint(uint64 u) : base_uint<bits>(u) {}
        uint() : uint(0) {}
        
        uint(const slice<size>);
        
        explicit uint(string_view hex);
        explicit uint(const base_uint<bits>& b) : base_uint<bits>{b} {}
        
        explicit uint(::uint256);
        explicit uint(arith_uint256);
        
        byte* begin() {
            return (byte*)base_uint<bits>::pn;
        }
        
        byte* end() {
            return begin() + size;
        }
        
        const byte* begin() const {
            return (byte*)this->pn;
        }
        
        const byte* end() const {
            return begin() + size;
        }
        
        byte* data() {  
            return begin();
        }
        
        const byte* data() const {
            return begin();
        }
        
        operator bytes_view() const {
            return bytes_view{data(), size};
        }
        
        operator slice<size>() {
            return slice<size>(data());
        }
        
        operator const slice<size>() const {
            return slice<size>(const_cast<byte*>(data()));
        }
        
        explicit operator N() const;
        
        uint& operator=(uint64_t b) {
            base_uint<bits>::operator=(b);
            return *this;
        }
        
        uint& operator^=(const uint& b) {
            base_uint<bits>::operator^=(b);
            return *this;
        }

        uint& operator&=(const uint& b) {
            base_uint<bits>::operator&=(b);
            return *this;
        }

        uint& operator|=(const uint& b) {
            base_uint<bits>::operator|=(b);
            return *this;
        }

        uint& operator^=(uint64 b) {
            base_uint<bits>::operator^=(b);
            return *this;
        }
        
        uint& operator|=(uint64 b) {
            base_uint<bits>::operator|=(b);
            return *this;
        }
        
        uint& operator<<=(unsigned int shift) {
            base_uint<bits>::operator<<=(shift);
            return *this;
        }
        
        uint& operator>>=(unsigned int shift) {
            base_uint<bits>::operator>>=(shift);
            return *this;
        }
        
        uint& operator+=(const uint& b) {
            base_uint<bits>::operator+=(b);
            return *this;
        }
        
        uint& operator-=(const uint& b) {
            base_uint<bits>::operator-=(b);
            return *this;
        }
        
        uint& operator+=(uint64 b) {
            base_uint<bits>::operator+=(b);
            return *this;
        }
        
        uint& operator-=(uint64 b) {
            base_uint<bits>::operator-=(b);
            return *this;
        }
        
        uint& operator*=(uint32 b) {
            base_uint<bits>::operator*=(b);
            return *this;
        }
        
        uint& operator*=(const uint& b) {
            base_uint<bits>::operator*=(b);
            return *this;
        }
        
        uint& operator/=(const uint& b) {
            base_uint<bits>::operator/=(b);
            return *this;
        }
        
        uint& operator++() {
            base_uint<bits>::operator++();
            return *this;
        }
        
        const uint operator++(int) {
            // postfix operator
            const uint ret = *this;
            ++(*this);
            return ret;
        }
        
        uint& operator--() {
            base_uint<bits>::operator--();
            return *this;
        }
        
        const uint operator--(int) {
            // postfix operator
            const uint ret = *this;
            --(*this);
            return ret;
        }
    };
    
    using uint160 = uint<20>;
    using uint256 = uint<32>;
    
    template <size_t size> struct digest : nonzero<uint<size>> {
        
        digest() : nonzero<uint<size>>{} {}
        
        explicit digest(const uint<size>& u) : nonzero<uint<size>>{u} {}
        explicit digest(string_view s) : nonzero<uint<size>>{uint<size>{s}} {}
        explicit digest(const slice<size>& x) : digest{uint<size>(x)} {}
        
        operator bytes_view() const {
            return bytes_view(nonzero<uint<size>>::Value);
        }
        
        explicit operator N() const;
        
        byte* begin() {
            return nonzero<uint<size>>::Value.begin();
        }
        
        byte* end() {
            return nonzero<uint<size>>::Value.end();
        }
        
        const byte* begin() const {
            return nonzero<uint<size>>::Value.begin();
        }
        
        const byte* end() const {
            return nonzero<uint<size>>::Value.end();
        }
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
    
        digest160 hash160(string_view b);
        digest256 hash256(string_view b);
        
        inline digest160 address_hash(bytes_view b) {
            return hash160(b);
        }
        
        inline digest256 signature_hash(bytes_view b) {
            return hash256(b);
        }
    
    }
    
}



namespace data::encoding::hexidecimal { 
    
    template <size_t size, unsigned int bits> 
    inline std::string write(const Gigamonkey::uint<size, bits>& n) {
        return write((N)(n));
    }
    
    template <size_t size, unsigned int bits> 
    inline std::ostream& write(std::ostream& o, const Gigamonkey::uint<size, bits>& n) {
        return o << write(n);
    }
    
}

namespace data::encoding::integer {
    
    template <size_t size, unsigned int bits> 
    inline std::string write(const Gigamonkey::uint<size, bits>& n) {
        return write((N)(n));
    }
    
    template <size_t size, unsigned int bits> 
    inline std::ostream& write(std::ostream& o, const Gigamonkey::uint<size, bits>& n) {
        return o << write(n);
    }
    
}

template <size_t size, unsigned int bits> 
inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::uint<size, bits>& s) {
    return o << data::encoding::hexidecimal::write((data::bytes_view)(s), data::endian::little);
}

template <size_t size> 
inline std::ostream& operator<<(std::ostream& o, const Gigamonkey::digest<size>& s) {
    return o << "digest{" << s.Value << "}";
}

template <size_t size, unsigned int bits> 
inline Gigamonkey::bytes_writer operator<<(Gigamonkey::bytes_writer w, const Gigamonkey::uint<size, bits>& s) {
    return w << data::bytes_view(s);
}

template <size_t size, unsigned int bits>
inline Gigamonkey::bytes_reader operator>>(Gigamonkey::bytes_reader r, Gigamonkey::uint<size, bits>& s) {
    data::bytes b(size);
    Gigamonkey::bytes_reader rx = r >> b;
    std::copy(b.begin(), b.end(), s.begin());
    return rx;
}

template <size_t size> 
inline Gigamonkey::bytes_writer operator<<(Gigamonkey::bytes_writer w, const Gigamonkey::digest<size>& s) {
    return w << s.Value;
}

template <size_t size> 
inline Gigamonkey::bytes_reader operator>>(Gigamonkey::bytes_reader r, Gigamonkey::digest<size>& s) {
    return r >> s.Value;
}

namespace Gigamonkey {

    template <size_t size, unsigned int bits>
    inline uint<size, bits>::uint(const slice<size> x) {
        std::copy(x.begin(), x.end(), begin());
    }
    
    template <size_t size, unsigned int bits>
    uint<size, bits>::operator N() const {
        N n(0);
        int width = size / 4;
        int i;
        for (i = width - 1; i > 0; i--) {
            uint32 step = boost::endian::load_little_u32(data() + 4 * i);
            n += step;
            n <<= 32;
        }
        n += uint64(boost::endian::load_little_u32(data()));
        return n;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>::uint(string_view hex) : uint(0) {
        if (hex.size() != size * 2 + 2) return;
        if (!data::encoding::hexidecimal::valid(hex)) return;
        bytes read = bytes_view(encoding::hex::string{hex.substr(2)});
        std::reverse_copy(read.begin(), read.end(), begin());
    }

}

#endif
