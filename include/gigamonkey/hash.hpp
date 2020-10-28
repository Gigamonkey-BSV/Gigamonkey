// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_HASH
#define GIGAMONKEY_HASH

#include <sv/arith_uint256.h>

#include <gigamonkey/types.hpp>

#include <data/encoding/integer.hpp>
#include <data/math/number/bytes/N.hpp>

namespace Gigamonkey {
    
    // a representation of uints of any size. 
    template <size_t size, unsigned int bits = 8 * size> struct uint : sv::base_uint<bits> {
        uint(uint64 u) : sv::base_uint<bits>(u) {}
        uint() : uint(0) {}
        
        uint(const slice<size>);
        
        explicit uint(string_view hex);
        explicit uint(const sv::base_uint<bits>& b) : sv::base_uint<bits>{b} {}
        explicit uint(const N& n);
        
        explicit uint(const sv::uint256&);
        explicit uint(const sv::arith_uint256&);
        
        explicit operator N() const;
        explicit operator double() const;
        
        operator bytes_view() const;
        operator slice<size>();
        operator const slice<size>() const;
        
        uint& operator=(uint64_t b);
        uint& operator=(const sv::base_uint<bits>& b);
        
        uint& operator^=(const uint& b);
        uint& operator&=(const uint& b);
        uint& operator|=(const uint& b);
        uint& operator^=(uint64 b);
        uint& operator|=(uint64 b);
        
        uint operator<<(unsigned int shift);
        uint operator>>(unsigned int shift);
        
        uint& operator<<=(unsigned int shift);
        uint& operator>>=(unsigned int shift);
        
        uint& operator+=(const uint& b);
        uint& operator-=(const uint& b);
        uint& operator+=(uint64 b);
        uint& operator-=(uint64 b);
        uint& operator*=(uint32 b);
        uint& operator*=(const uint& b);
        uint& operator/=(const uint& b);
        
        uint& operator++();
        const uint operator++(int);
        
        uint& operator--();
        const uint operator--(int);
        
        uint operator*(const uint& ret);
        
        byte* begin();
        byte* end();
        
        const byte* begin() const;
        const byte* end() const;
        
        byte* data();
        const byte* data() const;
    };
    
    // sizes of standard hash functions. 
    using uint160 = uint<20>;
    using uint256 = uint<32>;
    using uint512 = uint<64>;

    // a hash digest. 
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
        
        bool operator==(const digest& d) const {
            return nonzero<uint<size>>::Value == d.Value;
        }
        
        bool operator!=(const digest& d) const {
            return nonzero<uint<size>>::Value != d.Value;
        }
        
        bool operator>(const digest& d) const {
            return nonzero<uint<size>>::Value > d.Value;
        }
        
        bool operator<(const digest& d) const {
            return nonzero<uint<size>>::Value < d.Value;
        }
        
        bool operator<=(const digest& d) const {
            return nonzero<uint<size>>::Value <= d.Value;
        }
        
        bool operator>=(const digest& d) const {
            return nonzero<uint<size>>::Value >= d.Value;
        }
    };

    using digest160 = digest<20>;
    using digest256 = digest<32>;
    using digest512 = digest<64>;
    
    // standard hash functions. 
    digest160 ripemd160(bytes_view b);
    digest256 sha256(bytes_view b);
    
    digest160 ripemd160(string_view b);
    digest256 sha256(string_view b);
    
    namespace Bitcoin {
    
        // bitcoin hash functions. 
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

    template <size_t size, unsigned int bits> 
    inline std::ostream& operator<<(std::ostream& o, const uint<size, bits>& s) {
        return o << data::encoding::hexidecimal::write((data::bytes_view)(s), data::endian::little);
    }

    template <size_t size> 
    inline std::ostream& operator<<(std::ostream& o, const digest<size>& s) {
        return o << "digest{" << s.Value << "}";
    }

    template <size_t size, unsigned int bits> 
    inline bytes_writer operator<<(bytes_writer w, const uint<size, bits>& s) {
        return w << data::bytes_view(s);
    }

    template <size_t size, unsigned int bits>
    inline bytes_reader operator>>(bytes_reader r, uint<size, bits>& s) {
        data::bytes b(size);
        bytes_reader rx = r >> b;
        std::copy(b.begin(), b.end(), s.begin());
        return rx;
    }

    template <size_t size> 
    inline bytes_writer operator<<(bytes_writer w, const digest<size>& s) {
        return w << s.Value;
    }

    template <size_t size> 
    inline bytes_reader operator>>(bytes_reader r, digest<size>& s) {
        return r >> s.Value;
    }

    template <size_t size> 
    inline Bitcoin::writer operator<<(Bitcoin::writer w, const digest<size>& s) {
        return Bitcoin::writer{w.Writer << s};
    }

    template <size_t size>
    inline Bitcoin::reader operator>>(Bitcoin::reader r, digest<size>& s) {
        return Bitcoin::reader{r.Reader >> s};
    }
    
}

namespace data::encoding::hexidecimal { 
    
    template <size_t size, unsigned int bits> 
    inline std::string write(const Gigamonkey::uint<size, bits>& n) {
        return write((math::number::gmp::N)(n));
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
        bytes read = bytes_view(encoding::hex::view{hex.substr(2)});
        std::reverse_copy(read.begin(), read.end(), begin());
    }
    
    template <size_t size, unsigned int bits>
    uint<size, bits>::uint(const N& n) : uint(0) {
        data::math::number::N_bytes<data::endian::little> b{n};
        if (b.size() > size) std::copy(b.begin(), b.begin() + size, begin());
        else std::copy(b.begin(), b.end(), begin());
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>::operator bytes_view() const {
        return bytes_view{data(), size};
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>::operator slice<size>() {
        return slice<size>(data());
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>::operator const slice<size>() const {
        return slice<size>(const_cast<byte*>(data()));
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>::operator double() const {
        return double(operator N());
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator=(uint64_t b) {
        sv::base_uint<bits>::operator=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator=(const sv::base_uint<bits>& b) {
        sv::base_uint<bits>::operator=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator^=(const uint& b) {
        sv::base_uint<bits>::operator^=(b);
        return *this;
    }

    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator&=(const uint& b) {
        sv::base_uint<bits>::operator&=(b);
        return *this;
    }

    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator|=(const uint& b) {
        sv::base_uint<bits>::operator|=(b);
        return *this;
    }

    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator^=(uint64 b) {
        sv::base_uint<bits>::operator^=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator|=(uint64 b) {
        sv::base_uint<bits>::operator|=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator<<=(unsigned int shift) {
        sv::base_uint<bits>::operator<<=(shift);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator>>=(unsigned int shift) {
        sv::base_uint<bits>::operator>>=(shift);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits> uint<size, bits>::operator<<(unsigned int shift) {
        return uint<size, bits>(*this) <<= shift;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits> uint<size, bits>::operator>>(unsigned int shift) {
        return uint<size, bits>(*this) >>= shift;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator+=(const uint& b) {
        sv::base_uint<bits>::operator+=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator-=(const uint& b) {
        sv::base_uint<bits>::operator-=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator+=(uint64 b) {
        sv::base_uint<bits>::operator+=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator-=(uint64 b) {
        sv::base_uint<bits>::operator-=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator*=(uint32 b) {
        sv::base_uint<bits>::operator*=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator*=(const uint& b) {
        sv::base_uint<bits>::operator*=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator/=(const uint& b) {
        sv::base_uint<bits>::operator/=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator++() {
        sv::base_uint<bits>::operator++();
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline const uint<size, bits> uint<size, bits>::operator++(int) {
        // postfix operator
        const uint ret = *this;
        ++(*this);
        return ret;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator--() {
        sv::base_uint<bits>::operator--();
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline const uint<size, bits> uint<size, bits>::operator--(int) {
        // postfix operator
        const uint ret = *this;
        --(*this);
        return ret;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits> uint<size, bits>::operator*(const uint& ret) {
        return sv::base_uint<bits>::operator*(ret);
    }
    
    template <size_t size, unsigned int bits>
    inline byte* uint<size, bits>::begin() {
        return (byte*)sv::base_uint<bits>::pn;
    }
    
    template <size_t size, unsigned int bits>
    inline byte* uint<size, bits>::end() {
        return begin() + size;
    }
    
    template <size_t size, unsigned int bits>
    inline const byte* uint<size, bits>::begin() const {
        return (byte*)this->pn;
    }
    
    template <size_t size, unsigned int bits>
    inline const byte* uint<size, bits>::end() const {
        return begin() + size;
    }
    
    template <size_t size, unsigned int bits>
    inline byte* uint<size, bits>::data() {  
        return begin();
    }
    
    template <size_t size, unsigned int bits>
    inline const byte* uint<size, bits>::data() const {
        return begin();
    }

}

#endif
