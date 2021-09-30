// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_HASH
#define GIGAMONKEY_HASH

#include "types.hpp"
#include <data/data.hpp>
#include <data/encoding/integer.hpp>
#include <data/encoding/endian/words.hpp>
#include <data/math/number/bytes/N.hpp>

#include <sv/arith_uint256.h>

template <unsigned int BITS>
base_uint<BITS> &base_uint<BITS>::operator<<=(unsigned int shift) {
    base_uint<BITS> a(*this);
    for (int i = 0; i < WIDTH; i++)
        pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < WIDTH; i++) {
        if (i + k + 1 < WIDTH && shift != 0)
            pn[i + k + 1] |= (a.pn[i] >> (32 - shift));
        if (i + k < WIDTH) pn[i + k] |= (a.pn[i] << shift);
    }
    return *this;
}

template <unsigned int BITS>
base_uint<BITS> &base_uint<BITS>::operator>>=(unsigned int shift) {
    base_uint<BITS> a(*this);
    for (int i = 0; i < WIDTH; i++)
        pn[i] = 0;
    int k = shift / 32;
    shift = shift % 32;
    for (int i = 0; i < WIDTH; i++) {
        if (i - k - 1 >= 0 && shift != 0)
            pn[i - k - 1] |= (a.pn[i] << (32 - shift));
        if (i - k >= 0) pn[i - k] |= (a.pn[i] >> shift);
    }
    return *this;
}

template <unsigned int BITS>
base_uint<BITS> &base_uint<BITS>::operator*=(uint32_t b32) {
    uint64_t carry = 0;
    for (int i = 0; i < WIDTH; i++) {
        uint64_t n = carry + (uint64_t)b32 * pn[i];
        pn[i] = n & 0xffffffff;
        carry = n >> 32;
    }
    return *this;
}

template <unsigned int BITS>
base_uint<BITS> &base_uint<BITS>::operator*=(const base_uint &b) {
    base_uint<BITS> a = *this;
    *this = 0;
    for (int j = 0; j < WIDTH; j++) {
        uint64_t carry = 0;
        for (int i = 0; i + j < WIDTH; i++) {
            uint64_t n = carry + pn[i + j] + (uint64_t)a.pn[j] * b.pn[i];
            pn[i + j] = n & 0xffffffff;
            carry = n >> 32;
        }
    }
    return *this;
}

template <unsigned int BITS>
base_uint<BITS> &base_uint<BITS>::operator/=(const base_uint &b) {
    // make a copy, so we can shift.
    base_uint<BITS> div = b;
    // make a copy, so we can subtract.
    base_uint<BITS> num = *this;
    // the quotient.
    *this = 0;
    int num_bits = num.bits();
    int div_bits = div.bits();
    if (div_bits == 0) throw uint_error("Division by zero");
    // the result is certainly 0.
    if (div_bits > num_bits) return *this;
    int shift = num_bits - div_bits;
    // shift so that div and num align.
    div <<= shift;
    while (shift >= 0) {
        if (num >= div) {
            num -= div;
            // set a bit of the result.
            pn[shift / 32] |= (1 << (shift & 31));
        }
        // shift back.
        div >>= 1;
        shift--;
    }
    // num now contains the remainder of the division.
    return *this;
}

template <unsigned int BITS>
int base_uint<BITS>::CompareTo(const base_uint<BITS> &b) const {
    for (int i = WIDTH - 1; i >= 0; i--) {
        if (pn[i] < b.pn[i]) return -1;
        if (pn[i] > b.pn[i]) return 1;
    }
    return 0;
}

template <unsigned int BITS> bool base_uint<BITS>::EqualTo(uint64_t b) const {
    for (int i = WIDTH - 1; i >= 2; i--) {
        if (pn[i]) return false;
    }
    if (pn[1] != (b >> 32)) return false;
    if (pn[0] != (b & 0xfffffffful)) return false;
    return true;
}

template <unsigned int BITS> double base_uint<BITS>::getdouble() const {
    double ret = 0.0;
    double fact = 1.0;
    for (int i = 0; i < WIDTH; i++) {
        ret += fact * pn[i];
        fact *= 4294967296.0;
    }
    return ret;
}

template <unsigned int BITS> unsigned int base_uint<BITS>::bits() const {
    for (int pos = WIDTH - 1; pos >= 0; pos--) {
        if (pn[pos]) {
            for (int bits = 31; bits > 0; bits--) {
                if (pn[pos] & 1 << bits) return 32 * pos + bits + 1;
            }
            return 32 * pos + 1;
        }
    }
    return 0;
}

// Explicit instantiations for base_uint<256>
template base_uint<256> &base_uint<256>::operator<<=(unsigned int);
template base_uint<256> &base_uint<256>::operator>>=(unsigned int);
template base_uint<256> &base_uint<256>::operator*=(uint32_t b32);
template base_uint<256> &base_uint<256>::operator*=(const base_uint<256> &b);
template base_uint<256> &base_uint<256>::operator/=(const base_uint<256> &b);
template int base_uint<256>::CompareTo(const base_uint<256> &) const;
template bool base_uint<256>::EqualTo(uint64_t) const;
template double base_uint<256>::getdouble() const;
template unsigned int base_uint<256>::bits() const;

namespace Gigamonkey {
    
    // a representation of uints of any size. 
    template <size_t size, unsigned int bits = 8 * size> struct uint : public base_uint<bits> {
        uint(uint64 u) : base_uint<bits>(u) {}
        uint() : uint(0) {}
        
        uint(const slice<size>);
        
        // valid inputs are a hexidecimal number, which will be written 
        // to the digest in little endian (in other words, reversed
        // from the way it is written) or a hex string, which will be
        // written to the digest as given, without reversing. 
        explicit uint(string_view hex);
        
        explicit uint(const base_uint<bits>& b) : base_uint<bits>{b} {}
        explicit uint(const N& n);
        
        explicit uint(const ::uint256&);
        explicit uint(const arith_uint256&);
        
        explicit operator N() const;
        explicit operator double() const;
        
        operator bytes_view() const;
        operator slice<size>();
        operator const slice<size>() const;
        
        uint& operator=(uint64_t b);
        uint& operator=(const base_uint<bits>& b);
        
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
        
        explicit operator string() const;
        
        arithmetic::digits<endian::little> digits() const {
            return {data::slice<byte>(const_cast<byte*>(data()), size)};
        }
        
        arithmetic::digits<endian::big> reverse_digits() const {
            return {data::slice<byte>(const_cast<byte*>(data()), size)};
        }
        
    };
    
    // sizes of standard hash functions. 
    using uint160 = uint<20>;
    using uint256 = uint<32>;
    using uint512 = uint<64>;

    // a hash digest. 
    template <size_t size> struct digest : nonzero<uint<size>> {
        
        digest() : nonzero<uint<size>>{} {}
        
        explicit digest(const uint<size>& u) : nonzero<uint<size>>{u} {}
        explicit digest(string_view s);
        explicit digest(const slice<size>& x) : digest{uint<size>(x)} {}
        
        operator bytes_view() const;
        
        explicit operator N() const;
        
        byte* begin();
        byte* end();
        
        const byte* begin() const;
        const byte* end() const;
        
        bool operator==(const digest& d) const;
        bool operator!=(const digest& d) const;
        
        bool operator>(const digest& d) const;
        bool operator<(const digest& d) const;
        bool operator<=(const digest& d) const;
        bool operator>=(const digest& d) const;
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
    inline uint<size, bits>::operator string() const {
        bytes r(32);
        std::copy(begin(), end(), r.rbegin());
        return string{"0x"} + data::encoding::hex::write(r, data::encoding::hex::lower);
    }

    template <size_t size, unsigned int bits> 
    inline std::ostream& operator<<(std::ostream& o, const uint<size, bits>& s) {
        return o << string(s);
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
        ptr<bytes> read = encoding::hex::read(hex.substr(2));
        std::reverse_copy(read->begin(), read->end(), begin());
    }
    
    template <size_t size, unsigned int bits>
    uint<size, bits>::uint(const N& n) : uint(0) {
        ptr<bytes> b = encoding::hex::read(encoding::hexidecimal::write(n).substr(2));
        std::reverse(b->begin(), b->end());
        if (b->size() > size) std::copy(b->begin(), b->begin() + size, begin());
        else std::copy(b->begin(), b->end(), begin());
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
        base_uint<bits>::operator=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator=(const base_uint<bits>& b) {
        base_uint<bits>::operator=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator^=(const uint& b) {
        base_uint<bits>::operator^=(b);
        return *this;
    }

    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator&=(const uint& b) {
        base_uint<bits>::operator&=(b);
        return *this;
    }

    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator|=(const uint& b) {
        base_uint<bits>::operator|=(b);
        return *this;
    }

    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator^=(uint64 b) {
        base_uint<bits>::operator^=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator|=(uint64 b) {
        base_uint<bits>::operator|=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator<<=(unsigned int shift) {
        base_uint<bits>::operator<<=(shift);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator>>=(unsigned int shift) {
        base_uint<bits>::operator>>=(shift);
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
        base_uint<bits>::operator+=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator-=(const uint& b) {
        base_uint<bits>::operator-=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator+=(uint64 b) {
        base_uint<bits>::operator+=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator-=(uint64 b) {
        base_uint<bits>::operator-=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator*=(uint32 b) {
        base_uint<bits>::operator*=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator*=(const uint& b) {
        base_uint<bits>::operator*=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator/=(const uint& b) {
        base_uint<bits>::operator/=(b);
        return *this;
    }
    
    template <size_t size, unsigned int bits>
    inline uint<size, bits>& uint<size, bits>::operator++() {
        base_uint<bits>::operator++();
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
        base_uint<bits>::operator--();
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
        return base_uint<bits>::operator*(ret);
    }
    
    template <size_t size, unsigned int bits>
    inline byte* uint<size, bits>::begin() {
        return (byte*)base_uint<bits>::pn;
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
    
    template <size_t size>
    digest<size>::digest(string_view s) {
        ptr<bytes> b = data::encoding::hex::read(s);
        if (b != nullptr) {
            std::copy(b->begin(), b->end(), begin());
        } else *this = digest{uint<size>{s}};
    }
    
    template <size_t size>
    inline digest<size>::operator bytes_view() const {
        return bytes_view(nonzero<uint<size>>::Value);
    }
    
    template <size_t size>
    byte inline *digest<size>::begin() {
        return nonzero<uint<size>>::Value.begin();
    }
    
    template <size_t size>
    byte inline *digest<size>::end() {
        return nonzero<uint<size>>::Value.end();
    }
    
    template <size_t size>
    const byte inline *digest<size>::begin() const {
        return nonzero<uint<size>>::Value.begin();
    }
    
    template <size_t size>
    const byte inline *digest<size>::end() const {
        return nonzero<uint<size>>::Value.end();
    }
    
    template <size_t size>
    bool inline digest<size>::operator==(const digest& d) const {
        return nonzero<uint<size>>::Value == d.Value;
    }
    
    template <size_t size>
    bool inline digest<size>::operator!=(const digest& d) const {
        return nonzero<uint<size>>::Value != d.Value;
    }
    
    template <size_t size>
    bool inline digest<size>::operator>(const digest& d) const {
        return nonzero<uint<size>>::Value > d.Value;
    }
    
    template <size_t size>
    bool inline digest<size>::operator<(const digest& d) const {
        return nonzero<uint<size>>::Value < d.Value;
    }
    
    template <size_t size>
    bool inline digest<size>::operator<=(const digest& d) const {
        return nonzero<uint<size>>::Value <= d.Value;
    }
    
    template <size_t size>
    bool inline digest<size>::operator>=(const digest& d) const {
        return nonzero<uint<size>>::Value >= d.Value;
    }

}

#endif
