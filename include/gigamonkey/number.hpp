// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_NUMBER
#define GIGAMONKEY_NUMBER

#include <gigamonkey/p2p/var_int.hpp>

#include <sv/arith_uint256.h>

#include <data/encoding/integer.hpp>
#include <data/encoding/endian/words.hpp>
#include <data/encoding/halves.hpp>

#include <data/math/number/bytes/N.hpp>
#include <data/math/number/rational.hpp>
#include <data/math/octonian.hpp>
#include <data/math/number/integer.hpp>

#include <gigamonkey/types.hpp>

namespace Gigamonkey {
    
    template <size_t size> struct uint;
    
    // sizes of standard hash functions.
    using uint128 = uint<16>; 
    using uint160 = uint<20>;
    using uint224 = uint<28>;
    using uint256 = uint<32>;
    using uint320 = uint<40>;
    using uint384 = uint<48>;
    using uint448 = uint<56>;
    using uint512 = uint<64>;
    
    template <endian::order> struct natural;
    template <endian::order> struct integer;
    
    template <endian::order r> bool operator==(const integer<r>&, const integer<r>&);
    template <endian::order r> bool operator!=(const integer<r>&, const integer<r>&);
    template <endian::order r> bool operator<=(const integer<r>&, const integer<r>&);
    template <endian::order r> bool operator>=(const integer<r>&, const integer<r>&);
    template <endian::order r> bool operator<(const integer<r>&, const integer<r>&);
    template <endian::order r> bool operator>(const integer<r>&, const integer<r>&);
    
    template <endian::order r> bool operator==(const natural<r>&, const natural<r>&);
    template <endian::order r> bool operator!=(const natural<r>&, const natural<r>&);
    template <endian::order r> bool operator<=(const natural<r>&, const natural<r>&);
    template <endian::order r> bool operator>=(const natural<r>&, const natural<r>&);
    template <endian::order r> bool operator<(const natural<r>&, const natural<r>&);
    template <endian::order r> bool operator>(const natural<r>&, const natural<r>&);
    
    template <endian::order r> bool operator==(const natural<r>&, int);
    template <endian::order r> bool operator!=(const natural<r>&, int);
    template <endian::order r> bool operator<=(const natural<r>&, int);
    template <endian::order r> bool operator>=(const natural<r>&, int);
    template <endian::order r> bool operator<(const natural<r>&, int);
    template <endian::order r> bool operator>(const natural<r>&, int);
    
    template <endian::order r> bool operator==(int, const natural<r>&);
    template <endian::order r> bool operator!=(int, const natural<r>&);
    template <endian::order r> bool operator<=(int, const natural<r>&);
    template <endian::order r> bool operator>=(int, const natural<r>&);
    template <endian::order r> bool operator<(int, const natural<r>&);
    template <endian::order r> bool operator>(int, const natural<r>&);
}

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
    for (int pos = WIDTH - 1; pos >= 0; pos--) if (pn[pos]) {
        for (int bits = 31; bits > 0; bits--) if (pn[pos] & 1 << bits) return 32 * pos + bits + 1;
        return 32 * pos + 1;
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
    template <size_t size> struct uint : public base_uint<8 * size> {
        static const unsigned int bits = 8 * size;
        uint(base_uint<bits> &&b) : base_uint<bits>{b} {}
        uint(const base_uint<bits> &b) : base_uint<bits>{b} {}
        uint(uint64 u) : base_uint<bits>(u) {}
        uint() : uint(0) {}
        
        uint(const slice<size>);
        
        // valid inputs are a hexidecimal number, which will be written 
        // to the digest in little endian (in other words, reversed
        // from the way it is written) or a hex string, which will be
        // written to the digest as given, without reversing. 
        explicit uint(string_view hex);
        
        explicit uint(const data::math::number::N& n);
        
        explicit uint(const ::uint256&);
        explicit uint(const arith_uint256&);
        
        explicit operator data::math::number::N() const;
        explicit operator double() const;
        
        operator bytes_view() const;
        operator slice<size>();
        operator const slice<size>() const;
        
        uint& operator=(uint64_t b);
        uint& operator=(const base_uint<bits>& b);
        
        uint operator~();
        uint operator^(const uint &);
        uint operator|(const uint &);
        uint operator&(const uint &);
        
        uint operator+(const uint &);
        uint operator-(const uint &);
        uint operator*(const uint &);
        
        uint& operator^=(const uint &);
        uint& operator&=(const uint &);
        uint& operator|=(const uint &);
        
        uint operator<<(unsigned int shift) const;
        uint operator>>(unsigned int shift) const;
        
        uint& operator<<=(unsigned int shift);
        uint& operator>>=(unsigned int shift);
        
        uint& operator+=(const uint &);
        uint& operator-=(const uint &);
        uint& operator*=(const uint &);
        
        math::division<uint<size>> divide(const uint &) const;
        
        uint operator/(const uint &) const;
        uint operator%(const uint &) const;
        
        uint& operator/=(const uint &);
        uint& operator%=(const uint &);
        
        uint& operator++();
        const uint operator++(int);
        
        uint& operator--();
        const uint operator--(int);
        
        byte* begin();
        byte* end();
        
        const byte* begin() const;
        const byte* end() const;
        
        byte* data();
        const byte* data() const;
        
        explicit operator string() const;
        
        const byte& operator[](int i) const {
            if (i < 0) return operator[](size + i);
            return data()[i];
        }
        
        byte& operator[](int i) {
            if (i < 0) return operator[](size + i);
            return data()[i];
        }
        
        size_t serialized_size() const;
        
    };
    
    template <size_t size> writer &operator<<(writer &, const uint<size> &);
    template <size_t size> reader &operator>>(reader &, uint<size> &);
    
    template <endian::order r> struct integer : bytes {
        
        static bool minimal(const bytes_view b);
        
        static bool is_zero(const bytes_view b);
        static bool is_positive_zero(const bytes_view b);
        static bool is_negative_zero(const bytes_view b);
        
        static bool sign_bit(bytes_view b);
        
        static data::math::sign sign(bytes_view b);
        
        static bool is_positive(bytes_view b);
        static bool is_negative(bytes_view b);
        
        bool minimal() const;
        
        bool is_zero() const;
        bool is_positive_zero() const;
        bool is_negative_zero() const;
        
        bool sign_bit() const;
        
        data::math::sign sign() const;
        
        bool is_positive() const;
        bool is_negative() const;
        
        // shorted to be minimally encoded. 
        static bytes trim(bytes_view b);
        
        integer trim() const;
        
        static bool equal(bytes_view a, bytes_view b);
        static bool unequal(bytes_view a, bytes_view b);
        
        static bool greater(bytes_view a, bytes_view b);
        static bool less(bytes_view a, bytes_view b);
        static bool greater_equal(bytes_view a, bytes_view b);
        static bool less_equal(bytes_view a, bytes_view b);
        
        static bytes abs(bytes_view b);
        
        natural<r> abs() const;
        
        static bytes negate(bytes_view b);
        
        static bytes plus(bytes_view a, bytes_view b);
        static bytes minus(bytes_view a, bytes_view b);
        static bytes times(bytes_view a, bytes_view b);
        
        integer operator-() const;
        
        integer operator+(const integer&) const;
        integer operator-(const integer&) const;
        integer operator*(const integer&) const;
        
        integer &operator+=(const integer&);
        integer &operator-=(const integer&);
        integer &operator*=(const integer&);
        
        static bytes shift(bytes_view a, int);
        
        integer operator<<(int) const;
        integer operator>>(int) const;
        
        integer &operator<<=(int);
        integer &operator>>=(int);
        
        math::division<integer> divide(const integer&) const;
        
        integer operator/(const integer&) const;
        integer operator%(const integer&) const;
        
        integer() : bytes{} {}
        integer(int64 z);
        template <size_t size> integer(const uint<size> &);
        explicit integer(bytes_view b) : bytes{b} {}
        explicit integer(string_view x);
        explicit integer(const integer<endian::opposite(r)>&);
        
        data::arithmetic::digits<r> digits() {
            return data::arithmetic::digits<r>{data::slice<byte>(*this)};
        }
        
    protected:
        explicit integer(bytes&& b) : bytes{b} {}
    };
    
    template <endian::order r> 
    struct natural : public integer<r> {
        
        natural() : integer<r>{} {}
        
        natural operator+(const natural&) const;
        natural operator-(const natural&) const;
        natural operator*(const natural&) const;
        
        natural &operator+=(const natural&);
        natural &operator-=(const natural&);
        natural &operator*=(const natural&);
        
        math::division<natural> divide(const natural&) const;
        
        natural operator/(const natural&) const;
        natural operator%(const natural&) const;
        
        natural operator<<(int) const;
        natural operator>>(int) const;
        
        natural &operator<<=(int);
        natural &operator>>=(int);
        
        natural(uint64 z);
        explicit natural(string_view x);
        explicit natural(const natural<endian::opposite(r)>&);
        template <size_t size> explicit natural(const uint<size> &);
        
        template <size_t size> operator uint<size>() const;
        
        bool valid() const {
            return !integer<r>::is_negative(*this);
        }
        
    private:
        explicit natural(bytes&& b) : integer<r>{b} {}
        friend struct integer<r>;
    };
    
}

namespace Gigamonkey::Bitcoin {
    
    using N = natural<endian::little>;
    using Z = integer<endian::little>;
    
    using Q = data::math::fraction<Z, N>;
    
    // Gaussian numbers (complex rationals)
    using G = data::math::complex<Q>;
        
    // rational quaternions
    using H = data::math::quaternion<Q>;
        
    // rational octonions
    using O = data::math::octonion<Q>;
    
}

namespace Gigamonkey {
    
    template <size_t size> 
    inline uint<size>::operator string() const {
        bytes r(32);
        std::copy(begin(), end(), r.rbegin());
        return string{"0x"} + data::encoding::hex::write(r, data::encoding::hex::lower);
    }

    template <size_t size> 
    std::ostream inline &operator<<(std::ostream& o, const uint<size>& s) {
        return o << string(s);
    }
    
}

namespace data::encoding::hexidecimal { 
    
    template <size_t size> 
    inline std::string write(const Gigamonkey::uint<size>& n) {
        return write((math::number::N)(n));
    }
    
    template <size_t size> 
    inline std::ostream& write(std::ostream& o, const Gigamonkey::uint<size>& n) {
        return o << write(n);
    }
    
}

namespace data::encoding::integer {
    
    template <size_t size, unsigned int bits> 
    inline std::string write(const Gigamonkey::uint<size>& n) {
        return write((math::number::N)(n));
    }
    
    template <size_t size, unsigned int bits> 
    inline std::ostream& write(std::ostream& o, const Gigamonkey::uint<size>& n) {
        return o << write(n);
    }
    
}

namespace Gigamonkey {

    template <size_t size>
    inline uint<size>::uint(const slice<size> x) {
        std::copy(x.begin(), x.end(), begin());
    }
    
    template <size_t size>
    uint<size>::operator math::number::N() const {
        math::number::N n(0);
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
    
    template <size_t size>
    inline uint<size>::uint(string_view hex) : uint(0) {
        if (hex.size() != size * 2 + 2) return;
        if (!data::encoding::hexidecimal::valid(hex)) return;
        ptr<bytes> read = encoding::hex::read(hex.substr(2));
        std::reverse_copy(read->begin(), read->end(), begin());
    }
    
    template <size_t size>
    uint<size>::uint(const math::number::N& n) : uint(0) {
        ptr<bytes> b = encoding::hex::read(encoding::hexidecimal::write(n).substr(2));
        std::reverse(b->begin(), b->end());
        if (b->size() > size) std::copy(b->begin(), b->begin() + size, begin());
        else std::copy(b->begin(), b->end(), begin());
    }
    
    template <size_t size>
    inline uint<size>::operator bytes_view() const {
        return bytes_view{data(), size};
    }
    
    template <size_t size>
    inline uint<size>::operator slice<size>() {
        return slice<size>(data());
    }
    
    template <size_t size>
    inline uint<size>::operator const slice<size>() const {
        return slice<size>(const_cast<byte*>(data()));
    }
    
    template <size_t size>
    inline uint<size>::operator double() const {
        return double(operator math::number::N());
    }
    
    template <size_t size>
    inline uint<size>& uint<size>::operator=(uint64_t b) {
        base_uint<bits>::operator=(b);
        return *this;
    }
    
    template <size_t size>
    inline uint<size>& uint<size>::operator=(const base_uint<bits>& b) {
        base_uint<bits>::operator=(b);
        return *this;
    }
    
    template <size_t size>
    inline uint<size>& uint<size>::operator^=(const uint& b) {
        base_uint<bits>::operator^=(b);
        return *this;
    }

    template <size_t size>
    inline uint<size>& uint<size>::operator&=(const uint& b) {
        base_uint<bits>::operator&=(b);
        return *this;
    }

    template <size_t size>
    inline uint<size>& uint<size>::operator|=(const uint& b) {
        base_uint<bits>::operator|=(b);
        return *this;
    }
    
    template <size_t size>
    inline uint<size>& uint<size>::operator<<=(unsigned int shift) {
        base_uint<bits>::operator<<=(shift);
        return *this;
    }
    
    template <size_t size>
    inline uint<size>& uint<size>::operator>>=(unsigned int shift) {
        base_uint<bits>::operator>>=(shift);
        return *this;
    }
    
    template <size_t size>
    inline uint<size> uint<size>::operator<<(unsigned int shift) const {
        return uint<size>(*this) <<= shift;
    }
    
    template <size_t size>
    inline uint<size> uint<size>::operator>>(unsigned int shift) const {
        return uint<size>(*this) >>= shift;
    }
    
    template <size_t size>
    inline uint<size>& uint<size>::operator+=(const uint& b) {
        base_uint<bits>::operator+=(b);
        return *this;
    }
    
    template <size_t size>
    inline uint<size>& uint<size>::operator-=(const uint& b) {
        base_uint<bits>::operator-=(b);
        return *this;
    }
    
    template <size_t size>
    inline uint<size>& uint<size>::operator*=(const uint& b) {
        base_uint<bits>::operator*=(b);
        return *this;
    }
    
    template <size_t size>
    inline uint<size>& uint<size>::operator++() {
        base_uint<bits>::operator++();
        return *this;
    }
    
    template <size_t size>
    inline const uint<size> uint<size>::operator++(int) {
        // postfix operator
        const uint ret = *this;
        ++(*this);
        return ret;
    }
    
    template <size_t size>
    inline uint<size>& uint<size>::operator--() {
        base_uint<bits>::operator--();
        return *this;
    }
    
    template <size_t size>
    inline const uint<size> uint<size>::operator--(int) {
        // postfix operator
        const uint ret = *this;
        --(*this);
        return ret;
    }
    
    template <size_t size> uint<size> inline uint<size>::operator~() {
        return ~base_uint<bits>(*this);
    }
    
    template <size_t size> uint<size> inline uint<size>::operator^(const uint<size> &b) {
        return base_uint<bits>(*this) ^= b;
    }
    
    template <size_t size> uint<size> inline uint<size>::operator&(const uint<size> &b) {
        return base_uint<bits>(*this) &= b;
    }
    
    template <size_t size> uint<size> inline uint<size>::operator|(const uint<size> &b) {
        return base_uint<bits>(*this) |= b;
    }
    
    template <size_t size> uint<size> inline uint<size>::operator+(const uint<size> &b) {
        return base_uint<bits>(*this) += b;
    }
    
    template <size_t size> uint<size> inline uint<size>::operator-(const uint<size> &b) {
        return base_uint<bits>(*this) -= b;
    }
    
    template <size_t size> uint<size> inline uint<size>::operator*(const uint &b) {
        return base_uint<bits>(*this) *= b;
    }
    
    template <size_t size> math::division<uint<size>>  inline uint<size>::divide(const uint &u) const {
        return math::number::natural::divide(*this, u);
    }
        
    template <size_t size> uint<size> inline uint<size>::operator/(const uint &u) const {
        return divide(u).Quotient;
    }
    
    template <size_t size> uint<size> inline uint<size>::operator%(const uint &u) const {
        return divide(u).Remainder;
    }
        
    template <size_t size> uint<size> inline &uint<size>::operator/=(const uint &u) {
        return *this = *this / u;
    }
    
    template <size_t size> uint<size> inline &uint<size>::operator%=(const uint &u) {
        return *this = *this % u;
    }
    
    template <size_t size>
    inline byte* uint<size>::begin() {
        return (byte*)base_uint<bits>::pn;
    }
    
    template <size_t size>
    inline byte* uint<size>::end() {
        return begin() + size;
    }
    
    template <size_t size>
    inline const byte* uint<size>::begin() const {
        return (byte*)this->pn;
    }
    
    template <size_t size>
    inline const byte* uint<size>::end() const {
        return begin() + size;
    }
    
    template <size_t size>
    inline byte* uint<size>::data() {  
        return begin();
    }
    
    template <size_t size>
    inline const byte* uint<size>::data() const {
        return begin();
    }
    
    template <size_t size> size_t uint<size>::serialized_size() const {
        size_t last_0 = 0;
        for (size_t i = 0; i < size; i++) if ((*this)[i] != 0x00) last_0 = i + 1;
        return last_0 == 0 ? 1 : (*this)[last_0 - 1] & 0x80 ? last_0 + 2 : last_0 + 1;
    }
    
    template <size_t size> writer inline &operator<<(writer &w, const uint<size> &u) {
        return w << byte(0x02) << Bitcoin::var_string{natural<endian::big>(u)};
    }
    
    template <size_t size> reader &operator>>(reader &re, uint<size> &u) {
        byte b;
        re >> b;
        if (b != 0x02) throw std::logic_error{"invalid uint format"};
        natural<endian::big> n;
        re >> n;
        u = uint<size>(n);
        return re;
    }
    
    template <endian::order r> bool inline integer<r>::equal(bytes_view a, bytes_view b) {
        return trim(a) == trim(b);
    }
    
    template <endian::order r> bool inline integer<r>::unequal(bytes_view a, bytes_view b) {
        return trim(a) != trim(b);
    }
    
    template <endian::order r> data::math::sign inline integer<r>::sign(bytes_view b) {
        return is_zero(b) ? data::math::zero : sign_bit(b) ? data::math::negative : data::math::positive;
    }
    
    template <endian::order r> bool inline integer<r>::is_positive(bytes_view b) {
        return sign(b) == data::math::positive;
    }
    
    template <endian::order r> bool inline integer<r>::is_negative(bytes_view b) {
        return sign(b) == data::math::negative;
    }
    
    template <endian::order r> bool inline operator==(const integer<r> &a, const integer<r> &b) {
        return integer<r>::equal(a, b);
    }
    
    template <endian::order r> bool inline operator!=(const integer<r> &a, const integer<r> &b) {
        return integer<r>::unequal(a, b);
    }
    
    template <endian::order r> bool inline operator<=(const integer<r> &a, const integer<r> &b) {
        return integer<r>::less_equal(a, b);
    }
    
    template <endian::order r> bool inline operator>=(const integer<r> &a, const integer<r> &b) {
        return integer<r>::greater_equal(a, b);
    }
    
    template <endian::order r> bool inline operator<(const integer<r> &a, const integer<r> &b) {
        return integer<r>::less(a, b);
    }
    
    template <endian::order r> bool inline operator>(const integer<r> &a, const integer<r> &b) {
        return integer<r>::greater(a, b);
    }
    
    template <endian::order r> bool inline operator==(const natural<r> &a, const natural<r> &b) {
        return integer<r>::equal(a, b);
    }
    
    template <endian::order r> bool inline operator!=(const natural<r> &a, const natural<r> &b) {
        return integer<r>::unequal(a, b);
    }
    
    template <endian::order r> bool inline operator<=(const natural<r> &a, const natural<r> &b) {
        return integer<r>::less_equal(a, b);
    }
    
    template <endian::order r> bool inline operator>=(const natural<r> &a, const natural<r> &b) {
        return integer<r>::greater_equal(a, b);
    }
    
    template <endian::order r> bool inline operator<(const natural<r> &a, const natural<r> &b) {
        return integer<r>::less(a, b);
    }
    
    template <endian::order r> bool inline operator>(const natural<r> &a, const natural<r> &b) {
        return integer<r>::greater(a, b);
    }
    
    template <endian::order r> integer<r> inline integer<r>::operator-() const {
        return integer(negate(*this));
    }
    
    template <endian::order r> integer<r> inline integer<r>::operator+(const integer &z) const {
        return integer(plus(*this, z));
    }
    
    template <endian::order r> integer<r> inline integer<r>::operator-(const integer &z) const {
        return integer(plus(*this, -z));
    }
    
    template <endian::order r> integer<r> inline integer<r>::operator*(const integer &z) const {
        return integer(times(*this, z));
    }
        
    template <endian::order r> natural<r> inline natural<r>::operator+(const natural &n) const {
        return natural{integer<r>::plus(*this, n)};
    }
    
    template <endian::order r> natural<r> inline natural<r>::operator-(const natural &n) const {
        if (n > *this) return natural{};
        return natural{integer<r>::minus(*this, n)};
    }
    
    template <endian::order r> natural<r> inline natural<r>::operator*(const natural &n) const {
        return natural{integer<r>::times(*this, n)};
    }
    
    template <endian::order r> integer<r> inline &integer<r>::operator+=(const integer &z) {
        return *this = *this + z;
    }
    
    template <endian::order r> integer<r> inline &integer<r>::operator-=(const integer &z) {
        return *this = *this - z;
    }
    
    template <endian::order r> integer<r> inline &integer<r>::operator*=(const integer &z) {
        return *this = *this * z;
    }
    
    template <endian::order r> natural<r> inline &natural<r>::operator+=(const natural &z) {
        return *this = *this + z;
    }
    
    template <endian::order r> natural<r> inline &natural<r>::operator-=(const natural &z) {
        return *this = *this - z;
    }
    
    template <endian::order r> natural<r> inline &natural<r>::operator*=(const natural &z) {
        return *this = *this * z;
    }
    
    template <endian::order r> bool inline integer<r>::minimal() const {
        return minimal(*this);
    }
    
    template <endian::order r> bool inline integer<r>::is_zero() const {
        return is_zero(*this);
    }
    
    template <endian::order r> bool inline integer<r>::is_positive_zero() const {
        return is_positive_zero(*this);
    }
    
    template <endian::order r> bool inline integer<r>::is_negative_zero() const {
        return is_negative_zero(*this);
    }
    
    template <endian::order r> bool inline integer<r>::sign_bit() const {
        return sign_bit(*this);
    }
    
    template <endian::order r> data::math::sign inline integer<r>::sign() const {
        return sign(*this);
    }
    
    template <endian::order r> bool inline integer<r>::is_positive() const {
        return is_positive(*this);
    }
    
    template <endian::order r> bool inline integer<r>::is_negative() const {
        return is_negative(*this);
    }
    
    template <endian::order r> integer<r> inline integer<r>::operator/(const integer &z) const {
        return divide(z).Quotient;
    }
    
    template <endian::order r> integer<r> inline integer<r>::operator%(const integer &z) const {
        return divide(z).Remainder;
    }
    
    template <endian::order r> natural<r> inline natural<r>::operator/(const natural &z) const {
        return divide(z).Quotient;
    }
    
    template <endian::order r> natural<r> inline natural<r>::operator%(const natural &z) const {
        return divide(z).Remainder;
    }
    
    template <endian::order r> math::division<integer<r>> inline integer<r>::divide(const integer &z) const {
        return math::number::integer::divide(*this, z);
    }
    
    template <endian::order r> math::division<natural<r>> inline natural<r>::divide(const natural &z) const {
        return math::number::natural::divide(*this, z);
    }
    
    template <endian::order r> integer<r> inline integer<r>::operator<<(int i) const {
        if (i == 0) return *this;
        return integer{shift(this->trim(), i)};
    }
    
    template <endian::order r> integer<r> inline integer<r>::operator>>(int i) const {
        if (i == 0) return *this;
        return integer{shift(this->trim(), -i)};
    }
    
    template <endian::order r> natural<r> inline natural<r>::operator<<(int i) const {
        if (i == 0) return *this;
        return natural{integer<r>::shift(this->trim(), i)};
    }
    
    template <endian::order r> natural<r> inline natural<r>::operator>>(int i) const {
        if (i == 0) return *this;
        return natural{integer<r>::shift(this->trim(), -i)};
    }
    
    template <endian::order r> integer<r> &integer<r>::operator<<=(int i) {
        return *this = *this << i;
    }
    
    template <endian::order r> integer<r> &integer<r>::operator>>=(int i) {
        return *this = *this >> i;
    }
    
    template <endian::order r> natural<r> &natural<r>::operator<<=(int i) {
        return *this = *this << i;
    }
    
    template <endian::order r> natural<r> &natural<r>::operator>>=(int i) {
        return *this = *this >> i;
    }
    
    template <endian::order r> inline integer<r>::integer(const integer<endian::opposite(r)>& x) {
        this->resize(x.size());
        std::copy(x.begin(), x.end(), this->rbegin());
    }
    
    template <endian::order r> inline natural<r>::natural(const natural<endian::opposite(r)>& x) {
        this->resize(x.size());
        std::copy(x.begin(), x.end(), this->rbegin());
    }
    
    template <endian::order r> bool inline operator==(int i, const natural<r> &n) {
        return n == i;
    }
    
    template <endian::order r> bool inline operator!=(int i, const natural<r> &n) {
        return n != i;
    }
    
    template <endian::order r> bool inline operator<=(int i, const natural<r> &n) {
        return n >= i;
    }
    
    template <endian::order r> bool inline operator>=(int i, const natural<r> &n) {
        return n <= i;
    }
    
    template <endian::order r> bool inline operator<(int i, const natural<r> &n) {
        return n < i;
    }
    
    template <endian::order r> bool inline operator>(int i, const natural<r> &n) {
        return n > i;
    }
    
    template <endian::order r> bool inline operator==(const natural<r> &n, int i) {
        return i < 0 ? false : n == static_cast<uint64>(i);
    }
    
    template <endian::order r> bool inline operator!=(const natural<r> &n, int i) {
        return i < 0 ? true : n != static_cast<uint64>(i);
    }
    
    template <endian::order r> bool inline operator<=(const natural<r> &n, int i) {
        return i < 0 ? false : n <= static_cast<uint64>(i);
    }
    
    template <endian::order r> bool inline operator>=(const natural<r> &n, int i) {
        return i < 0 ? true : n >= static_cast<uint64>(i);
    }
    
    template <endian::order r> bool inline operator<(const natural<r> &n, int i) {
        return i < 0 ? false : n < static_cast<uint64>(i);
    }
    
    template <endian::order r> bool inline operator>(const natural<r> &n, int i) {
        return i < 0 ? true : n > static_cast<uint64>(i);
    }
    
    struct numbers {
        
        template <endian::order r> using digits = data::arithmetic::digits<r>;
        
    private:
        template <endian::order r> friend struct integer;
        template <endian::order r> friend struct natural;
        
        template <endian::order r> static bool minimal(const digits<r> b) {
            size_t size = b.Data.size();
            if (size == 0) return true;
            byte last = b[-1];
            if (last == 0x00 || last == 0x80) {
                if (size == 1) return false;
                return b[-2] & 0x80;
            } 
            return true;
        }
        
        template <endian::order r> static bool is_zero(const digits<r> b) {
            size_t size = b.Data.size();
            if (size == 0) return true;
            for (int i = 0; i < size - 1; i++) {
                if (b[i] != 0x00) return false;
            }
            byte last = b[-1];
            return (last == 0x00 || last == 0x80);
        }
        
        template <endian::order r> static bool is_positive_zero(const digits<r> b) {
            size_t size = b.Data.size();
            if (size == 0) return true;
            for (int i = 0; i < size; i++) {
                if (b[i] != 0x00) return false;
            }
            return true;
        }
        
        template <endian::order r> static bool is_negative_zero(const digits<r> b) {
            size_t size = b.Data.size();
            if (size == 0) return false;
            for (int i = 0; i < size - 1; i++) {
                if (b[i] != 0x00) return false;
            }
            return b[-1] == 0x80;
        }
        
        template <endian::order r> static bool sign_bit(const digits<r> b) {
            size_t size = b.Data.size();
            if (size == 0) return false;
            return b[-1] & 0x80;
        }
        
        // this function is only called after checks for minimal and zero. 
        template <endian::order r> static bytes trim_nonminimal_nonzero(const digits<r> b) {
            // size will necessarily be greater than 1;
            size_t size = b.Data.size();
            // this will be either 0x00 or 0x80
            byte last = b[-1];
            // will be at least zero. 
            size_t last_nonzero = size - 2;
            // this will terminate. 
            while(b[last_nonzero] == 0x00) last_nonzero--;
            
            bool last_nonzero_sign_bit = b[last_nonzero] & 0x80;
            size_t new_size = last_nonzero + (last_nonzero_sign_bit ? 2 : 1);
            
            bytes new_number{};
            new_number.resize(new_size);
            std::copy(b.begin(), b.begin() + new_size, new_number.begin());
            
            digits<r> n{data::slice<byte>{new_number.data(), new_number.size()}};
            if (last_nonzero_sign_bit) n[last_nonzero + 1] = last;
            else n[last_nonzero] += last;
            return new_number;
        }
        
        template <endian::order r> static bytes abs_positive(const digits<r> b) {
            bytes new_number{b.Data};
            // size is necessarily greater than zero
            digits<r> n{data::slice<byte>{new_number.data(), new_number.size()}};
            n[-1] &= 0x7f;
            
            return integer<r>::trim(new_number);
        }
        
        template <endian::order r> static bytes negate(const digits<r> b) {
            if (is_zero(b)) return bytes{};
            
            bytes new_number{bytes_view{b.Data.data(), b.Data.size()}};
            digits<r> n{data::slice<byte>{new_number.data(), new_number.size()}};
            byte last = n[-1];
            if (last & 0x80) n[-1] &= 0x7f;
            else n[-1] += 0x80;
            return new_number;
        }
        
        template <endian::order r> static bytes from_int(int64 z) {
            if (z == 0) return bytes{};
            
            bool negative = z < 0;
            uint64_little lil = negative ? -z : z;
            
            int last_nonzero_digit = -1;
            for (int i = 0; i < lil.size(); i++) if (lil[i] != 0) last_nonzero_digit = i;
            
            bool last_digit_sign_bit = last_nonzero_digit >= 0 && lil[last_nonzero_digit] & 0x80;
            size_t new_size = last_nonzero_digit + (last_digit_sign_bit ? 2 : 1);
            
            bytes new_number(new_size);
            digits<r> n{data::slice<byte>{new_number.data(), new_number.size()}};
            
            std::copy(lil.begin(), lil.begin() + last_nonzero_digit + 1, n.begin());
            if (last_digit_sign_bit) n[last_nonzero_digit + 1] = negative ? 0x80 : 0x00;
            else if (negative) n[last_nonzero_digit] += 0x80;
            
            return new_number;
        }
        
        template <endian::order r> static bytes from_uint(uint64 z) {
            if (z == 0) return bytes{};
        
            uint64_little lil = z;
            
            int last_nonzero_digit = -1;
            for (int i = 0; i < lil.size(); i++) if (lil[i] != 0) last_nonzero_digit = i;
            
            bool last_digit_sign_bit = last_nonzero_digit >= 0 && lil[last_nonzero_digit] & 0x80;
            size_t new_size = last_nonzero_digit + (last_digit_sign_bit ? 2 : 1);
            
            bytes new_number(new_size);
            digits<r> n{data::slice<byte>{new_number.data(), new_number.size()}};
            
            std::copy(lil.begin(), lil.begin() + last_nonzero_digit + 1, n.begin());
            if (last_digit_sign_bit) n[last_nonzero_digit + 1] = 0x00;
            
            return new_number;
        }
        
        template <endian::order r> static bytes from_string(string_view x) {
                        
            auto hex = data::encoding::hex::read(x);
            if (hex != nullptr) {
                bytes b;
                b.resize(hex->size());
                std::copy(hex->begin(), hex->end(), b.begin());
                return b;
            } 
            
            auto hexidecimal = data::encoding::hexidecimal::read<r>(x);
            if (hexidecimal != nullptr) {
                bytes b;
                b.resize(hexidecimal->size());
                std::copy(hexidecimal->begin(), hexidecimal->end(), b.begin());
                return b;
            }
            
            if (x == "-0") return bytes({0x80});
            
            if (data::encoding::integer::valid(x)) {
                bool negative = data::encoding::integer::negative(x);
                ptr<data::math::Z_bytes<r>> positive_number; 
                positive_number = negative ? 
                    data::encoding::integer::read<r>(x.substr(1)) : 
                    data::encoding::integer::read<r>(x);
                
                bool has_sign_bit = sign_bit(positive_number->digits());
                
                bytes b;
                b.resize(positive_number->size() + (has_sign_bit ? 1 : 0));
                auto n = numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}};
                std::copy(positive_number->begin(), positive_number->end(), n.begin());
                if (has_sign_bit) *(n.begin() + positive_number->size()) = negative ? 0x80 : 0x00;
                else if (negative) *(n.begin() + positive_number->size() - 1) += 0x80;
                return b;
            }
            
            throw std::logic_error{"Invalid string representation"};
        }
        
        template <endian::order r, size_t size>
        static bytes from_uint(const uint<size>& u) {
            size_t serialized_size = u.serialized_size();
            size_t min_size = std::min(size, serialized_size);
            bytes b(serialized_size);
            digits<r> n{data::slice<byte>{b.data(), b.size()}};
            std::copy(u.begin(), u.begin() + min_size, n.begin());
            if (min_size < serialized_size) n[-1] = 0x00;
            return b;
        }
        
        template <endian::order r> static bytes shift(const digits<r> x, int i) {
            bytes a(x.Data.size());
            std::copy(x.Data.begin(), x.Data.end(), a.begin());
            
            if (i == 0) {
                return a;
            }
            
            int shift_bytes = i / 8;
            int mod = i%8;
            if (mod < 0) {
                mod += 8;
                shift_bytes++;
            }
            
            int new_size = a.size() + shift_bytes;
            if (new_size <= 0) return bytes{};
            
            // add one extra for sign byte. We will make a non-minimal representation
            // of the result and then trim it since that's easier. 
            bytes b(new_size + 1);
            
            numbers::digits<r> m{data::slice<byte>{const_cast<byte*>(a.data()), a.size()}};
            numbers::digits<r> n{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}};
            
            int to_copy = std::min(new_size, int(a.size()));
            
            // remove sign bit. 
            bool sign_bit = m[-1] & 0x80;
            m[-1] &= 0x7f;
            
            auto ai = m.begin();
            auto ae = m.begin() + to_copy;
            auto bi = n.begin();
            auto be = n.begin() + new_size;
            
            uint16 shift = 0;
            
            while (ai != ae) {
                uint16 shift = (shift << 8) + (uint16(*ai) << mod);
                *bi = data::greater_half(shift);
                ai++;
                bi++;
            }
            
            while (bi != be) {
                uint16 shift = shift << 8;
                *bi = data::greater_half(shift);
                bi++;
            }
            
            // replace sign bit
            n[-1] = sign_bit ? 0x80 : 0x00;
            
            return integer<r>::trim(b);
        }
        
        template <endian::order r> static bool less(const digits<r> a, const digits<r> b);
        template <endian::order r> static bool greater(const digits<r> a, const digits<r> b);
        template <endian::order r> static bool less_equal(const digits<r> a, const digits<r> b);
        template <endian::order r> static bool greater_equal(const digits<r> a, const digits<r> b);
        
        template <endian::order r> static std::vector<byte> plus(const digits<r> a, const digits<r> b);
        template <endian::order r> static std::vector<byte> times(const digits<r> a, const digits<r> b);
        
    };
    
    template <endian::order r> bool inline integer<r>::minimal(const bytes_view b) {
        return numbers::minimal(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}});
    }
    
    template <endian::order r> bool inline integer<r>::is_zero(const bytes_view b) {
        return numbers::is_zero(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}});
    }
    
    template <endian::order r> bool inline integer<r>::is_positive_zero(const bytes_view b) {
        return numbers::is_positive_zero(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}});
    }
    
    template <endian::order r> bool inline integer<r>::is_negative_zero(const bytes_view b) {
        return numbers::is_negative_zero(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}});
    }
    
    template <endian::order r> bool inline integer<r>::sign_bit(bytes_view b) {
        return numbers::sign_bit(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}});
    }
    
    template <endian::order r> bytes inline integer<r>::trim(bytes_view b) {
        if (minimal(b)) return bytes{b};
        if (is_zero(b)) return bytes{};
        return numbers::trim_nonminimal_nonzero(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}});
    }
    
    template <endian::order r> integer<r> inline integer<r>::trim() const {
        if (minimal()) return *this;
        if (is_zero()) return {};
        return integer{numbers::trim_nonminimal_nonzero(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(this->data()), this->size()}})};
    }
    
    template <endian::order r> bytes inline integer<r>::abs(bytes_view b) {
        if (!is_negative(b)) return integer<r>::trim(b);
        return numbers::abs_positive(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}});
    }
    
    template <endian::order r> natural<r> inline integer<r>::abs() const {
        if (!is_negative()) return natural<r>{trim(*this)};
        return natural<r>{numbers::abs_positive(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(this->data()), this->size()}})};
    }
    
    template <endian::order r> bytes inline integer<r>::negate(bytes_view b) {
        return numbers::negate(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}});
    }
    
    template <endian::order r> bool inline integer<r>::greater(bytes_view a, bytes_view b) {
        return numbers::greater(
            numbers::digits<r>{data::slice<byte>{const_cast<byte*>(a.data()), a.size()}}, 
            numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}});
    }
    
    template <endian::order r> bool inline integer<r>::less(bytes_view a, bytes_view b) {
        return numbers::less(
            numbers::digits<r>{data::slice<byte>{const_cast<byte*>(a.data()), a.size()}}, 
            numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}});
    }
    
    template <endian::order r> bool inline integer<r>::greater_equal(bytes_view a, bytes_view b) {
        return numbers::greater_equal(
            numbers::digits<r>{data::slice<byte>{const_cast<byte*>(a.data()), a.size()}}, 
            numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}});
    }
    
    template <endian::order r> bool inline integer<r>::less_equal(bytes_view a, bytes_view b) {
        return numbers::less_equal(
            numbers::digits<r>{data::slice<byte>{const_cast<byte*>(a.data()), a.size()}}, 
            numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}});
    }
    
    template <endian::order r> bytes inline integer<r>::plus(bytes_view a, bytes_view b) {
        return bytes(numbers::plus(
            numbers::digits<r>{data::slice<byte>{const_cast<byte*>(a.data()), a.size()}}, 
            numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}}));
    }
    
    template <endian::order r> bytes inline integer<r>::minus(bytes_view a, bytes_view b) {
        return plus(a, negate(b));
    }
    
    template <endian::order r> bytes inline integer<r>::times(bytes_view a, bytes_view b) {
        return bytes(numbers::times(
            numbers::digits<r>{data::slice<byte>{const_cast<byte*>(a.data()), a.size()}}, 
            numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}}));
    }
        
    template <endian::order r> bytes integer<r>::shift(bytes_view a, int i) {
        return numbers::shift(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(a.data()), a.size()}}, i);
    }
    
    template <endian::order r> inline integer<r>::integer(int64 z) : bytes{numbers::from_int<r>(z)} {}
    
    template <endian::order r> inline integer<r>::integer(string_view x) : bytes{numbers::from_string<r>(x)} {}
    
    template <endian::order r> inline natural<r>::natural(uint64 z) : integer<r>{numbers::from_uint<r>(z)} {}
    
    template <endian::order r> inline natural<r>::natural(string_view x) : integer<r>{numbers::from_string<r>(x)} {
        if (integer<r>::is_negative(*this)) throw std::logic_error{"invalid string representation"};
    }
    
    template <endian::order r> template <size_t size> 
    inline natural<r>::natural(const uint<size> &u) : natural{numbers::from_uint<r, size>(u)} {}
    
    template <endian::order r> template <size_t size> natural<r>::operator uint<size>() const {
        auto n = this->trim();
        auto d = n.digits();
        if (d.Data.size() > size + 1 || (d.Data.size() == size + 1 && d[-1] != 0x00))
            throw std::logic_error{"natural too big to cast to uint"};
        uint<size> u{};
        std::copy(d.begin(), d.begin() + std::min(size, d.Data.size()), u.begin());
        return u;
    }
    
    template <> bool numbers::less<endian::little>(const digits<endian::little> a, const digits<endian::little> b);
    
    template <> bool numbers::greater<endian::little>(const digits<endian::little> a, const digits<endian::little> b);
    
    template <> bool numbers::less_equal<endian::little>(const digits<endian::little> a, const digits<endian::little> b);
    
    template <> bool numbers::greater_equal<endian::little>(const digits<endian::little> a, const digits<endian::little> b);
    
    template <> std::vector<byte> numbers::plus<endian::little>(const digits<endian::little> a, const digits<endian::little> b);
    
    template <> std::vector<byte> numbers::times<endian::little>(const digits<endian::little> a, const digits<endian::little> b);
    
    template <> bool numbers::less<endian::big>(const digits<endian::big> a, const digits<endian::big> b);
    
    template <> bool numbers::greater<endian::big>(const digits<endian::big> a, const digits<endian::big> b);
    
    template <> bool numbers::less_equal<endian::big>(const digits<endian::big> a, const digits<endian::big> b);
    
    template <> bool numbers::greater_equal<endian::big>(const digits<endian::big> a, const digits<endian::big> b);
    
    template <> std::vector<byte> numbers::plus<endian::big>(const digits<endian::big> a, const digits<endian::big> b);
    
    template <> std::vector<byte> numbers::times<endian::big>(const digits<endian::big> a, const digits<endian::big> b);
    
    template struct uint<16>; 
    template struct uint<20>;
    template struct uint<28>;
    template struct uint<32>;
    template struct uint<40>;
    template struct uint<48>;
    template struct uint<56>;
    template struct uint<64>;
    
    template struct natural<endian::big>;
    template struct natural<endian::little>;
    
}

#endif


