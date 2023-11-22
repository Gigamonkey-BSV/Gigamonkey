// Copyright (c) 2021-2023 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_NUMBER
#define GIGAMONKEY_NUMBER

#include <data/numbers.hpp>
#include <gigamonkey/p2p/var_int.hpp>
#include "hash.hpp"

namespace Gigamonkey {

    template <size_t size> using uint = uint_little<size>;
    
    template <endian::order> struct natural;
    template <endian::order> struct integer;

    template <endian::order r> natural<r> trim (const natural<r> &);
    template <endian::order r> integer<r> trim (const integer<r> &);

    template <endian::order r> natural<r> resize (const natural<r> &, size_t);
    template <endian::order r> integer<r> resize (const integer<r> &, size_t);

    template <endian::order r> size_t minimal_size (const integer<r> &);
    template <endian::order r> bool is_minimal_size (const integer<r> &);
    template <endian::order r> bool is_zero (const integer<r> &);
    template <endian::order r> bool is_positive (const integer<r> &);
    template <endian::order r> bool is_negative (const integer<r> &);
    template <endian::order r> bool is_positive_zero (const integer<r> &);
    template <endian::order r> bool is_negative_zero (const integer<r> &);

    template <endian::order r> math::sign sign (const integer<r> &);

    // comparison
    template <endian::order r> bool operator == (const integer<r> &a, const integer<r> &b);
    template <endian::order r> bool operator == (const integer<r> &, int64);

    template <endian::order r> std::weak_ordering operator <=> (const integer<r> &a, const integer<r> &b);
    template <endian::order r> std::weak_ordering operator <=> (const integer<r> &a, int64);

    template <endian::order r> bool operator == (const natural<r> &a, const natural<r> &b);
    template <endian::order r> bool operator == (const natural<r> &, uint64);

    template <endian::order r> std::weak_ordering operator <=> (const natural<r> &a, const natural<r> &b);
    template <endian::order r> std::weak_ordering operator <=> (const natural<r> &a, uint64);

    // bit operations
    template <endian::order r> integer<r> operator ~ (const integer<r> &);

    template <endian::order r> natural<r> operator & (const natural<r> &, const natural<r> &);
    template <endian::order r> integer<r> operator & (const integer<r> &, const natural<r> &);

    template <endian::order r> natural<r> operator | (const natural<r> &, const natural<r> &);
    template <endian::order r> integer<r> operator | (const integer<r> &, const natural<r> &);

    template <endian::order r> integer<r> operator ^ (const natural<r> &, const natural<r> &);
    template <endian::order r> integer<r> operator ^ (const integer<r> &, const integer<r> &);

    template <endian::order r> natural<r> &operator &= (natural<r> &, const natural<r> &);
    template <endian::order r> integer<r> &operator &= (integer<r> &, const natural<r> &);

    template <endian::order r> natural<r> &operator |= (natural<r> &, const natural<r> &);
    template <endian::order r> integer<r> &operator |= (integer<r> &, const natural<r> &);

    template <endian::order r> integer<r> &operator ^= (const natural<r> &, const natural<r> &);
    template <endian::order r> integer<r> &operator ^= (const integer<r> &, const integer<r> &);

    // boolean logic
    template <endian::order r> natural<r> operator ! (const natural<r> &);
    template <endian::order r> integer<r> operator ! (const integer<r> &);

    template <endian::order r> natural<r> operator && (const natural<r> &, const natural<r> &);
    template <endian::order r> integer<r> operator && (const integer<r> &, const natural<r> &);

    template <endian::order r> natural<r> operator || (const natural<r> &, const natural<r> &);
    template <endian::order r> integer<r> operator || (const integer<r> &, const natural<r> &);

    // increment and decrement
    template <endian::order r> natural<r> increment (const natural<r> &);
    template <endian::order r> natural<r> decrement (const natural<r> &);

    template <endian::order r> integer<r> increment (const integer<r> &);
    template <endian::order r> integer<r> decrement (const integer<r> &);

    // pre-increment and decreement
    template <endian::order r> natural<r> &operator ++ (natural<r> &);
    template <endian::order r> integer<r> &operator ++ (integer<r> &);

    template <endian::order r> natural<r> &operator -- (natural<r> &);
    template <endian::order r> integer<r> &operator -- (integer<r> &);

    // post-increment and decrement
    template <endian::order r> natural<r> operator ++ (natural<r> &, int);
    template <endian::order r> integer<r> operator ++ (integer<r> &, int);

    template <endian::order r> natural<r> operator -- (natural<r> &, int);
    template <endian::order r> integer<r> operator -- (integer<r> &, int);

    // negation
    template <endian::order r> integer<r> operator - (const natural<r> &);
    template <endian::order r> integer<r> operator - (const integer<r> &);

    // abs
    template <endian::order r> natural<r> abs (const natural<r> &);
    template <endian::order r> natural<r> abs (const integer<r> &);

    // arithmetic
    template <endian::order r> natural<r> operator + (const natural<r> &, const natural<r> &);
    template <endian::order r> natural<r> operator - (const natural<r> &, const natural<r> &);
    template <endian::order r> natural<r> operator * (const natural<r> &, const natural<r> &);
    template <endian::order r> natural<r> operator / (const natural<r> &, const natural<r> &);
    template <endian::order r> natural<r> operator % (const natural<r> &, const natural<r> &);

    template <endian::order r> natural<r> &operator += (natural<r> &, const natural<r> &);
    template <endian::order r> natural<r> &operator -= (natural<r> &, const natural<r> &);
    template <endian::order r> natural<r> &operator *= (natural<r> &, const natural<r> &);
    template <endian::order r> natural<r> &operator /= (natural<r> &, const natural<r> &);
    template <endian::order r> natural<r> &operator %= (natural<r> &, const natural<r> &);

    template <endian::order r> integer<r> operator + (const integer<r> &, const integer<r> &);
    template <endian::order r> integer<r> operator - (const integer<r> &, const integer<r> &);
    template <endian::order r> integer<r> operator * (const integer<r> &, const integer<r> &);
    template <endian::order r> integer<r> operator / (const integer<r> &, const integer<r> &);
    template <endian::order r> integer<r> operator % (const integer<r> &, const integer<r> &);

    template <endian::order r> integer<r> &operator += (integer<r> &, const integer<r> &);
    template <endian::order r> integer<r> &operator -= (integer<r> &, const integer<r> &);
    template <endian::order r> integer<r> &operator *= (integer<r> &, const integer<r> &);
    template <endian::order r> integer<r> &operator /= (integer<r> &, const integer<r> &);
    template <endian::order r> integer<r> &operator %= (integer<r> &, const integer<r> &);

    //shift
    template <endian::order r> natural<r> operator << (const natural<r> &, int);
    template <endian::order r> integer<r> operator << (const integer<r> &, int);
    template <endian::order r> natural<r> operator >> (const natural<r> &, int);
    template <endian::order r> integer<r> operator >> (const integer<r> &, int);

    template <endian::order r> natural<r> operator <<= (const natural<r> &, int);
    template <endian::order r> integer<r> operator <<= (const integer<r> &, int);
    template <endian::order r> natural<r> operator >>= (const natural<r> &, int);
    template <endian::order r> integer<r> operator >>= (const integer<r> &, int);

    template <size_t size> writer &operator << (writer &, const uint_little<size> &);
    template <size_t size> reader &operator >> (reader &, uint_little<size> &);
    
    template <endian::order r> struct integer : bytes {

        // shorted to be minimally encoded.
        static bytes trim (bytes_view b);
        static bytes resize (bytes_view, size_t);
        
        static size_t minimal_size (const bytes_view b);
        static bool is_minimal_size (const bytes_view b);
        
        static bool is_zero (const bytes_view b);
        static bool is_positive_zero (const bytes_view b);
        static bool is_negative_zero (const bytes_view b);
        
        static bool sign_bit (bytes_view b);
        
        static data::math::sign sign (bytes_view b);
        
        static bool is_positive (bytes_view b);
        static bool is_negative (bytes_view b);
        
        bool sign_bit () const;
        
        integer &trim ();
        integer &resize (size_t z);
        
        static std::weak_ordering compare (bytes_view, bytes_view);

        static bytes bit_and (bytes_view, bytes_view);
        static bytes bit_or (bytes_view, bytes_view);

        static bytes increment (bytes_view b);
        static bytes decrement (bytes_view b);
        
        static bytes abs (bytes_view b);
        
        static bytes negate (bytes_view b);
        
        static bytes plus (bytes_view a, bytes_view b);
        static bytes times (bytes_view a, bytes_view b);
        
        static bytes shift (bytes_view a, int);
        
        integer operator << (int) const;
        integer operator >> (int) const;
        
        integer &operator <<= (int);
        integer &operator >>= (int);
        
        math::division<integer> divide (const integer &) const;
        
        static integer zero (size_t size = 0, bool negative = false);

        integer () : bytes {} {}
        integer (int64 z): integer (math::Z_bytes_twos<r> (z)) {}
        integer (bytes_view b) : bytes {b} {}
        explicit integer (string_view x): integer (math::Z_bytes_twos<r>::read (x)) {}
        explicit operator integer<endian::opposite (r)> () const;

        template <size_t size> explicit integer (const uint<size> &u): bytes (0, size + 1) {
            std::copy (u.begin (), u.end (), this->begin ());
            trim ();
        }

        explicit operator bool () const {
            return !is_zero (*this);
        }

        static const integer &boolean (bool);
        
        integer (bytes &&b) : bytes {b} {}

        explicit operator Z () const {
            return Z (Z_bytes_little (bytes_view (*this)));
        }
    };
    
    template <endian::order r> 
    struct natural : public integer<r> {
        
        natural () : integer<r> {} {}

        template <size_t size>
        natural (digest<size>);
        
        math::division<natural> divide (const natural &) const;
        
        natural operator << (int) const;
        natural operator >> (int) const;
        
        natural &operator <<= (int);
        natural &operator >>= (int);
        
        natural (uint64 z);
        explicit natural (string_view x);
        explicit operator N () const;
        explicit operator natural<endian::opposite (r)> () const;
        template <size_t size> explicit natural (const uint<size> &u): integer<r> {u} {}
        template <size_t size> operator uint<size> () const;
        natural (bytes &&b) : integer<r> {b} {}
        
        bool valid () const {
            return !integer<r>::is_negative (*this);
        }
    };
    
}

namespace Gigamonkey::Bitcoin {
    
    using N = natural<endian::little>;
    using Z = integer<endian::little>;
    
    template <size_t size> size_t serialized_size (const uint<size> &u) {
        size_t last_0 = 0;
        for (size_t i = 0; i < size; i++) if (u[i] != 0x00) last_0 = i + 1;
        return last_0 == 0 ? 1 : u[last_0 - 1] & 0x80 ? last_0 + 2 : last_0 + 1;
    }
}

namespace Gigamonkey {

    template <endian::order r> natural<r> inline trim (const natural<r> &x) {
        return integer<r>::trim (x);
    }

    template <endian::order r> integer<r> inline trim (const integer<r> &x) {
        return integer<r>::trim (x);
    }

    template <endian::order r> natural<r> inline resize (const natural<r> &x, size_t z) {
        return integer<r>::resize (x, z);
    }

    template <endian::order r> integer<r> inline resize (const integer<r> &x, size_t z) {
        return integer<r>::resize (x, z);
    }

    template <endian::order r> size_t inline minimal_size (const integer<r> &x) {
        return integer<r>::minimal_size (x);
    }

    template <endian::order r> bool inline is_minimal_size (const integer<r> &x) {
        return integer<r>::is_minimal_size (x);
    }

    template <endian::order r> bool inline is_zero (const integer<r> &x) {
        return integer<r>::is_zero (x);
    }

    template <endian::order r> bool inline is_positive (const integer<r> &x) {
        return integer<r>::is_positive (x);
    }

    template <endian::order r> bool inline is_negative (const integer<r> &x) {
        return integer<r>::is_negative (x);
    }

    template <endian::order r> bool inline is_positive_zero (const integer<r> &x) {
        return integer<r>::is_positive_zero (x);
    }

    template <endian::order r> bool inline is_negative_zero (const integer<r> &x) {
        return integer<r>::is_negative_zero (x);
    }

    template <endian::order r> math::sign inline sign (const integer<r> &x) {
        return integer<r>::sign (x);
    }

    template <endian::order r>
    bool inline operator == (const natural<r> &a, const natural<r> &b) {
        return (a <=> b) == 0;
    }

    template <endian::order r>
    bool inline operator == (const integer<r> &a, const integer<r> &b) {
        return (a <=> b) == 0;
    }

    template <endian::order r> natural<r> inline increment (const natural<r> &x) {
        return integer<r>::increment (x);
    }

    template <endian::order r> natural<r> inline decrement (const natural<r> &x) {
        if (integer<r>::is_zero (x)) return natural<r> {};
        return integer<r>::decrement (x);
    }

    template <endian::order r> integer<r> inline increment (const integer<r> &x) {
        return integer<r>::increment (x);
    }

    template <endian::order r> integer<r> inline decrement (const integer<r> &x) {
        return integer<r>::decrement (x);
    }

    // post-increment and decrement
    template <endian::order r> natural<r> inline operator ++ (natural<r> &n, int) {
        auto x = n; ++n; return x;
    }

    template <endian::order r> integer<r> inline operator ++ (integer<r> &n, int) {
        auto x = n; ++n; return x;
    }

    template <endian::order r> natural<r> inline operator -- (natural<r> &n, int) {
        auto x = n; --n; return x;
    }

    template <endian::order r> integer<r> inline operator -- (integer<r> &n, int) {
        auto x = n; --n; return x;
    }

    template <endian::order r> natural<r> inline &operator /= (natural<r> &a, const natural<r> &b) {
        return a = a / b;
    }

    template <endian::order r> integer<r> inline &operator /= (integer<r> &a, const natural<r> &b) {
        return a = a / b;
    }

    template <endian::order r> natural<r> inline &operator %= (natural<r> &a, const natural<r> &b) {
        return a = a % b;
    }

    template <endian::order r> integer<r> inline &operator %= (integer<r> &a, const natural<r> &b) {
        return a = a % b;
    }

    template <endian::order r> natural<r> inline operator ! (const natural<r> &n) {
        return !bool (n);
    }

    template <endian::order r> integer<r> inline operator ! (const integer<r> &n) {
        return !bool (n);
    }

    template <endian::order r> natural<r> inline operator && (const natural<r> &a, const natural<r> &b) {
        return bool (a) && bool (b);
    }

    template <endian::order r> integer<r> inline operator && (const integer<r> &a, const natural<r> &b) {
        return bool (a) && bool (b);
    }

    template <endian::order r> natural<r> inline operator || (const natural<r> &a, const natural<r> &b) {
        return bool (a) || bool (b);
    }

    template <endian::order r> integer<r> inline operator || (const integer<r> &a, const natural<r> &b) {
        return bool (a) || bool (b);
    }

    template <endian::order r> integer<r> inline operator / (const integer<r> &x, const integer<r> &z) {
        return trim (trim (x).divide (trim (z)).Quotient);
    }

    template <endian::order r> integer<r> inline operator % (const integer<r> &x, const integer<r> &z) {
        return trim (trim (x).divide (trim (z)).Remainder);
    }

    template <endian::order r> natural<r> inline operator / (const integer<r> &x, const natural<r> &z) {
        return trim (trim (x).divide (trim (z)).Quotient);
    }

    template <endian::order r> natural<r> inline operator % (const integer<r> &x, const natural<r> &z) {
        return trim (trim (x).divide (trim (z)).Remainder);
    }

    template <endian::order r>
    std::weak_ordering inline operator <=> (const integer<r> &a, const integer<r> &b) {
        return integer<r>::compare (a, b);
    }

    template <endian::order r>
    std::weak_ordering inline operator <=> (const natural<r> &a, const natural<r> &b) {
        return integer<r>::compare (a, b);
    }

    template <endian::order r>
    bytes inline integer<r>::increment (bytes_view b) {
        integer n (b);
        return ++n;
    }

    template <endian::order r>
    bytes inline integer<r>::decrement (bytes_view b) {
        integer n (b);
        return --n;
    }

    template <endian::order r> integer<r> inline operator ~ (const integer<r> &x) {
        auto z = x;
        z.bit_negate ();
        return z;
    }

    template <endian::order r> bool inline integer<r>::sign_bit () const {
        return sign_bit (*this);
    }

    template <endian::order r> integer<r> inline integer<r>::zero (size_t size, bool negative) {
        return Z_bytes_twos_little::zero (size, negative);
    }

    template <endian::order r> const integer<r> &integer<r>::boolean (bool b) {
        static integer<r> True {bytes (1, 1)};
        static integer<r> False {bytes (0)};
        return b ? True : False;
    }

    template <endian::order r> bool inline integer<r>::is_negative (bytes_view b) {
        return !is_zero (b) && sign_bit (b);
    }

    template <endian::order r> bool inline integer<r>::is_positive (bytes_view b) {
        return !is_zero (b) && !sign_bit (b);
    }

    template <endian::order r> bool inline integer<r>::is_negative_zero (bytes_view b) {
        return is_zero (b) && sign_bit (b);
    }

    template <endian::order r> bool inline integer<r>::is_positive_zero (bytes_view b) {
        return is_zero (b) && !sign_bit (b);
    }

    template <endian::order r> math::sign inline integer<r>::sign (bytes_view b) {
        return is_zero (b) ? math::zero : sign_bit (b) ? math::negative : math::positive;
    }

    template <endian::order r> inline
    integer<r>::operator integer<endian::opposite (r)> () const {
        bytes x;
        x.resize (this->size ());
        std::copy (this->begin (), this->end (), x.rbegin ());
        return x;
    }

    template <endian::order r> inline
    natural<r>::natural (uint64 z): natural {uint_little<8> {z}} {
        *this = integer<r>::trim (*this);
    }

    template <endian::order r> inline
    natural<r>::natural (string_view x): integer<r> (x) {
        if (integer<r>::is_negative (*this)) throw exception {} << "invalid string representation " << string {x};
    }

    template <endian::order r> inline
    natural<r>::operator natural<endian::opposite (r)> () const {
        bytes x;
        x.resize (this->size ());
        std::copy (this->begin (), this->end (), x.rbegin ());
        return x;
    }

    template <endian::order r> integer<r> inline operator - (const natural<r> &z) {
        return integer<r>::negate (z);
    }

    template <endian::order r> integer<r> inline operator - (const integer<r> &z) {
        return integer<r>::negate (z);
    }

    template <endian::order r> natural<r> inline abs (const natural<r> &z) {
        return trim (z);
    }

    template <endian::order r> natural<r> inline abs (const integer<r> &z) {
        return integer<r>::abs (z);
    }

    template <endian::order r> natural<r> inline operator & (const natural<r> &a, const natural<r> &b) {
        return integer<r>::bit_and (a, b);
    }

    template <endian::order r> integer<r> inline operator & (const integer<r> &a, const natural<r> &b) {
        return integer<r>::bit_and (a, b);
    }

    template <endian::order r> natural<r> inline operator | (const natural<r> &a, const natural<r> &b) {
        return integer<r>::bit_or (a, b);
    }

    template <endian::order r> integer<r> inline operator | (const integer<r> &a, const natural<r> &b) {
        return integer<r>::bit_or (a, b);
    }

    template <endian::order r> natural<r> inline operator ^ (const natural<r> &a, const natural<r> &b) {
        return integer<r>::bit_xor (a, b);
    }

    template <endian::order r> integer<r> inline operator ^ (const integer<r> &a, const natural<r> &b) {
        return integer<r>::bit_xor (a, b);
    }

    template <endian::order r> integer<r> inline operator + (const integer<r> &y, const integer<r> &z) {
        return integer<r>::plus (y, z);
    }

    template <endian::order r> integer<r> inline operator - (const integer<r> &y, const integer<r> &z) {
        return integer<r>::plus (y, -z);
    }

    template <endian::order r> integer<r> inline operator * (const integer<r> &y, const integer<r> &z) {
        return integer<r>::times (y, z);
    }

    template <endian::order r> natural<r> inline operator + (const natural<r> &y, const natural<r> &z) {
        return integer<r>::plus (y, z);
    }

    template <endian::order r> natural<r> inline operator - (const natural<r> &y, const natural<r> &z) {
        if (z > y) return natural<r> {};
        return integer<r>::plus (y, -z);
    }

    template <endian::order r> natural<r> inline operator * (const natural<r> &y, const natural<r> &z) {
        return integer<r>::times (y, z);
    }
/*
    template <endian::order r> math::division<integer<r>> inline integer<r>::divide (const integer &z) const {
        return math::number::integer::divide (*this, z);
    }

    template <endian::order r> math::division<natural<r>> inline natural<r>::divide (const natural &z) const {
        return math::number::natural::divide (*this, z);
    }
*/
    namespace arithmetic = math::number::arithmetic;

    template <endian::order r> bool inline integer<r>::is_minimal_size (bytes_view b) {
        return arithmetic::is_minimal<r, math::number::complement::twos, byte> (b);
    }

    template <endian::order r> bytes inline integer<r>::trim (bytes_view b) {
        return arithmetic::trim<r, math::number::complement::twos, byte> (b);
    }

    template <endian::order r>
    integer<r> inline &integer<r>::trim () {
        arithmetic::trim<r, math::number::complement::twos> (*this);
        return *this;
    }

    template <endian::order r>
    integer<r> inline &integer<r>::resize (size_t z) {
        arithmetic::extend<r, math::number::complement::twos> (*this, z);
        return *this;
    }

    template <endian::order r> bool inline integer<r>::is_zero (bytes_view b) {
        return arithmetic::is_zero<r, math::number::complement::twos, byte> (b);
    }

    template <endian::order r> bool inline integer<r>::sign_bit (bytes_view b) {
        return arithmetic::sign_bit<r, math::number::complement::twos, byte> (b);
    }

    template <endian::order r> bytes inline integer<r>::bit_and (bytes_view a, bytes_view b) {
        return arithmetic::bit_and<r, math::number::complement::twos> (a, b);
    }

    template <endian::order r> bytes inline integer<r>::bit_or (bytes_view a, bytes_view b) {
        return arithmetic::bit_or<r, math::number::complement::twos> (a, b);
    }

    template <endian::order r> bytes inline integer<r>::negate (bytes_view b) {
        return integer<r>::trim (arithmetic::twos::negate<r, byte> (b));
    }

    template <endian::order r> bytes inline integer<r>::abs (bytes_view b) {
        return integer<r>::trim (is_positive (b) ? bytes {b} : arithmetic::twos::negate<r, byte> (b));
    }

    template <endian::order r> std::weak_ordering inline integer<r>::compare (bytes_view a, bytes_view b) {
        return arithmetic::twos::compare<r, byte> (a, b);
    }

    template <endian::order r> natural<r> inline &operator ++ (natural<r> &x) {
        arithmetic::twos::increment<r> (integer<r>::trim (x.trim));
        return x;
    }

    template <endian::order r> natural<r> inline &operator -- (natural<r> &x) {
        integer<r>::trim (arithmetic::nones::decrement<r> (x));
        return x;
    }

    template <endian::order r> integer<r> inline &operator ++ (integer<r> &x) {
        integer<r>::trim (arithmetic::twos::increment<r> (x));
        return x;
    }

    template <endian::order r> integer<r> inline &operator -- (integer<r> &x) {
        integer<r>::trim (arithmetic::twos::decrement<r> (x));
        return x;
    }

    template <endian::order r> natural<r> inline operator &= (natural<r> &a, const natural<r> &b) {
        arithmetic::bit_and<r, math::number::complement::twos, byte> (a, b);
        return a;
    }

    template <endian::order r> integer<r> inline operator &= (integer<r> &a, const natural<r> &b) {
        arithmetic::bit_and<r, math::number::complement::twos, byte> (a, b);
        return a;
    }

    template <endian::order r> natural<r> inline operator |= (natural<r> &a, const natural<r> &b) {
        arithmetic::bit_or<r, math::number::complement::twos, byte> (a, b);
        return a;
    }

    template <endian::order r> integer<r> inline operator |= (integer<r> &a, const natural<r> &b) {
        arithmetic::bit_or<r, math::number::complement::twos, byte> (a, b);
        return a;
    }

    template <endian::order r> natural<r> inline operator ^= (natural<r> &a, const natural<r> &b) {
        arithmetic::bit_xor<r, math::number::complement::twos, byte> (a, b);
        return a;
    }

    template <endian::order r> integer<r> inline operator ^= (integer<r> &a, const natural<r> &b) {
        arithmetic::bit_xor<r, math::number::complement::twos, byte> (a, b);
        return a;
    }

    template <endian::order r> integer<r> inline operator += (integer<r> &y, const integer<r> &z) {
        arithmetic::twos::plus<r, byte> (y.trim (), trim (z));
        return y.trim ();
    }

    template <endian::order r> integer<r> inline operator -= (integer<r> &y, const integer<r> &z) {
        arithmetic::twos::plus<r, byte> (y.trim (), -z);
        return y.trim ();
    }

    template <endian::order r> integer<r> inline operator *= (integer<r> &y, const integer<r> &z) {
        arithmetic::twos::times<r, byte> (y.trim (), trim (z));
        return y.trim ();
    }

    template <endian::order r> natural<r> inline operator += (natural<r> &y, const natural<r> &z) {
        arithmetic::twos::plus<r, byte> (y.trim (), trim (z));
        return y.trim ();
    }

    template <endian::order r> natural<r> inline operator -= (natural<r> &y, const natural<r> &z) {
        if (z > y) return y = natural<r> {};
        arithmetic::twos::plus<r, byte> (y.trim (), -z);
        return y.trim ();
    }

    template <endian::order r> natural<r> inline operator *= (natural<r> &y, const natural<r> &z) {
        arithmetic::twos::times<r, byte> (y.trim (), trim (z));
        return y.trim ();
    }

    template <endian::order r> bytes inline integer<r>::plus (bytes_view a, bytes_view b) {
        return integer<r>::trim (arithmetic::twos::plus<r, byte> (integer<r>::trim (a), integer<r>::trim (b)));
    }

    template <endian::order r> bytes inline integer<r>::times (bytes_view a, bytes_view b) {
        return integer<r>::trim (arithmetic::twos::times<r, byte> (integer<r>::trim (a), integer<r>::trim (b)));
    }
/*
    template <endian::order r> integer<r> inline integer<r>::operator << (int i) const {
        if (i == 0) return *this;
        return integer {shift (this->trim (), i)};
    }
    
    template <endian::order r> integer<r> inline integer<r>::operator >> (int i) const {
        if (i == 0) return *this;
        return integer {shift (this->trim (), -i)};
    }
    
    template <endian::order r> natural<r> inline natural<r>::operator << (int i) const {
        if (i == 0) return *this;
        return natural {integer<r>::shift (this->trim (), i)};
    }
    
    template <endian::order r> natural<r> inline natural<r>::operator >> (int i) const {
        if (i == 0) return *this;
        return natural {integer<r>::shift (this->trim (), -i)};
    }
    
    template <endian::order r> integer<r> &integer<r>::operator <<= (int i) {
        return *this = *this << i;
    }
    
    template <endian::order r> integer<r> &integer<r>::operator >>= (int i) {
        return *this = *this >> i;
    }
    
    template <endian::order r> natural<r> &natural<r>::operator <<= (int i) {
        return *this = *this << i;
    }
    
    template <endian::order r> natural<r> &natural<r>::operator >>= (int i) {
        return *this = *this >> i;
    }
    
    struct numbers {

        template <endian::order r> using digits = data::encoding::words<r, byte>;

    private:
        template <endian::order r> friend struct integer;
        template <endian::order r> friend struct natural;
        
        template <endian::order r> static bytes shift (const digits<r> x, int i) {
            bytes a (x.Data.size ());
            std::copy (x.Data.begin (), x.Data.end (), a.begin ());
            
            if (i == 0) return a;
            
            int shift_bytes = i / 8;
            int mod = i % 8;
            if (mod < 0) {
                mod += 8;
                shift_bytes++;
            }
            
            int new_size = a.size () + shift_bytes;
            if (new_size <= 0) return bytes {};
            
            // add one extra for sign byte. We will make a non-minimal representation
            // of the result and then trim it since that's easier. 
            bytes b (new_size + 1);
            
            numbers::digits<r> m {data::slice<byte> {const_cast<byte*> (a.data ()), a.size ()}};
            numbers::digits<r> n {data::slice<byte> {const_cast<byte*> (b.data ()), b.size ()}};
            
            int to_copy = std::min (new_size, int (a.size ()));
            
            // remove sign bit. 
            bool sign_bit = m[-1] & 0x80;
            m[-1] &= 0x7f;
            
            auto ai = m.begin ();
            auto ae = m.begin () + to_copy;
            auto bi = n.begin ();
            auto be = n.begin () + new_size;
            
            uint16 shift = 0;
            
            while (ai != ae) {
                uint16 shift = (shift << 8) + (uint16 (*ai) << mod);
                *bi = data::encoding::greater_half (shift);
                ai++;
                bi++;
            }
            
            while (bi != be) {
                uint16 shift = shift << 8;
                *bi = data::encoding::greater_half (shift);
                bi++;
            }
            
            // replace sign bit
            n[-1] = sign_bit ? 0x80 : 0x00;
            
            return integer<r>::trim (b);
        }
        
        template <endian::order r> static bool less (const digits<r> a, const digits<r> b);
        template <endian::order r> static bool greater (const digits<r> a, const digits<r> b);
        template <endian::order r> static bool less_equal (const digits<r> a, const digits<r> b);
        template <endian::order r> static bool greater_equal (const digits<r> a, const digits<r> b);
        
        template <endian::order r> static std::vector<byte> plus (const digits<r> a, const digits<r> b);
        template <endian::order r> static std::vector<byte> times (const digits<r> a, const digits<r> b);
        
    };
    
    template <endian::order r> template <size_t size> natural<r>::operator uint_little<size> () const {
        auto n = this->trim ();
        auto d = n.words ();
        if (d.Data.size () > size + 1 || (d.Data.size () == size + 1 && d[-1] != 0x00))
            throw std::logic_error {"natural too big to cast to uint"};
        uint_little<size> u {};
        std::copy (d.begin (), d.begin () + std::min (size, d.Data.size ()), u.begin ());
        return u;
    }*/
    
    template struct integer<endian::little>;
    template struct natural<endian::little>;
    
}

#endif


