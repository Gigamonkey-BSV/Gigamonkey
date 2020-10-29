// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BSV_ARITH_UINT256_H
#define BSV_ARITH_UINT256_H

#include <cassert>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace bsv {

    class uint256;

    class uint_error : public std::runtime_error {
    public:
        explicit uint_error(const std::string &str) : std::runtime_error(str) {}
    };

    /** Template base class for unsigned big integers. */
    template <unsigned int BITS> class base_uint {
    protected:
        enum { WIDTH = BITS / 32 };
        uint32_t pn[WIDTH];

    public:
        base_uint() {
            for (int i = 0; i < WIDTH; i++)
                pn[i] = 0;
        }

        base_uint(const base_uint &b) {
            for (int i = 0; i < WIDTH; i++)
                pn[i] = b.pn[i];
        }

        base_uint &operator=(const base_uint &b) {
            for (int i = 0; i < WIDTH; i++)
                pn[i] = b.pn[i];
            return *this;
        }

        base_uint(uint64_t b) {
            pn[0] = (unsigned int)b;
            pn[1] = (unsigned int)(b >> 32);
            for (int i = 2; i < WIDTH; i++)
                pn[i] = 0;
        }

        explicit base_uint(const std::string &str);

        bool operator!() const {
            for (int i = 0; i < WIDTH; i++)
                if (pn[i] != 0) return false;
            return true;
        }

        const base_uint operator~() const {
            base_uint ret;
            for (int i = 0; i < WIDTH; i++)
                ret.pn[i] = ~pn[i];
            return ret;
        }

        const base_uint operator-() const {
            base_uint ret;
            for (int i = 0; i < WIDTH; i++)
                ret.pn[i] = ~pn[i];
            ret++;
            return ret;
        }

        double getdouble() const;

        base_uint &operator=(uint64_t b) {
            pn[0] = (unsigned int)b;
            pn[1] = (unsigned int)(b >> 32);
            for (int i = 2; i < WIDTH; i++)
                pn[i] = 0;
            return *this;
        }

        base_uint &operator^=(const base_uint &b) {
            for (int i = 0; i < WIDTH; i++)
                pn[i] ^= b.pn[i];
            return *this;
        }

        base_uint &operator&=(const base_uint &b) {
            for (int i = 0; i < WIDTH; i++)
                pn[i] &= b.pn[i];
            return *this;
        }

        base_uint &operator|=(const base_uint &b) {
            for (int i = 0; i < WIDTH; i++)
                pn[i] |= b.pn[i];
            return *this;
        }

        base_uint &operator^=(uint64_t b) {
            pn[0] ^= (unsigned int)b;
            pn[1] ^= (unsigned int)(b >> 32);
            return *this;
        }

        base_uint &operator|=(uint64_t b) {
            pn[0] |= (unsigned int)b;
            pn[1] |= (unsigned int)(b >> 32);
            return *this;
        }

        base_uint &operator<<=(unsigned int shift);
        base_uint &operator>>=(unsigned int shift);

        base_uint &operator+=(const base_uint &b) {
            uint64_t carry = 0;
            for (int i = 0; i < WIDTH; i++) {
                uint64_t n = carry + pn[i] + b.pn[i];
                pn[i] = n & 0xffffffff;
                carry = n >> 32;
            }
            return *this;
        }

        base_uint &operator-=(const base_uint &b) {
            *this += -b;
            return *this;
        }

        base_uint &operator+=(uint64_t b64) {
            base_uint b;
            b = b64;
            *this += b;
            return *this;
        }

        base_uint &operator-=(uint64_t b64) {
            base_uint b;
            b = b64;
            *this += -b;
            return *this;
        }

        base_uint &operator*=(uint32_t b32);
        base_uint &operator*=(const base_uint &b);
        base_uint &operator/=(const base_uint &b);

        base_uint &operator++() {
            // prefix operator
            int i = 0;
            while (++pn[i] == 0 && i < WIDTH - 1)
                i++;
            return *this;
        }

        const base_uint operator++(int) {
            // postfix operator
            const base_uint ret = *this;
            ++(*this);
            return ret;
        }

        base_uint &operator--() {
            // prefix operator
            int i = 0;
            while (--pn[i] == (uint32_t)-1 && i < WIDTH - 1)
                i++;
            return *this;
        }

        const base_uint operator--(int) {
            // postfix operator
            const base_uint ret = *this;
            --(*this);
            return ret;
        }

        int CompareTo(const base_uint &b) const;
        bool EqualTo(uint64_t b) const;

        friend inline const base_uint operator+(const base_uint &a,
                                                const base_uint &b) {
            return base_uint(a) += b;
        }
        friend inline const base_uint operator-(const base_uint &a,
                                                const base_uint &b) {
            return base_uint(a) -= b;
        }
        friend inline const base_uint operator*(const base_uint &a,
                                                const base_uint &b) {
            return base_uint(a) *= b;
        }
        friend inline const base_uint operator/(const base_uint &a,
                                                const base_uint &b) {
            return base_uint(a) /= b;
        }
        friend inline const base_uint operator|(const base_uint &a,
                                                const base_uint &b) {
            return base_uint(a) |= b;
        }
        friend inline const base_uint operator&(const base_uint &a,
                                                const base_uint &b) {
            return base_uint(a) &= b;
        }
        friend inline const base_uint operator^(const base_uint &a,
                                                const base_uint &b) {
            return base_uint(a) ^= b;
        }
        friend inline const base_uint operator>>(const base_uint &a, int shift) {
            return base_uint(a) >>= shift;
        }
        friend inline const base_uint operator<<(const base_uint &a, int shift) {
            return base_uint(a) <<= shift;
        }
        friend inline const base_uint operator*(const base_uint &a, uint32_t b) {
            return base_uint(a) *= b;
        }
        friend inline bool operator==(const base_uint &a, const base_uint &b) {
            return memcmp(a.pn, b.pn, sizeof(a.pn)) == 0;
        }
        friend inline bool operator!=(const base_uint &a, const base_uint &b) {
            return memcmp(a.pn, b.pn, sizeof(a.pn)) != 0;
        }
        friend inline bool operator>(const base_uint &a, const base_uint &b) {
            return a.CompareTo(b) > 0;
        }
        friend inline bool operator<(const base_uint &a, const base_uint &b) {
            return a.CompareTo(b) < 0;
        }
        friend inline bool operator>=(const base_uint &a, const base_uint &b) {
            return a.CompareTo(b) >= 0;
        }
        friend inline bool operator<=(const base_uint &a, const base_uint &b) {
            return a.CompareTo(b) <= 0;
        }
        friend inline bool operator==(const base_uint &a, uint64_t b) {
            return a.EqualTo(b);
        }
        friend inline bool operator!=(const base_uint &a, uint64_t b) {
            return !a.EqualTo(b);
        }

        std::string GetHex() const;
        void SetHex(const char *psz);
        void SetHex(const std::string &str);
        std::string ToString() const;

        unsigned int size() const { return sizeof(pn); }

        /**
        * Returns the position of the highest bit set plus one, or zero if the
        * value is zero.
        */
        unsigned int bits() const;

        uint64_t GetLow64() const {
            assert(WIDTH >= 2);
            return pn[0] | (uint64_t)pn[1] << 32;
        }
    };

    /** 256-bit unsigned big integer. */
    class arith_uint256 : public base_uint<256> {
    public:
        arith_uint256() {}
        arith_uint256(const base_uint<256> &b) : base_uint<256>(b) {}
        arith_uint256(uint64_t b) : base_uint<256>(b) {}
        explicit arith_uint256(const std::string &str) : base_uint<256>(str) {}

        /**
        * The "compact" format is a representation of a whole number N using an
        * unsigned 32bit number similar to a floating point format.
        * The most significant 8 bits are the unsigned exponent of base 256.
        * This exponent can be thought of as "number of bytes of N".
        * The lower 23 bits are the mantissa.
        * Bit number 24 (0x800000) represents the sign of N.
        * N = (-1^sign) * mantissa * 256^(exponent-3)
        *
        * Satoshi's original implementation used BN_bn2mpi() and BN_mpi2bn().
        * MPI uses the most significant bit of the first byte as sign.
        * Thus 0x1234560000 is compact (0x05123456)
        * and  0xc0de000000 is compact (0x0600c0de)
        *
        * Bitcoin only uses this "compact" format for encoding difficulty targets,
        * which are unsigned 256bit quantities. Thus, all the complexities of the
        * sign bit and using base 256 are probably an implementation accident.
        */
        arith_uint256 &SetCompact(uint32_t nCompact, bool *pfNegative = nullptr,
                                bool *pfOverflow = nullptr);
        uint32_t GetCompact(bool fNegative = false) const;

        friend uint256 ArithToUint256(const arith_uint256 &);
        friend arith_uint256 UintToArith256(const uint256 &);
    };

    uint256 ArithToUint256(const arith_uint256 &);
    arith_uint256 UintToArith256(const uint256 &);

}

#include <sv/uint256.h>

namespace bsv {
    
    template <unsigned int BITS>
    base_uint<BITS>::base_uint(const std::string &str) {
        SetHex(str);
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

    template <unsigned int BITS> std::string base_uint<BITS>::GetHex() const {
        return ArithToUint256(*this).GetHex();
    }

    template <unsigned int BITS> void base_uint<BITS>::SetHex(const char *psz) {
        *this = UintToArith256(uint256S(psz));
    }

    template <unsigned int BITS>
    void base_uint<BITS>::SetHex(const std::string &str) {
        SetHex(str.c_str());
    }

    template <unsigned int BITS> std::string base_uint<BITS>::ToString() const {
        return (GetHex());
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
    template base_uint<256>::base_uint(const std::string &);
    template base_uint<256> &base_uint<256>::operator<<=(unsigned int);
    template base_uint<256> &base_uint<256>::operator>>=(unsigned int);
    template base_uint<256> &base_uint<256>::operator*=(uint32_t b32);
    template base_uint<256> &base_uint<256>::operator*=(const base_uint<256> &b);
    template base_uint<256> &base_uint<256>::operator/=(const base_uint<256> &b);
    template int base_uint<256>::CompareTo(const base_uint<256> &) const;
    template bool base_uint<256>::EqualTo(uint64_t) const;
    template double base_uint<256>::getdouble() const;
    template std::string base_uint<256>::GetHex() const;
    template std::string base_uint<256>::ToString() const;
    template void base_uint<256>::SetHex(const char *);
    template void base_uint<256>::SetHex(const std::string &);
    template unsigned int base_uint<256>::bits() const;

}

#endif // BSV_ARITH_UINT256_H

