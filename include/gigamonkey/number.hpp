// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_NUMBER
#define GIGAMONKEY_NUMBER

#include <gigamonkey/hash.hpp>
#include <data/math/number/rational.hpp>
#include <data/math/octonian.hpp>
#include <data/math/number/integer.hpp>
#include <data/encoding/halves.hpp>

namespace Gigamonkey {
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
}

namespace Gigamonkey {
    
    template <endian::order r> struct integer final : public bytes {
        
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
        
        math::division<integer> divide(const integer&) const;
        
        integer operator/(const integer&) const;
        integer operator%(const integer&) const;
        
        static bytes shift(bytes_view a, int);
        
        integer operator<<(int) const;
        integer operator>>(int) const;
        
        integer() : bytes{} {}
        integer(int64 z);
        integer(const uint256&);
        explicit integer(bytes_view b) : bytes{b} {}
        explicit integer(string_view x);
        explicit integer(const integer<endian::opposite(r)>&);
        
    private:
        explicit integer(bytes&& b) : bytes{b} {}
        data::arithmetic::digits<r> digits();
    };
    
    template <endian::order r> 
    struct natural final : bytes {
        
        bool minimal() const;
        
        bool is_zero() const;
        bool is_positive_zero() const;
        bool is_negative_zero() const;
        
        bool sign_bit() const;
        
        data::math::sign sign() const;
        
        bool is_positive() const;
        bool is_negative() const;
        
        natural trim() const;
        
        natural() : bytes{} {}
        
        operator integer<r>() const {
            return integer<r>{bytes_view(*this)};
        }
        
        natural operator+(const natural&) const;
        natural operator-(const natural&) const;
        natural operator*(const natural&) const;
        
        math::division<natural> divide(const natural&) const;
        
        natural operator/(const natural&) const;
        natural operator%(const natural&) const;
        
        natural operator<<(int) const;
        natural operator>>(int) const;
        
        natural(uint64 z);
        natural(const uint256&);
        explicit natural(string_view x);
        explicit natural(const natural<endian::opposite(r)>&);
        
    private:
        natural(bytes_view b) : bytes{b} {}
        natural(bytes&& b) : bytes{b} {}
        
        friend struct integer<r>;
        data::arithmetic::digits<r> digits();
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
        return integer<r>::plus(*this, n);
    }
    
    template <endian::order r> natural<r> inline natural<r>::operator-(const natural &n) const {
        if (n > *this) return natural{};
        return integer<r>::minus(*this, n);
    }
    
    template <endian::order r> natural<r> inline natural<r>::operator*(const natural &n) const {
        return integer<r>::times(*this, n);
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
    
    template <endian::order r> bool inline natural<r>::minimal() const {
        return integer<r>::minimal(*this);
    }
    
    template <endian::order r> bool inline natural<r>::is_zero() const {
        return integer<r>::is_zero(*this);
    }
    
    template <endian::order r> bool inline natural<r>::is_positive_zero() const {
        return integer<r>::is_positive_zero(*this);
    }
    
    template <endian::order r> bool inline natural<r>::is_negative_zero() const {
        return integer<r>::is_negative_zero(*this);
    }
    
    template <endian::order r> bool inline natural<r>::sign_bit() const {
        return integer<r>::sign_bit(*this);
    }
    
    template <endian::order r> data::math::sign inline natural<r>::sign() const {
        return integer<r>::sign(*this);
    }
    
    template <endian::order r> bool inline natural<r>::is_positive() const {
        return integer<r>::is_positive(*this);
    }
    
    template <endian::order r> bool inline natural<r>::is_negative() const {
        return false;
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
        if (z.is_zero()) throw math::division_by_zero{};
        return math::number::integer::divide(*this, z);
    }
    
    template <endian::order r> math::division<natural<r>> inline natural<r>::divide(const natural &z) const {
        if (z.is_zero()) throw math::division_by_zero{};
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
        return natural{shift(this->trim(), i)};
    }
    
    template <endian::order r> natural<r> inline natural<r>::operator>>(int i) const {
        if (i == 0) return *this;
        return natural{shift(this->trim(), -i)};
    }
    
    template <endian::order r> inline integer<r>::integer(const integer<endian::opposite(r)>& x) {
        resize(x.size());
        std::copy(x.begin(), x.end(), this->rbegin());
    }
    
    template <endian::order r> inline natural<r>::natural(const natural<endian::opposite(r)>& x) {
        resize(x.size());
        std::copy(x.begin(), x.end(), this->rbegin());
    }
}

#include <data/encoding/integer.hpp>
#include <data/math/number/bytes/N.hpp>
#include <data/encoding/endian/words.hpp>

namespace Gigamonkey {
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
                ptr<data::math::Z_bytes<endian::little>> positive_number; 
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
        
        template <endian::order r> static bytes from_uint256(const uint256& u) {
            bytes b;
            
            bool last_zero;
            if (u.digits()[31] & 0x80) {
                b.resize(33);
                last_zero = true;
            } else {
                b.resize(32);
                last_zero = false;
            }
            
            digits<r> n{data::slice<byte>{b.data(), b.size()}};
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
    
    template <endian::order r> natural<r> inline natural<r>::trim() const {
        if (minimal()) return *this;
        if (is_zero()) return {};
        return natural{numbers::trim_nonminimal_nonzero(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(this->data()), this->size()}})};
    }
    
    template <endian::order r> integer<r> inline integer<r>::trim() const {
        if (minimal()) return *this;
        if (is_zero()) return {};
        return integer{numbers::trim_nonminimal_nonzero(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(this->data()), this->size()}})};
    }
    
    template <endian::order r> bytes inline integer<r>::abs(bytes_view b) {
        if (!is_negative(b)) return trim(b);
        return numbers::abs_positive(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(b.data()), b.size()}});
    }
    
    template <endian::order r> natural<r> inline integer<r>::abs() const {
        if (!is_negative()) return trim();
        return numbers::abs_positive(numbers::digits<r>{data::slice<byte>{const_cast<byte*>(this->data()), this->size()}});
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
    
    template <endian::order r> inline integer<r>::integer(const uint256& x) : bytes{numbers::from_uint256<r>(x)} {}
    
    template <endian::order r> inline natural<r>::natural(uint64 z) : bytes{numbers::from_uint<r>(z)} {}
    
    template <endian::order r> inline natural<r>::natural(string_view x) : bytes{numbers::from_string<r>(x)} {
        if (integer<r>::is_negative(*this)) throw std::logic_error{"invalid string representation"};
    }
    
    template <endian::order r> inline natural<r>::natural(const uint256& x) : bytes{numbers::from_uint256<r>(x)} {}
    
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
    
}

#endif


