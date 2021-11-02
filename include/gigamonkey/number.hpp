// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_NUMBER
#define GIGAMONKEY_NUMBER

#include <gigamonkey/types.hpp>
#include <data/math/number/rational.hpp>
#include <data/math/octonian.hpp>

namespace Gigamonkey::Bitcoin {
    
    struct N;
    struct Z;
    
    bool operator==(const Z&, const Z&);
    bool operator!=(const Z&, const Z&);
    bool operator<=(const Z&, const Z&);
    bool operator>=(const Z&, const Z&);
    bool operator<(const Z&, const Z&);
    bool operator>(const Z&, const Z&);
    
    struct Z : public bytes {
        
        // a number is minimally encoded if it does not end in 00 or 0080
        static bool is_minimally_encoded(const bytes_view b);
        
        static bool is_zero(const bytes_view b);
        static bool is_positive_zero(const bytes_view b);
        static bool is_negative_zero(const bytes_view b);
        
        static bool sign_bit(bytes_view b);
        
        static data::math::sign sign(bytes_view b);
        
        static bool is_positive(bytes_view b);
        static bool is_negative(bytes_view b);
        
        // shorted to be minimally encoded. 
        static bytes trim(bytes_view b);
        
        static bool equal(bytes_view a, bytes_view b);
        
        static bool unequal(bytes_view a, bytes_view b);
        
        bytes abs(bytes_view b);
        
        bytes minus(bytes_view b);
        
        static bool greater(bytes_view a, bytes_view b);
        static bool less(bytes_view a, bytes_view b);
        static bool greater_equal(bytes_view a, bytes_view b);
        static bool less_equal(bytes_view a, bytes_view b);
        
        static bytes plus(bytes_view a, bytes_view b);
        static bytes minus(bytes_view a, bytes_view b);
        static bytes times(bytes_view a, bytes_view b);
        static bytes shift(bytes_view a, int x);
        
        Z() : bytes{} {}
        Z(int64 z);
        explicit Z(bytes_view b) : bytes{b} {}
        explicit Z(const string& x);
        
        N abs() const;
    
        Z operator-();
        
        Z operator+(const Z&);
        Z operator-(const Z&);
        Z operator*(const Z&);
        
    private:
        explicit Z(bytes&& b) : bytes{b} {}
    };
    
    struct N : bytes {
        N() : bytes{} {}
        
        operator Z() const {
            return Z{bytes_view(*this)};
        }
        
        N operator+(const N&);
        N operator-(const N&);
        N operator*(const N&);
        
        N(uint64 z);
        
    private:
        N(bytes_view b) : bytes{b} {}
        N(bytes&& b) : bytes{b} {}
        
        friend struct Z;
    };
    
    using Q = data::math::fraction<Z, N>;
    
    // Gaussian numbers (complex rationals)
    using G = data::math::complex<Q>;
        
    // rational quaternions
    using H = data::math::quaternion<Q>;
        
    // rational octonions
    using O = data::math::octonion<Q>;
    
    bool inline Z::equal(bytes_view a, bytes_view b) {
        return trim(a) == trim(b);
    }
    
    bool inline Z::unequal(bytes_view a, bytes_view b) {
        return trim(a) != trim(b);
    }
    
    data::math::sign inline Z::sign(bytes_view b) {
        return is_zero(b) ? data::math::zero : sign_bit(b) ? data::math::negative : data::math::positive;
    }
    
    bool inline Z::is_positive(bytes_view b) {
        return sign(b) == data::math::positive;
    }
    
    bool inline Z::is_negative(bytes_view b) {
        return sign(b) == data::math::negative;
    }
    
    bool inline operator==(const Z &a, const Z &b) {
        return Z::equal(a, b);
    }
    
    bool inline operator!=(const Z &a, const Z &b) {
        return Z::unequal(a, b);
    }
    
    bool inline operator<=(const Z &a, const Z &b) {
        return Z::greater_equal(a, b);
    }
    
    bool inline operator>=(const Z &a, const Z &b) {
        return Z::less_equal(a, b);
    }
    
    bool inline operator<(const Z &a, const Z &b) {
        return Z::greater(a, b);
    }
    
    bool inline operator>(const Z &a, const Z &b) {
        return Z::less(a, b);
    }
    
    Z inline Z::operator-() {
        return Z(minus(*this));
    }
    
    Z inline Z::operator+(const Z &z) {
        return Z(plus(*this, z));
    }
    
    Z inline Z::operator-(const Z &z) {
        return Z(minus(*this, z));
    }
    
    Z inline Z::operator*(const Z &z) {
        return Z(times(*this, z));
    }
        
    N inline N::operator+(const N &n) {
        return Z::plus(*this, n);
    }
    
    N inline N::operator-(const N &n) {
        if (n > *this) return N{};
        return Z::minus(*this, n);
    }
    
    N inline N::operator*(const N &n) {
        return Z::times(*this, n);
    }
    
}

#endif


