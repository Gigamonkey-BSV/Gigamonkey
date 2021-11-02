// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/number.hpp>
#include <data/encoding/integer.hpp>
#include <data/math/number/bytes/N.hpp>

namespace Gigamonkey::Bitcoin {
    
    // a number is minimally encoded if it does not end in 00 or 0080
    bool Z::is_minimally_encoded(const bytes_view b) {
        size_t size = b.size();
        if (size == 0) return true;
        byte last = b[size - 1];
        if (last == 0x00) return false;
        if (last == 0x80) {
            if (size == 1) return false;
            return b[size - 2] & 0x80;
        }
        return true;
    }
    
    bool Z::is_zero(const bytes_view b) {
        size_t size = b.size();
        if (size == 0) return true;
        for (int i = 0; i < size - 1; i++) {
            if (b[i] != 0x00) return false;
        }
        byte last = b[size - 1];
        return (last == 0x00 || last == 0x80);
    }
    
    bool Z::is_positive_zero(const bytes_view b) {
        size_t size = b.size();
        if (size == 0) return true;
        for (int i = 0; i < size; i++) {
            if (b[i] != 0x00) return false;
        }
        return true;
    }
    
    bool Z::is_negative_zero(const bytes_view b) {
        size_t size = b.size();
        if (size == 0) return false;
        for (int i = 0; i < size - 1; i++) {
            if (b[i] != 0x00) return false;
        }
        return b[size - 1] == 0x80;
    }
    
    bool Z::sign_bit(bytes_view b) {
        size_t size = b.size();
        if (size == 0) return false;
        return b[size - 1] & 0x80;
    }
    
    bytes Z::trim(bytes_view b) {
        if (is_minimally_encoded(b)) return bytes{b};
        if (is_zero(b)) return bytes{};
        // size will necessarily be greater than 1;
        size_t size = b.size();
        // this will be either 0x00 or 0x80
        byte last = b[size - 1];
        size_t last_nonzero = size - 2;
        // this will not overflow. 
        while(b[last_nonzero] != 0x00) last_nonzero--;
        bool last_nonzero_sign_bit = b[last_nonzero] & 0x80;
        size_t new_size = last_nonzero + (last_nonzero_sign_bit ? 2 : 1);
        bytes new_number{};
        new_number.resize(new_size);
        std::copy(b.begin(), b.begin() + new_size, new_number.begin());
        if (last_nonzero_sign_bit) new_number[last_nonzero + 1] = last;
        else new_number[last_nonzero] += last;
        return new_number;
    }
    
    bytes Z::abs(bytes_view b) {
        if (!is_negative(b)) return trim(b);
        bytes new_number{b};
        // size is necessarily greater than zero
        new_number[b.size() - 1] &= 0x7f;
        return trim(new_number);
    }
    
    bytes Z::minus(bytes_view b) {
        if (is_zero(b)) return bytes{};
        bytes new_number{b};
        byte last = new_number[b.size() - 1];
        if (last & 0x80) new_number[b.size() - 1] &= 0x7f;
        else new_number[b.size() - 1] += 0x80;
        return new_number;
    }
    
    Z::Z(int64 z) : bytes{} {
        if (z == 0) return;
        
        bool negative = z < 0;
        uint64_little lil = negative ? -z : z;
        
        int last_nonzero_digit = -1;
        for (int i = 0; i < lil.size(); i++) if (lil[i] != 0) last_nonzero_digit = i;
        
        bool last_digit_sign_bit = last_nonzero_digit >= 0 && lil[last_nonzero_digit] & 0x80;
        size_t new_size = last_nonzero_digit + (last_digit_sign_bit ? 2 : 1);
        resize(new_size);
        
        std::copy(lil.begin(), lil.begin() + last_nonzero_digit + 1, this->begin());
        if (last_digit_sign_bit) (*this)[last_nonzero_digit + 1] = negative ? 0x80 : 0x00;
        else if (negative) (*this)[last_nonzero_digit] += 0x80;
    }
    
    Z::Z(const string& x) {
        auto hex = data::encoding::hex::read(x);
        if (hex != nullptr) {
            bytes::resize(hex->size());
            std::copy(hex->begin(), hex->end(), this->begin());
            return;
        } 
        
        auto hexidecimal = data::encoding::hexidecimal::read<endian::little>(x);
        if (hexidecimal != nullptr) {
            bytes::resize(hexidecimal->size());
            std::copy(hexidecimal->begin(), hexidecimal->end(), this->begin());
            return;
        }
        
        if (data::encoding::integer::valid(x)) {
            ptr<data::math::Z_bytes<endian::little>> positive_number; 
            bool negative = data::encoding::integer::negative(x);
            positive_number = negative ? 
                data::encoding::integer::read<endian::little>(x.substr(1)) : 
                data::encoding::integer::read<endian::little>(x);
            
            bytes::resize(positive_number->size());
            std::copy(positive_number->begin(), positive_number->end(), this->begin());
            if (negative) *this = -*this;
            return;
        }
        
        throw std::logic_error{"Invalid string representation"};
    }
    
}
