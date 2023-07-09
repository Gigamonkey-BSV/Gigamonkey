// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/number.hpp>
#include <sv/big_int.h>

namespace Gigamonkey {
    
    template <> bool numbers::less<endian::little> (const digits<endian::little> a, const digits<endian::little> b) {
        return bsv::bint::deserialize (std::span<byte> (const_cast<byte*> (a.Data.data ()), a.Data.size ())) <
            bsv::bint::deserialize (std::span<byte> (const_cast<byte*> (b.Data.data ()), b.Data.size ()));
    }
    
    template <> bool numbers::greater<endian::little> (const digits<endian::little> a, const digits<endian::little> b) {
        return bsv::bint::deserialize (std::span<byte> (const_cast<byte*> (a.Data.data ()), a.Data.size ())) >
            bsv::bint::deserialize (std::span<byte> (const_cast<byte*> (b.Data.data ()), b.Data.size ()));
    }
    
    template <> bool numbers::less_equal<endian::little> (const digits<endian::little> a, const digits<endian::little> b) {
        return bsv::bint::deserialize (std::span<byte> (const_cast<byte*> (a.Data.data ()), a.Data.size ())) <=
            bsv::bint::deserialize (std::span<byte> (const_cast<byte*> (b.Data.data ()), b.Data.size ()));
    }
    
    template <> bool numbers::greater_equal<endian::little> (const digits<endian::little> a, const digits<endian::little> b) {
        return bsv::bint::deserialize (std::span<byte> (const_cast<byte*> (a.Data.data ()), a.Data.size ())) >=
            bsv::bint::deserialize (std::span<byte> (const_cast<byte*> (b.Data.data ()), b.Data.size ()));
    }
    
    template <> std::vector<byte> numbers::plus<endian::little> (const digits<endian::little> a, const digits<endian::little> b) {
        return (bsv::bint::deserialize (std::span<byte> (const_cast<byte*> (a.Data.data ()), a.Data.size ())) +
            bsv::bint::deserialize (std::span<byte> (const_cast<byte*> (b.Data.data ()), b.Data.size ()))).serialize ();
    }
    
    template <> std::vector<byte> numbers::times<endian::little> (const digits<endian::little> a, const digits<endian::little> b) {
        return (bsv::bint::deserialize (std::span<byte> (const_cast<byte*> (a.Data.data ()), a.Data.size ())) *
            bsv::bint::deserialize (std::span<byte> (const_cast<byte*> (b.Data.data ()), b.Data.size ()))).serialize ();
    }
    
    template <> bool numbers::less<endian::big> (const digits<endian::big> a, const digits<endian::big> b) {
        bytes A (a.Data.size ());
        bytes B (b.Data.size ());
        std::copy(a.begin(), a.end(), A.rbegin ());
        std::copy(b.begin(), b.end(), B.rbegin ());
        
        return integer<endian::little>::less (A, B);
    }
    
    template <> bool numbers::greater<endian::big> (const digits<endian::big> a, const digits<endian::big> b) {
        bytes A (a.Data.size ());
        bytes B (b.Data.size ());
        std::copy (a.begin (), a.end (), A.rbegin ());
        std::copy (b.begin (), b.end (), B.rbegin ());
        
        return integer<endian::little>::greater (A, B);
    }
    
    template <> bool numbers::less_equal<endian::big> (const digits<endian::big> a, const digits<endian::big> b) {
        bytes A (a.Data.size ());
        bytes B (b.Data.size ());
        std::copy (a.begin(), a.end(), A.rbegin());
        std::copy (b.begin(), b.end(), B.rbegin());
        
        return integer<endian::little>::less_equal (A, B);
    }
    
    template <> bool numbers::greater_equal<endian::big> (const digits<endian::big> a, const digits<endian::big> b) {
        bytes A (a.Data.size ());
        bytes B (b.Data.size ());
        std::copy (a.begin (), a.end (), A.rbegin ());
        std::copy (b.begin (), b.end (), B.rbegin ());
        
        return integer<endian::little>::greater_equal (A, B);
    }
    
    template <> std::vector<byte> numbers::plus<endian::big> (const digits<endian::big> a, const digits<endian::big> b) {
        bytes A (a.Data.size ());
        bytes B (b.Data.size ());
        std::copy (a.begin (), a.end (), A.rbegin ());
        std::copy (b.begin (), b.end (), B.rbegin ());
        
        std::vector<byte> X = integer<endian::little>::plus (A, B);
        std::reverse (X.begin (), X.end ());
        return X;
    }
    
    template <> std::vector<byte> numbers::times<endian::big> (const digits<endian::big> a, const digits<endian::big> b) {
        bytes A (a.Data.size ());
        bytes B (b.Data.size ());
        std::copy (a.begin(), a.end(), A.rbegin ());
        std::copy (b.begin(), b.end(), B.rbegin ());
        
        std::vector<byte> X = integer<endian::little>::times (A, B);
        std::reverse (X.begin(), X.end ());
        return X;
    }
}
