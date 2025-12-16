// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SATOSHI
#define GIGAMONKEY_SATOSHI

#include <gigamonkey/types.hpp>

namespace Gigamonkey::Bitcoin {
    
    // in the protocol, satoshi amounts are written as uint64_littles. 
    // However, we need to be able to think in terms of negative amounts
    // for accounting purposes. 
    struct satoshi : int64_little {
        using int64_little::int64_little;
        constexpr explicit satoshi (uint64_little x);
        constexpr satoshi (): int64_little {0} {}
        
        constexpr bool valid () const {
            return *this >= 0 && *this < 2100000000000000;
        }
        
        constexpr satoshi operator + (satoshi x) const;
        constexpr satoshi operator - (satoshi x) const;
        constexpr satoshi operator - () const;
    };
    
    constexpr inline satoshi::satoshi (uint64_little x) {
        std::copy (x.begin (), x.end (), int64_little::begin ());
    }
        
    constexpr satoshi inline satoshi::operator + (satoshi x) const {
        return static_cast<int64_little>(*this) + static_cast<int64_little> (x);
    }
    
    constexpr satoshi inline satoshi::operator - (satoshi x) const {
        return static_cast<int64_little> (*this) - static_cast<int64_little> (x);
    }
    
    constexpr satoshi inline satoshi::operator - () const {
        return satoshi {-static_cast<int64_little> (*this)};
    }

}

namespace Gigamonkey {
    struct satoshis_per_byte {
        Bitcoin::satoshi Satoshis;
        uint64 Bytes;

        constexpr satoshis_per_byte (): Satoshis {}, Bytes {0} {}
        constexpr satoshis_per_byte (Bitcoin::satoshi sats, uint64 bytes): Satoshis {sats}, Bytes {bytes} {}

        constexpr operator double () const;
        constexpr bool valid () const;
    };

    constexpr std::weak_ordering inline operator <=> (const satoshis_per_byte &a, const satoshis_per_byte &b);

    constexpr bool operator == (const satoshis_per_byte &a, const satoshis_per_byte &b);

    // given a tx size, what fee should we pay?
    Bitcoin::satoshi inline calculate_fee (satoshis_per_byte v, uint64 size) {
        if (v.Bytes == 0) throw data::math::division_by_zero {};
        return std::ceil (double (v.Satoshis) * double (size) / double (v.Bytes));
    }

    constexpr inline satoshis_per_byte::operator double () const {
        if (Bytes == 0) throw data::math::division_by_zero {};
        return double (Satoshis) / double (Bytes);
    }

    constexpr bool inline satoshis_per_byte::valid () const {
        return Bytes != 0;
    }

    constexpr std::weak_ordering inline operator <=> (const satoshis_per_byte &a, const satoshis_per_byte &b) {
        return int64 (a.Satoshis) * static_cast<int64> (b.Bytes) <=> int64 (b.Satoshis) * static_cast<int64> (a.Bytes);
    }

    constexpr bool inline operator == (const satoshis_per_byte &a, const satoshis_per_byte &b) {
        return int64 (a.Satoshis) * static_cast<int64> (b.Bytes) == int64 (b.Satoshis) * static_cast<int64> (a.Bytes);
    }
}

// Ensure that satoshis form a mathematical ring. I'm not sure we need this.
namespace data::math::def {
    
    template <> struct identity<plus<Gigamonkey::Bitcoin::satoshi>, Gigamonkey::Bitcoin::satoshi> {
        constexpr Gigamonkey::Bitcoin::satoshi operator () () {
            return {0};
        }
    };
    
    template <> struct inverse<plus<Gigamonkey::Bitcoin::satoshi>, Gigamonkey::Bitcoin::satoshi> {
        constexpr Gigamonkey::Bitcoin::satoshi operator () (const Gigamonkey::Bitcoin::satoshi &a, const Gigamonkey::Bitcoin::satoshi &b) {
            return b - a;
        }
    };
}

#endif
