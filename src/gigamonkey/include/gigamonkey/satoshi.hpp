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
        explicit satoshi (uint64_little x);
        satoshi (): int64_little {0} {}
        
        bool valid () const {
            return *this >= 0 && *this < 2100000000000000;
        }
        
        satoshi operator + (satoshi x) const;
        satoshi operator - (satoshi x) const;
        satoshi operator - () const;
    };
    
    inline satoshi::satoshi (uint64_little x) {
        std::copy (x.begin (), x.end (), int64_little::begin ());
    }
        
    satoshi inline satoshi::operator + (satoshi x) const {
        return static_cast<int64_little>(*this) + static_cast<int64_little> (x);
    }
    
    satoshi inline satoshi::operator - (satoshi x) const {
        return static_cast<int64_little> (*this) - static_cast<int64_little> (x);
    }
    
    satoshi inline satoshi::operator - () const {
        return satoshi {-static_cast<int64_little> (*this)};
    }

}

namespace Gigamonkey {
    struct satoshis_per_byte {
        Bitcoin::satoshi Satoshis;
        uint64 Bytes;

        satoshis_per_byte (): Satoshis {}, Bytes {0} {}
        satoshis_per_byte (Bitcoin::satoshi sats, uint64 bytes): Satoshis {sats}, Bytes {bytes} {}

        operator double () const;
        bool valid () const;
    };

    std::weak_ordering inline operator <=> (const satoshis_per_byte &a, const satoshis_per_byte &b);

    bool operator == (const satoshis_per_byte &a, const satoshis_per_byte &b);

    // given a tx size, what fee should we pay?
    Bitcoin::satoshi inline calculate_fee (satoshis_per_byte v, uint64 size) {
        if (v.Bytes == 0) throw data::math::division_by_zero {};
        return std::ceil (double (v.Satoshis) * double (size) / double (v.Bytes));
    }

    inline satoshis_per_byte::operator double () const {
        if (Bytes == 0) throw data::math::division_by_zero {};
        return double (Satoshis) / double (Bytes);
    }

    bool inline satoshis_per_byte::valid () const {
        return Bytes != 0;
    }

    std::weak_ordering inline operator <=> (const satoshis_per_byte &a, const satoshis_per_byte &b) {
        return data::math::fraction<int64> (int64 (a.Satoshis), a.Bytes) <=>
            data::math::fraction<int64> (int64 (b.Satoshis), b.Bytes);
    }

    bool inline operator == (const satoshis_per_byte &a, const satoshis_per_byte &b) {
        return data::math::fraction<int64> (int64 (a.Satoshis), a.Bytes) ==
            data::math::fraction<int64> (int64 (b.Satoshis), b.Bytes);
    }
}

namespace data::math {
    
    template <> struct identity<plus<Gigamonkey::Bitcoin::satoshi>, Gigamonkey::Bitcoin::satoshi> {
        Gigamonkey::Bitcoin::satoshi operator () () {
            return {0};
        }
    };
    
    template <> struct inverse<plus<Gigamonkey::Bitcoin::satoshi>, Gigamonkey::Bitcoin::satoshi> {
        Gigamonkey::Bitcoin::satoshi operator () (const Gigamonkey::Bitcoin::satoshi &a, const Gigamonkey::Bitcoin::satoshi &b) {
            return b - a;
        }
    };
}

#endif
