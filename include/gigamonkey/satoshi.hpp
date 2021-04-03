// Copyright (c) 2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SATOSHI
#define GIGAMONKEY_SATOSHI

#include <gigamonkey/types.hpp>

namespace Gigamonkey {
    
    // in the protocol, satoshi amounts are written as uint64_littles. 
    // However, we need to be able to think in terms of negative amounts
    // for accounting purposes. 
    struct satoshi : int64_little {
        using int64_little::int64_little;
        explicit satoshi(uint64_little x);
        
        bool valid() const {
            return *this >= 0 && *this < 2100000000000000;
        }
        
        satoshi operator+(satoshi x) const;
        satoshi operator-(satoshi x) const;
        satoshi operator-() const;
    };

    inline bytes_writer operator<<(bytes_writer w, const satoshi& s) {
        return w << (data::int64_little)(s);
    }

    inline bytes_reader operator>>(bytes_reader r, satoshi& s) {
        uint64_little x;
        r = r >> x;
        s = satoshi(x);
        return r;
    }
    
    inline satoshi::satoshi(uint64_little x) {
        std::copy(x.begin(), x.end(), int64_little::begin());
    }
        
    satoshi inline satoshi::operator+(satoshi x) const {
        return static_cast<int64_little>(*this) - static_cast<int64_little>(x);
    }
    
    satoshi inline satoshi::operator-(satoshi x) const {
        return static_cast<int64_little>(*this) - static_cast<int64_little>(x);
    }
    
    satoshi inline satoshi::operator-() const {
        return satoshi{-static_cast<int64_little>(*this)};
    }

}

#endif
