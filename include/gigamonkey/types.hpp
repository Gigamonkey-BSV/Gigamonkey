// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TYPES
#define GIGAMONKEY_TYPES

#include <string>
#include <string_view>
#include <array>

#include <boost/endian/conversion.hpp>

#include <data/stream.hpp>

#include <data/data.hpp>

inline bool implies(bool a, bool b) {
    return (!a) || b;
}

namespace Gigamonkey {
    
    using namespace data;
    
    using checksum = uint32_little;
    
    using index = uint32_little;
    
    using script = bytes;
    
    // in the protocol, satoshi amounts are written as uint64_littles. 
    // However, we need to be able to think in terms of negative amounts
    // for accounting purposes. 
    using satoshi = boost::endian::native_int64_t;
    
    using nonce = uint32_little;
    
    enum chain : byte {test, main};
    
    template <typename X> 
    struct nonzero : data::math::nonzero<X> {
        
        nonzero(const X& x) : data::math::nonzero<X>{x} {}
        nonzero() : data::math::nonzero<X>{} {}
        
        bool operator<(const X& n) const {
            return data::math::nonzero<X>::Value < n;
        }
        
        bool operator>(const X& n) const {
            return data::math::nonzero<X>::Value > n;
        }
        
        bool operator<=(const X& n) const {
            return data::math::nonzero<X>::Value <= n;
        }
        
        bool operator>=(const X& n) const {
            return data::math::nonzero<X>::Value >= n;
        }
    };
    
    /*
    template <size_t size>
    using uint = data::uint<size>;
    
    using N_bytes = data::N_bytes<LittleEndian>;
    using Z_bytes = data::Z_bytes<LittleEndian>;*/
    
    template <size_t size>
    using slice = data::slice<byte, size>;
    
    using bytes_writer = data::writer<bytes::iterator>;
    using bytes_reader = data::reader<const byte*>;
    
    using string_writer = data::writer<string::iterator>;
    using string_reader = data::reader<const char*>;
    
    template <typename X> bytes_writer 
    inline write(bytes_writer b, X x) {
        return b << x;
    }
    
    template <typename X, typename ... P> 
    inline bytes_writer write(bytes_writer b, X x, P... p) {
        return write(write(b, x), p...);
    }
    
    template <typename ... P> inline bytes write(size_t size, P... p) {
        bytes x(size);
        write(bytes_writer{x.begin(), x.end()}, p...);
        return x;
    }
    
    template <typename X>  
    inline bytes_writer write(bytes_writer b, list<X> ls) {
        while(!ls.empty()) {
            b = b << ls.first();
            ls = ls.rest();
        }
        return b;
    }
    
}

inline Gigamonkey::bytes_writer operator<<(Gigamonkey::bytes_writer w, const Gigamonkey::satoshi& s) {
    return w << data::int64_little(s);
}

inline Gigamonkey::bytes_reader operator>>(Gigamonkey::bytes_reader r, Gigamonkey::satoshi& s) {
    Gigamonkey::uint64_little x;
    r = r >> x;
    s = static_cast<int64_t>(uint64_t(x));
    return r;
}

template <typename X> 
std::ostream& operator<<(std::ostream& o, const data::list<X> s) {
    o << "[";
    if (!s.empty()) {
        data::list<X> x = s;
        o << x.first();
        x = x.rest();
        while (!x.empty()) {
            o << ", ";
            o << x.first();
            x = x.rest();
        }
    }
    return o << "]";
}

#endif
