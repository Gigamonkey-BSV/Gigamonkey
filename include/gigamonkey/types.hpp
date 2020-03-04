// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TYPES
#define GIGAMONKEY_TYPES

#include <string>
#include <string_view>
#include <array>

#include <data/stream.hpp>

#include <data/data.hpp>

inline bool implies(bool a, bool b) {
    return (!a) || b;
}

namespace Gigamonkey {
    
    using namespace data;
    
    using endian = boost::endian::order;
    
    const endian BigEndian = boost::endian::order::big;
    const endian LittleEndian = boost::endian::order::little;
    
    constexpr inline endian opposite_endian(endian e) {
        return e == BigEndian ? LittleEndian : BigEndian;
    }
    
    using checksum = uint32_little;
    
    using index = uint32_little;
    
    using script = bytes;
    
    // in the protocol, satoshi amounts are written as uint64_littles. 
    // However, we need to be able to think in terms of negative amounts
    // for accounting purposes. 
    using satoshi = boost::endian::native_int64_t;
    
    using nonce = uint32_little;
    
    template <typename X>
    struct nonzero : data::math::nonzero<X> {
        
        nonzero(const X& x) : data::math::nonzero<X>{x} {}
        nonzero() : data::math::nonzero<X>{} {}
        
        bool operator<(const nonzero& n) const {
            return data::math::nonzero<X>::operator<(n.Value);
        }
        
        bool operator>(const nonzero& n) const {
            return data::math::nonzero<X>::operator>(n.Value);
        }
        
        bool operator<=(const nonzero& n) const {
            return data::math::nonzero<X>::operator<=(n.Value);
        }
        
        bool operator>=(const nonzero& n) const {
            return data::math::nonzero<X>::operator>=(n.Value);
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

#endif
