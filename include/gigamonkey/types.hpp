// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TYPES
#define GIGAMONKEY_TYPES

#include <string>
#include <string_view>
#include <array>

#include <nlohmann/json.hpp>

#include <boost/endian/conversion.hpp>

#include <nlohmann/json.hpp>

#include <data/stream.hpp>
#include <data/tools.hpp>
#include <data/math/nonnegative.hpp>
#include <data/math/number/gmp/N.hpp>
#include <data/encoding/hex.hpp>

inline bool implies(bool a, bool b) {
    return (!a) || b;
}

namespace Gigamonkey {
    
    using namespace data;
    
    using checksum = uint32_little;
    
    using index = uint32_little;
    
    using script = bytes;
    
    using nonce = uint32_little;
    
    enum chain : byte {test, main};
    
    using json = nlohmann::json;
    
    template<typename x> using optional = std::optional<x>;
    
    using ostream = std::ostream;
    
    template <typename X> using nonzero = data::math::nonzero<X>;
    template <size_t size>
    using slice = data::slice<byte, size>;
    
    using bytes_writer = data::writer<bytes::iterator>;
    using bytes_reader = data::reader<const byte*>;
    
    using string_writer = data::writer<string::iterator>;
    using string_reader = data::reader<const char*>;
    
    template <typename X> 
    bytes_writer inline &write(bytes_writer &b, X x) {
        return b << x;
    }
    
    template <typename X, typename ... P> 
    bytes_writer inline &write(bytes_writer &b, X x, P... p) {
        return write(write(b, x), p...);
    }
    
    template <typename ... P> inline bytes write(size_t size, P... p) {
        bytes x(size);
        bytes_writer w{x.begin(), x.end()};
        write(w, p...);
        return x;
    }
    
    template <typename X>  
    bytes_writer inline &write(bytes_writer &b, list<X> ls) {
        while(!ls.empty()) {
            b << ls.first();
            ls = ls.rest();
        }
        return b;
    }
    
    // lazy bytes writer can be used without knowing the size
    // of the data to be written beforehand. 
    struct lazy_bytes_writer {
        list<bytes> Bytes;
        
        lazy_bytes_writer &operator<<(const bytes_view b) {
            Bytes = Bytes << b;
            return *this;
        }
        
        lazy_bytes_writer &operator<<(const byte b) {
            Bytes = Bytes << bytes({b});
            return *this;
        }
    
        template <boost::endian::order Order, bool is_signed, std::size_t bytes>
        lazy_bytes_writer &operator<<(const endian::arithmetic<Order, is_signed, bytes> &x) {
            return operator<<(bytes_view(x));
        }
        
        operator bytes() const {
            size_t size = 0;
            for (const bytes &b : Bytes) size += b.size();
            bytes z(size);
            bytes_writer w{z.begin(), z.end()};
            for (const bytes &b : Bytes) w << b;
            return z;
        }
    };
    
}

namespace Gigamonkey::Bitcoin {
    
    using writer = bytes_writer;
    using reader = bytes_reader;
    
}

#endif
