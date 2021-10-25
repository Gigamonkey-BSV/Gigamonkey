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
    
    using N = data::math::number::gmp::N;
    
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
    
}

namespace Gigamonkey::Bitcoin {
    
    using writer = bytes_writer;
    using reader = bytes_reader;
    
}

#endif
