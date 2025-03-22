// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TYPES
#define GIGAMONKEY_TYPES

#include <string>
#include <string_view>
#include <array>

#include <boost/endian/conversion.hpp>

#include <data/stream.hpp>
#include <data/tools.hpp>
#include <data/numbers.hpp>
#include <data/math.hpp>
#include <data/fold.hpp>
#include <data/for_each.hpp>
#include <data/string.hpp>
#include <data/encoding/hex.hpp>
#include <data/math/nonnegative.hpp>
#include <data/net/JSON.hpp>

inline bool implies (bool a, bool b) {
    return (!a) || b;
}

namespace Gigamonkey {
    
    using namespace data;
    
    namespace Bitcoin {

        using index = uint32_little;

        using script = bytes;

        using nonce = uint32_little;

        enum chain : byte {test, main};

        using check = bytes_array<byte, 4>;

    }
    
    using JSON = nlohmann::json;
    
    template <typename X> using nonzero = data::math::nonzero<X>;
    
    template <size_t size>
    using slice = data::slice<byte, size>;

    using writer = data::writer<byte>;
    using reader = data::reader<byte>;
    
    template <typename X>
    writer inline &write (writer &b, X x) {
        return b << x;
    }
    
    template <typename X, typename ... P>
    writer inline &write (writer &b, X x, P... p) {
        return write (write (b, x), p...);
    }

    template <typename ... P> inline bytes write (size_t size, P... p) {
        bytes x (size);
        iterator_writer w {x.begin (), x.end ()};
        write (w, p...);
        return x;
    }
    
    template <typename X>
    writer inline &write (writer &b, list<X> ls) {
        while (!ls.empty ()) {
            b << ls.first ();
            ls = ls.rest ();
        }
        return b;
    }
    
}

#endif
