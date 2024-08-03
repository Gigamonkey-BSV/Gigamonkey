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

        // bitcoin uses two kinds of numbers.
        // Fixed-size unsigned, little endian
        template <size_t size> using uint = uint_little<size>;

        // and arbitrary size integers, little endian two's complement.
        using integer = Z_bytes_twos_little;

        template <size_t size> size_t inline serialized_size (const uint<size> &u) {
            size_t last_0 = 0;
            for (size_t i = 0; i < size; i++) if (u[i] != 0x00) last_0 = i + 1;
            return last_0 == 0 ? 1 : u[last_0 - 1] & 0x80 ? last_0 + 2 : last_0 + 1;
        }

        template <size_t size> size_t inline serialized_size (const integer &i) {
            return i.size ();
        }
    }
    
    using JSON = nlohmann::json;
    
    template <typename X> using nonzero = data::math::nonzero<X>;
    
    template <size_t size>
    using slice = data::slice<byte, size>;
    
    using writer = data::writer<byte>;
    using reader = data::reader<byte>;
    
    using bytes_writer = data::iterator_writer<bytes::iterator, byte>;
    using bytes_reader = data::iterator_reader<const byte*, byte>;
    
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
        bytes_writer w {x.begin (), x.end ()};
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
    
    // lazy bytes writer can be used without knowing the size
    // of the data to be written beforehand.
    struct lazy_bytes_writer : data::writer<byte> {
        list<bytes> Bytes;

        void write (const byte* b, size_t size) override {
            Bytes = Bytes << bytes (bytes_view {b, size});
        }

        operator bytes () const {
            size_t size = 0;
            for (const bytes &b : Bytes) size += b.size ();
            bytes z (size);
            bytes_writer w {z.begin (), z.end ()};
            for (const bytes &b : Bytes) w << b;
            return z;
        }
    };
    
}
/*
namespace std {
    // See Effective C++ Third Edition Item 25 "Consider Support for a non-throwing Swap"
    template <> void inline swap<Gigamonkey::Bitcoin::integer> (Gigamonkey::Bitcoin::integer &a, Gigamonkey::Bitcoin::integer &b) noexcept {
        Gigamonkey::Bitcoin::integer i = a;
        a = b;
        b = i;
    }
}*/

#endif
