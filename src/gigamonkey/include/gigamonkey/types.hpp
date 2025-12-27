// Copyright (c) 2019-2020 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_TYPES
#define GIGAMONKEY_TYPES

#include <string>
#include <string_view>
#include <array>

#include <boost/endian/conversion.hpp>

#include <data/stream.hpp>
#include <data/dispatch.hpp>
#include <data/string.hpp>
#include <data/numbers.hpp>
#include <data/math.hpp>
#include <data/fold.hpp>
#include <data/lift.hpp>
#include <data/encoding/hex.hpp>
#include <data/math/nonzero.hpp>

inline bool implies (bool a, bool b) {
    return (!a) || b;
}

namespace Gigamonkey {

    namespace encoding = data::encoding;

    using float64 = data::float64;

    using byte = data::byte;
    using uint16 = data::uint16;
    using uint32 = data::uint32;
    using uint64 = data::uint64;

    using int16 = data::int16;
    using int32 = data::int32;
    using int64 = data::int64;

    // bitcoin uses two kinds of numbers.
    // Fixed-size unsigned, little endian
    template <size_t size> using uint = data::uint_little<size>;
    template <size_t size> using uint_little = data::uint_little<size>;
    using uint160 = uint<20>;
    using uint256 = uint<32>;
    using uint512 = uint<64>;

    using uint16_little = data::uint16_little;
    using uint24_little = data::uint24_little;
    using uint32_little = data::uint32_little;
    using uint64_little = data::uint64_little;

    using uint32_big = data::uint32_big;
    using uint64_big = data::uint64_big;

    using int32_little = data::int32_little;
    using int64_little = data::int64_little;

    using int32_big = data::int32_big;

    using bytes = data::bytes;
    template <std::unsigned_integral word, size_t size> using bytes_array = data::bytes_array<word, size>;
    template <size_t size> using byte_array = bytes_array<byte, size>;

    using string = data::string;

    using byte_slice = data::byte_slice;
    using string_view = data::string_view;
    
    namespace Bitcoin {

        using index = uint32_little;

        using script = bytes;

        using nonce = uint32_little;

        enum class net {Invalid, Main, Test};

        using check = bytes_array<byte, 4>;

    }
    
    template <typename X> using nonzero = data::math::nonzero<X>;

    template <typename X> using stack = data::stack<X>;
    template <typename X> using list = data::list<X>;
    template <typename X> using ordst = data::ordered_sequence<X>;
    template <typename X> using set = data::set<X>;
    template <typename K, typename V> using entry = data::entry<K, V>;
    template <typename K, typename V> using map = data::map<K, V>;
    template <typename K, typename V> using dispatch = data::dispatch<K, V>;

    template <typename X> using ptr = data::ptr<X>;

    template <typename X> using maybe = data::maybe<X>;
    template <typename ... X> using either = data::either<X...>;

    template <typename X> using cross = data::cross<X>;

    using N = data::N;
    using Z = data::Z;

    using exception = data::exception;
    
    template <std::integral word, size_t ...size> using slice = data::slice<word, size...>;

    using writer = data::writer<byte>;
    using reader = data::reader<byte>;
    
    template <typename X>
    writer inline &write (writer &b, X x) {
        return b << x;
    }
    
    template <typename X, typename ... P>
    writer inline &write (writer &b, X &&x, P &&...p) {
        return write (write (b, std::forward<X> (x)), std::forward<P> (p)...);
    }

    template <typename word, typename it> using it_wtr = data::iterator_writer<word, it>;
    template <typename it> using it_rdr = data::iterator_reader<it>;

    template <typename ... P> inline bytes write (size_t size, P &&...p) {
        bytes x (size);
        it_wtr w {x.begin (), x.end ()};
        write (w, std::forward<P> (p)...);
        return x;
    }
    
    template <typename X>
    writer inline &write (writer &b, list<X> ls) {
        while (!empty (ls)) {
            b << first (ls);
            ls = rest (ls);
        }
        return b;
    }
    
}

#endif
