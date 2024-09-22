// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_NUMBERS
#define GIGAMONKEY_NUMBERS

#include <gigamonkey/types.hpp>

namespace Gigamonkey::Bitcoin {

    // bitcoin uses two kinds of numbers.
    // Fixed-size unsigned, little endian
    template <size_t size> using uint = uint_little<size>;

    // and arbitrary size integers, little endian two's complement.
    using integer = Z_bytes_twos_little;

    bool inline nonzero (bytes_view b) {
        if (b.size () == 0) return false;
        for (int i = 0; i < b.size () - 1; i++) if (b[i] != 0) return true;
        return b[b.size () - 1] != 0 && b[b.size () - 1] != 0x80;
    }

    template <size_t size> size_t inline serialized_size (const uint<size> &u) {
        size_t last_0 = 0;
        for (size_t i = 0; i < size; i++) if (u[i] != 0x00) last_0 = i + 1;
        return last_0 == 0 ? 1 : u[last_0 - 1] & 0x80 ? last_0 + 2 : last_0 + 1;
    }

    size_t inline serialized_size (const integer &i) {
        return i.size ();
    }

    // shift x right by n bits, implements OP_RSHIFT
    integer right_shift (bytes_view, int32 n);

    // shift x left by n bits, implements OP_LSHIFT
    integer left_shift (bytes_view, int32 n);
}

#endif
