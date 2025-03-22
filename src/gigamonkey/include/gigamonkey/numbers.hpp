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

    bool nonzero (bytes_view b);

    template <size_t size> size_t serialized_size (const uint<size> &u);

    size_t serialized_size (const integer &i);

    // implements OP_AND
    integer bit_and (bytes_view, bytes_view);

    // implements OP_XOR
    integer bit_xor (bytes_view, bytes_view);

    // implements OP_OR
    integer bit_or (bytes_view, bytes_view);

    // concatinate, implements OP_CAT
    integer cat (bytes_view, bytes_view);
    data::string cat (string_view, string_view);

    // implements OP_LEFT
    // take the n leftmost bytes from the given string.
    bytes_view left (bytes_view, size_t n);
    string_view left (string_view, size_t n);

    // implements OP_RIGHT
    // take the n rightmost bytes from the given string.
    bytes_view right (bytes_view, size_t n);
    string_view right (string_view, size_t n);

    // implements OP_SPLIT
    std::pair<bytes_view, bytes_view> split (bytes_view, size_t);
    std::pair<string_view, string_view> split (string_view, size_t);

    // shift right by n bits, implements OP_RSHIFT
    integer right_shift (bytes_view, int32 n);

    // shift left by n bits, implements OP_LSHIFT
    integer left_shift (bytes_view, int32 n);

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

    // implements OP_LEFT
    // take the n leftmost bytes from the given string.
    bytes_view inline left (bytes_view x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return x.substr (n);
    }

    // implements OP_RIGHT
    // take the n rightmost bytes from the given string.
    bytes_view inline right (bytes_view x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return x.substr (x.size () - n, x.size ());
    }

    string_view inline left (string_view x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return x.substr (n);
    }

    string_view inline right (string_view x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return x.substr (x.size () - n, x.size ());
    }

    // implements OP_SPLIT
    std::pair<bytes_view, bytes_view> inline split (bytes_view x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return {x.substr (n), x.substr (x.size () - n, x.size ())};
    }

    std::pair<string_view, string_view> inline split (string_view x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return {x.substr (n), x.substr (x.size () - n, x.size ())};
    }
}

#endif
