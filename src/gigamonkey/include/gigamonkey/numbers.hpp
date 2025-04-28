// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_NUMBERS
#define GIGAMONKEY_NUMBERS

#include <gigamonkey/types.hpp>
#include <gigamonkey/script/error.h>

namespace Gigamonkey::Bitcoin {

    // and arbitrary size integers, little endian two's complement.
    using integer = data::Z_bytes_BC_little;

    size_t minimal_number_size (bytes_view);

    bool is_minimal_number (bytes_view);
    bytes &extend_number (bytes &, size_t size);

    // trim to minimal size;
    bytes &trim_number (bytes &);

    static const size_t MAXIMUM_ELEMENT_SIZE = 4;

    const integer &read_integer (const bytes &span, bool RequireMinimal, const size_t nMaxNumSize = MAXIMUM_ELEMENT_SIZE);

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

    template <size_t size> size_t inline serialized_size (const uint_little<size> &u) {
        size_t last_0 = 0;
        for (size_t i = 0; i < size; i++) if (u[i] != 0x00) last_0 = i + 1;
        return last_0 == 0 ? 1 : u[last_0 - 1] & 0x80 ? last_0 + 2 : last_0 + 1;
    }

    size_t inline serialized_size (const integer &i) {
        return i.size ();
    }

    size_t inline minimal_number_size (bytes_view b) {
        return data::arithmetic::minimal_size<data::endian::little, data::arithmetic::complement::BC, byte> (b);
    }

    const integer inline &read_integer (const bytes &span, bool RequireMinimal, const size_t nMaxNumSize) {

        if (span.size () > nMaxNumSize) throw script_exception {SCRIPT_ERR_SCRIPTNUM_OVERFLOW};

        if (RequireMinimal && !is_minimal_number (span)) throw script_exception {SCRIPT_ERR_SCRIPTNUM_MINENCODE};

        return static_cast<const integer &> (span);
    }

    bool inline is_minimal_number (bytes_view span) {
        return data::arithmetic::is_minimal<data::endian::little, data::arithmetic::complement::BC, byte> (span);
    }

    bytes inline &extend_number (bytes &rawnum, size_t size) {
        data::arithmetic::extend<data::endian::little, data::arithmetic::complement::BC, byte> (rawnum, size);
        return rawnum;
    }

    bytes inline &trim_number (bytes &num) {
        data::arithmetic::trim<data::endian::little, data::arithmetic::complement::BC, byte> (num);
        return num;
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
        return {x.substr (0, n), x.substr (n + 1)};
    }

    std::pair<string_view, string_view> inline split (string_view x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return {x.substr (0, n), x.substr (n + 1)};
    }
}

#endif
