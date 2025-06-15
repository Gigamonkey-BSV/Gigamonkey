// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_NUMBERS
#define GIGAMONKEY_NUMBERS

#include <gigamonkey/types.hpp>
#include <gigamonkey/script/error.h>

namespace Gigamonkey::Bitcoin {

    // and arbitrary size integers, little endian two's complement.
    using integer = data::Z_bytes_BC_little;

    size_t minimal_number_size (slice<const byte>);

    bool is_minimal_number (slice<const byte>);
    bytes &extend_number (bytes &, size_t size);

    // trim to minimal size;
    bytes &trim_number (bytes &);

    static const size_t MAXIMUM_ELEMENT_SIZE = 4;

    const integer &read_integer (const bytes &span, bool RequireMinimal, const size_t nMaxNumSize = MAXIMUM_ELEMENT_SIZE);

    // implements OP_0NOTEQUAL
    bool nonzero (slice<const byte> b);

    bool is_zero (slice<const byte>);
    bool is_negative (slice<const byte>);
    bool is_positive (slice<const byte>);

    template <size_t size> size_t serialized_size (const uint_little<size> &u);

    size_t serialized_size (const integer &i);

    // implements OP_INVERT
    integer bit_not (slice<const byte>);

    // implements OP_AND
    integer bit_and (slice<const byte>, slice<const byte>);

    // implements OP_XOR
    integer bit_xor (slice<const byte>, slice<const byte>);

    // implements OP_OR
    integer bit_or (slice<const byte>, slice<const byte>);

    // implements OP_NOT
    bool bool_not (slice<const byte>);

    // implements OP_BOOLAND
    bool bool_and (slice<const byte>, slice<const byte>);

    // implements OP_BOOLOR
    bool bool_or (slice<const byte>, slice<const byte>);

    bool num_equal (slice<const byte>, slice<const byte>);
    bool num_not_equal (slice<const byte>, slice<const byte>);
    bool less (slice<const byte>, slice<const byte>);
    bool greater (slice<const byte>, slice<const byte>);
    bool less_equal (slice<const byte>, slice<const byte>);
    bool greater_equal (slice<const byte>, slice<const byte>);

    bytes negate (slice<const byte>);
    bytes abs (slice<const byte>);
    bytes plus (slice<const byte>, slice<const byte>);
    bytes minus (slice<const byte>, slice<const byte>);
    bytes times (slice<const byte>, slice<const byte>);
    bytes divide (slice<const byte>, slice<const byte>);
    bytes mod (slice<const byte>, slice<const byte>);

    // concatinate, implements OP_CAT
    integer cat (slice<const byte>, slice<const byte>);
    data::string cat (string_view, string_view);

    // implements OP_LEFT
    // take the n leftmost bytes from the given string.
    slice<const byte> left (slice<const byte>, size_t n);
    string_view left (string_view, size_t n);

    // implements OP_RIGHT
    // take the n rightmost bytes from the given string.
    slice<const byte> right (slice<const byte>, size_t n);
    string_view right (string_view, size_t n);

    // implements OP_SPLIT
    std::pair<slice<const byte>, slice<const byte>> split (slice<const byte>, size_t);
    std::pair<string_view, string_view> split (string_view, size_t);

    // shift right by n bits, implements OP_RSHIFT
    integer right_shift (slice<const byte>, int32 n);

    // shift left by n bits, implements OP_LSHIFT
    integer left_shift (slice<const byte>, int32 n);

    bool inline nonzero (slice<const byte> b) {
        if (b.size () == 0) return false;
        for (int i = 0; i < b.size () - 1; i++) if (b[i] != 0) return true;
        return b[b.size () - 1] != 0x00 && b[b.size () - 1] != 0x80;
    }

    bool inline is_zero (slice<const byte> b) {
        if (b.size () == 0) return true;
        for (int i = 0; i < b.size () - 1; i++) if (b[i] != 0) return false;
        return b[b.size () - 1] == 0x00 || b[b.size () - 1] == 0x80;
    }

    bool inline is_negative (slice<const byte> b) {
        return nonzero (b) && (b[b.size () - 1] & 0x80);
    }

    bool inline is_positive (slice<const byte> b) {
        return nonzero (b) && !(b[b.size () - 1] & 0x80);
    }

    template <size_t size> size_t inline serialized_size (const uint_little<size> &u) {
        size_t last_0 = 0;
        for (size_t i = 0; i < size; i++) if (u[i] != 0x00) last_0 = i + 1;
        return last_0 == 0 ? 1 : u[last_0 - 1] & 0x80 ? last_0 + 2 : last_0 + 1;
    }

    size_t inline serialized_size (const integer &i) {
        return i.size ();
    }

    size_t inline minimal_number_size (slice<const byte> b) {
        return data::arithmetic::minimal_size<data::endian::little, data::arithmetic::negativity::BC, byte> (b);
    }

    const integer inline &read_integer (const bytes &span, bool RequireMinimal, const size_t nMaxNumSize) {
        if (span.size () > nMaxNumSize) throw script_exception {SCRIPT_ERR_SCRIPTNUM_OVERFLOW};
        if (RequireMinimal && !is_minimal_number (span)) throw script_exception {SCRIPT_ERR_SCRIPTNUM_MINENCODE};
        return static_cast<const integer &> (span);
    }

    bool inline is_minimal_number (slice<const byte> span) {
        return data::arithmetic::is_minimal<data::endian::little, data::arithmetic::negativity::BC, byte> (span);
    }

    bytes inline &extend_number (bytes &rawnum, size_t size) {
        data::arithmetic::extend<data::endian::little, data::arithmetic::negativity::BC, byte> (rawnum, size);
        return rawnum;
    }

    bytes inline &trim_number (bytes &num) {
        data::arithmetic::trim<data::endian::little, data::arithmetic::negativity::BC, byte> (num);
        return num;
    }

    // implements OP_LEFT
    // take the n leftmost bytes from the given string.
    slice<const byte> inline left (slice<const byte> x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return x.range (n);
    }

    // implements OP_RIGHT
    // take the n rightmost bytes from the given string.
    slice<const byte> inline right (slice<const byte> x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return x.range (x.size () - n, x.size ());
    }

    string_view inline left (string_view x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return x.substr (0, n);
    }

    string_view inline right (string_view x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return x.substr (x.size () - n, x.size () - n);
    }

    // implements OP_SPLIT
    std::pair<slice<const byte>, slice<const byte>> inline split (slice<const byte> x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return {x.range (0, n), x.drop (n)};
    }

    std::pair<string_view, string_view> inline split (string_view x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return {x.substr (0, n), x.substr (n)};
    }

    bool inline bool_not (slice<const byte> x) {
        return is_zero (x);
    }

    bool inline bool_and (slice<const byte> x, slice<const byte> y) {
        return nonzero (x) && nonzero (y);
    }

    bool inline bool_or (slice<const byte> x, slice<const byte> y) {
        return nonzero (x) || nonzero (y);
    }

    bool inline num_not_equal (slice<const byte> x, slice<const byte> y) {
        return !num_equal (x, y);
    }

    bool inline num_equal (slice<const byte> x, slice<const byte> y) {
        return integer {x} == integer {y};
    }

    bool inline less (slice<const byte> x, slice<const byte> y) {
        return integer {x} < integer {y};
    }

    bool inline greater (slice<const byte> x, slice<const byte> y) {
        return integer {x} > integer {y};
    }

    bool inline less_equal (slice<const byte> x, slice<const byte> y) {
        return integer {x} <= integer {y};
    }

    bool inline greater_equal (slice<const byte> x, slice<const byte> y) {
        return integer {x} >= integer {y};
    }

    bytes inline negate (slice<const byte> x) {
        return -integer {x};
    }

    bytes inline plus (slice<const byte> x, slice<const byte> y) {
        return integer {x} + integer {y};
    }

    bytes inline minus (slice<const byte> x, slice<const byte> y) {
        return integer {x} - integer {y};
    }

    bytes inline times (slice<const byte> x, slice<const byte> y) {
        return integer {x} * integer {y};
    }

    bytes inline divide (slice<const byte> x, slice<const byte> y) {
        return integer {x} / integer {y};
    }

    bytes inline mod (slice<const byte> x, slice<const byte> y) {
        return integer {x} % integer {y};
    }

    bytes inline abs (slice<const byte> x) {
        if (is_negative (x)) return negate (x);
        return bytes (x);
    }
}

#endif
