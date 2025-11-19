// Copyright (c) 2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_NUMBERS
#define GIGAMONKEY_NUMBERS

#include <gigamonkey/types.hpp>
#include <gigamonkey/script/error.h>

namespace Gigamonkey::Bitcoin {

    // and arbitrary size integers, little endian two's complement.
    using integer = data::Z_bytes_BC_little;

    size_t minimal_number_size (byte_slice);

    bool is_minimal_number (byte_slice);
    bytes &extend_number (bytes &, size_t size);

    // trim to minimal size;
    bytes &trim_number (bytes &);

    static const size_t MAXIMUM_ELEMENT_SIZE = 4;

    const integer &read_integer (const bytes &span, bool RequireMinimal, const size_t nMaxNumSize = MAXIMUM_ELEMENT_SIZE);

    // concatinate, implements OP_CAT
    integer cat (byte_slice, byte_slice);
    data::string cat (string_view, string_view);

    // implements OP_LEFT
    // take the n leftmost bytes from the given string.
    byte_slice left (byte_slice, size_t n);
    string_view left (string_view, size_t n);

    // implements OP_RIGHT
    // take the n rightmost bytes from the given string.
    byte_slice right (byte_slice, size_t n);
    string_view right (string_view, size_t n);

    // implements OP_SPLIT
    std::pair<byte_slice, byte_slice> split (byte_slice, size_t);
    std::pair<string_view, string_view> split (string_view, size_t);

    // implements OP_0NOTEQUAL
    // also how we cast a number to bool.
    bool nonzero (byte_slice b);

    bool is_zero (byte_slice);
    bool is_negative (byte_slice);
    bool is_positive (byte_slice);

    template <size_t size> size_t serialized_size (const uint_little<size> &u);

    size_t serialized_size (const integer &i);

    // implements OP_INVERT
    integer bit_not (byte_slice);

    // implements OP_AND
    integer bit_and (byte_slice, byte_slice);

    // implements OP_XOR
    integer bit_xor (byte_slice, byte_slice);

    // implements OP_OR
    integer bit_or (byte_slice, byte_slice);

    // shift right by n bits, implements OP_RSHIFT
    integer right_shift (byte_slice, int32 n);

    // shift left by n bits, implements OP_LSHIFT
    integer left_shift (byte_slice, int32 n);

    // shift right by n bits
    data::string right_shift (const data::string &, int32 n);

    // shift left by n bits
    data::string left_shift (const data::string &, int32 n);

    // integral bit shift, not an op code.
    integer bit_shift (byte_slice, int32 n);

    // implements OP_NOT
    bool bool_not (byte_slice);

    // implements OP_BOOLAND
    bool bool_and (byte_slice, byte_slice);

    // implements OP_BOOLOR
    bool bool_or (byte_slice, byte_slice);

    std::weak_ordering compare (byte_slice, byte_slice);

    // implements OP_NUMEQUAL
    bool num_equal (byte_slice, byte_slice);
    bool num_not_equal (byte_slice, byte_slice);
    bool less (byte_slice, byte_slice);
    bool greater (byte_slice, byte_slice);
    bool less_equal (byte_slice, byte_slice);
    bool greater_equal (byte_slice, byte_slice);
    bool within (byte_slice b, byte_slice min, byte_slice max);

    // Implements OP_1ADD
    integer increment (byte_slice);

    // implements OP_1SUB
    integer decrement (byte_slice);

    // implements OP_2MUL
    integer mul_2 (byte_slice);

    // implements OP_2DIV
    integer div_2 (byte_slice);

    integer negate (byte_slice);
    integer abs (byte_slice);
    integer plus (byte_slice, byte_slice);
    integer minus (byte_slice, byte_slice);
    integer times (byte_slice, byte_slice);
    integer divide (byte_slice, byte_slice);
    integer mod (byte_slice, byte_slice);

    bool inline nonzero (byte_slice b) {
        if (b.size () == 0) return false;
        for (int i = 0; i < b.size () - 1; i++) if (b[i] != 0) return true;
        return b[b.size () - 1] != 0x00 && b[b.size () - 1] != 0x80;
    }

    bool inline is_zero (byte_slice b) {
        if (b.size () == 0) return true;
        for (int i = 0; i < b.size () - 1; i++) if (b[i] != 0) return false;
        return b[b.size () - 1] == 0x00 || b[b.size () - 1] == 0x80;
    }

    bool inline is_negative (byte_slice b) {
        return nonzero (b) && (b[b.size () - 1] & 0x80);
    }

    bool inline is_positive (byte_slice b) {
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

    size_t inline minimal_number_size (byte_slice b) {
        return data::arithmetic::minimal_size<data::endian::little, data::arithmetic::negativity::BC, byte> (b);
    }

    const integer inline &read_integer (const bytes &span, bool RequireMinimal, const size_t nMaxNumSize) {
        if (span.size () > nMaxNumSize) throw script_exception {SCRIPT_ERR_SCRIPTNUM_OVERFLOW};
        if (RequireMinimal && !is_minimal_number (span)) throw script_exception {SCRIPT_ERR_SCRIPTNUM_MINENCODE};
        return static_cast<const integer &> (span);
    }

    bool inline is_minimal_number (byte_slice span) {
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
    byte_slice inline left (byte_slice x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return x.range (n);
    }

    // implements OP_RIGHT
    // take the n rightmost bytes from the given string.
    byte_slice inline right (byte_slice x, size_t n) {
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
    std::pair<byte_slice, byte_slice> inline split (byte_slice x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return {x.range (0, n), x.drop (n)};
    }

    std::pair<string_view, string_view> inline split (string_view x, size_t n) {
        if (n < 0 || n > x.size ()) throw exception {} << "invalid split range";
        return {x.substr (0, n), x.substr (n)};
    }

    bool inline bool_not (byte_slice x) {
        return is_zero (x);
    }

    bool inline bool_and (byte_slice x, byte_slice y) {
        return nonzero (x) && nonzero (y);
    }

    bool inline bool_or (byte_slice x, byte_slice y) {
        return nonzero (x) || nonzero (y);
    }

    bool inline num_not_equal (byte_slice x, byte_slice y) {
        return !num_equal (x, y);
    }

    integer inline negate (byte_slice x) {
        return -integer {x};
    }

    integer inline plus (byte_slice x, byte_slice y) {
        return integer {x} + integer {y};
    }

    integer inline minus (byte_slice x, byte_slice y) {
        return integer {x} - integer {y};
    }

    integer inline times (byte_slice x, byte_slice y) {
        return integer {x} * integer {y};
    }

    integer inline divide (byte_slice x, byte_slice y) {
        return integer {x} / integer {y};
    }

    integer inline mod (byte_slice x, byte_slice y) {
        return integer {x} % integer {y};
    }

    integer inline bit_shift (byte_slice x, int32 n) {
        return integer {x} << n;
    }

    integer inline abs (byte_slice x) {
        if (is_negative (x)) return negate (x);
        return bytes (x);
    }

    integer inline mul_2 (byte_slice x) {
        return data::math::bit_mul_2_pow (integer {x}, 1);
    }

    integer inline div_2 (byte_slice x) {
        return data::math::bit_div_2_negative_mod (integer {x});
    }

    std::weak_ordering inline compare (byte_slice a, byte_slice b) {
        return data::arithmetic::BC::compare<data::endian::little, byte> (a, b);
    }

    // implements OP_NUMEQUAL
    bool inline num_equal (byte_slice a, byte_slice b) {
        return compare (a, b) == 0;
    }

    bool inline less (byte_slice a, byte_slice b) {
        return compare (a, b) < 0;
    }

    bool inline greater (byte_slice a, byte_slice b) {
        return compare (a, b) > 0;
    }

    bool inline less_equal (byte_slice a, byte_slice b) {
        return compare (a, b) <= 0;
    }

    bool inline greater_equal (byte_slice a, byte_slice b) {
        return compare (a, b) >= 0;
    }

    bool inline within (byte_slice b, byte_slice min, byte_slice max) {
        return greater_equal (b, min) && less (b, max);
    }
}

#endif
