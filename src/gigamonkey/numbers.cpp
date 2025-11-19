#include <gigamonkey/numbers.hpp>

namespace Gigamonkey::Bitcoin {

    // implements OP_AND
    integer bit_and (byte_slice a, byte_slice b) {
        if (a.size () < b.size ()) return bit_and (b, a);
        bytes bb {b};
        extend_number (bb, a.size ());
        data::arithmetic::bit_and<byte> (bb.end (), bb.begin (), const_cast<const decltype (bb) &> (bb).data (), a.data ());
        return bb;
    }

    // implements OP_XOR
    integer bit_xor (byte_slice a, byte_slice b) {
        if (a.size () < b.size ()) return bit_xor (b, a);
        bytes bb {b};
        extend_number (bb, a.size ());
        data::arithmetic::bit_xor<byte> (bb.end (), bb.begin (), const_cast<const decltype (bb) &> (bb).data (), a.data ());
        return bb;
    }

    // implements OP_OR
    integer bit_or (byte_slice a, byte_slice b) {
        if (a.size () < b.size ()) return bit_or (b, a);
        bytes bb {b};
        extend_number (bb, a.size ());
        data::arithmetic::bit_or<byte> (bb.end (), bb.begin (), const_cast<const decltype (bb) &> (bb).data (), a.data ());
        return bb;
    }

    // implements OP_AND
    integer bit_not (byte_slice x) {
        integer result = integer::zero (x.size ());
        data::arithmetic::bit_negate<byte> (result.end (), result.begin (), x.begin ());
        return result;
    }

    // concatinate, implements OP_CAT
    integer cat (byte_slice x, byte_slice y) {
        integer result = integer::zero (x.size () + y.size ());
        auto b = result.begin ();

        for (const auto &xx : x) {
            *b = xx;
            b++;
        }

        for (const auto &yy : y) {
            *b = yy;
            b++;
        }

        return result;
    }

    // same as above but works on strings rather than byte sequences.
    data::string cat (string_view x, string_view y) {
        data::string result {};
        result.resize (x.size () + y.size ());
        auto b = result.begin ();

        for (const auto &xx : x) {
            *b = xx;
            b++;
        }

        for (const auto &yy : y) {
            *b = yy;
            b++;
        }

        return result;
    }

    uint8_t inline make_rshift_mask (size_t n) {
        static uint8_t mask[] = {0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80};
        return mask[n];
    }

    uint8_t inline make_lshift_mask (size_t n) {
        static uint8_t mask[] = {0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01};
        return mask[n];
    }

    // shift x right by n bits, implements OP_RSHIFT
    integer right_shift (byte_slice x, int32 n) {
        integer::size_type bit_shift = n % 8;
        integer::size_type byte_shift = n / 8;

        uint8_t mask = make_rshift_mask (bit_shift);
        uint8_t overflow_mask = ~mask;

        integer result = integer::zero (data::size (x));
        for (integer::size_type i = 0; i < data::size (x); i++) {
            integer::size_type k = i + byte_shift;
            if (k < data::size (x)) {
                uint8_t val = (x[i] & mask);
                val >>= bit_shift;
                result[k] |= val;
            }

            if (k + 1 < data::size (x)) {
                uint8_t carryval = (x[i] & overflow_mask);
                carryval <<= 8 - bit_shift;
                result[k + 1] |= carryval;
            }
        }

        return result;
    }

    // shift x left by n bits, implements OP_LSHIFT
    integer left_shift (byte_slice x, int32 n) {
        integer::size_type bit_shift = n % 8;
        integer::size_type byte_shift = n / 8;

        uint8_t mask = make_lshift_mask (bit_shift);
        uint8_t overflow_mask = ~mask;

        integer result = integer::zero (data::size (x));
        for (integer::size_type index = data::size (x); index > 0; index--) {
            integer::size_type i = index - 1;
            // make sure that k is always >= 0
            if (byte_shift <= i) {
                integer::size_type k = i - byte_shift;
                uint8_t val = (x[i] & mask);
                val <<= bit_shift;
                result[k] |= val;

                if (k >= 1) {
                    uint8_t carryval = (x[i] & overflow_mask);
                    carryval >>= 8 - bit_shift;
                    result[k - 1] |= carryval;
                }
            }
        }

        return result;
    }

    data::string right_shift (const data::string &x, int32 n) {
        integer z = right_shift (byte_slice {(const byte *) x.data (), x.size ()}, n);
        data::string result;
        result.resize (z.size ());
        std::copy (z.data (), z.data () + z.size (), (byte *) result.data ());
        return result;
    }

    data::string left_shift (const data::string &x, int32 n) {
        integer z = left_shift (byte_slice {(const byte *) x.data (), x.size ()}, n);
        data::string result;
        result.resize (z.size ());
        std::copy (z.data (), z.data () + z.size (), (byte *) result.data ());
        return result;
    }

}
