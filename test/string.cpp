// Copyright (c) 2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/numbers.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin {

    bytes inline hex (const string &x) {
        return *encoding::hex::read (x);
    }

    TEST (String, Cat) {

        EXPECT_EQ ((cat (hex (""), hex (""))), (hex ("")));
        EXPECT_EQ ((cat (hex ("12"), hex (""))), (hex ("12")));
        EXPECT_EQ ((cat (hex (""), hex ("12"))), (hex ("12")));
        EXPECT_EQ ((cat (hex ("01"), hex ("23"))), (hex ("0123")));
        EXPECT_EQ ((cat (hex ("32"), hex ("10"))), (hex ("3210")));

        EXPECT_EQ ((cat (string (""), string (""))), (string ("")));
        EXPECT_EQ ((cat (string ("x"), string (""))), (string ("x")));
        EXPECT_EQ ((cat (string (""), string ("x"))), (string ("x")));
        EXPECT_EQ ((cat (string ("y"), string ("t"))), (string ("yt")));
        EXPECT_EQ ((cat (string ("z"), string ("w"))), (string ("zw")));

    }

    TEST (String, Left) {

        EXPECT_EQ ((left (hex (""), 0)), hex (""));
        EXPECT_EQ ((left (hex ("ab"), 0)), hex (""));
        EXPECT_EQ ((left (hex ("ab"), 1)), hex ("ab"));

        EXPECT_EQ ((left (hex ("abcd"), 0)), hex (""));
        EXPECT_EQ ((left (hex ("abcd"), 1)), hex ("ab"));
        EXPECT_EQ ((left (hex ("abcd"), 2)), hex ("abcd"));

        EXPECT_EQ ((left (string (""), 0)), string (""));
        EXPECT_EQ ((left (string ("W"), 0)), string (""));
        EXPECT_EQ ((left (string ("W"), 1)), string ("W"));

        EXPECT_EQ ((left (string ("WX"), 0)), string (""));
        EXPECT_EQ ((left (string ("WX"), 1)), string ("W"));
        EXPECT_EQ ((left (string ("WX"), 2)), string ("WX"));

    }

    TEST (String, Right) {

        EXPECT_EQ ((right (hex (""), 0)), hex (""));
        EXPECT_EQ ((right (hex ("ab"), 0)), hex (""));
        EXPECT_EQ ((right (hex ("ab"), 1)), hex ("ab"));

        EXPECT_EQ ((right (hex ("abcd"), 0)), hex (""));
        EXPECT_EQ ((right (hex ("abcd"), 1)), hex ("cd"));
        EXPECT_EQ ((right (hex ("abcd"), 2)), hex ("abcd"));

        EXPECT_EQ ((right (string (""), 0)), string (""));
        EXPECT_EQ ((right (string ("Q"), 0)), string (""));
        EXPECT_EQ ((right (string ("Q"), 1)), string ("Q"));

        EXPECT_EQ ((right (string ("QP"), 0)), string (""));
        EXPECT_EQ ((right (string ("QP"), 1)), string ("P"));
        EXPECT_EQ ((right (string ("QP"), 2)), string ("QP"));

    }

    using splut = std::pair<byte_slice, byte_slice>;
    using sploot = std::pair<string_view, string_view>;

    TEST (String, Split) {

        EXPECT_EQ ((split (hex (""), 0)), (splut {hex (""), hex ("")}));
        EXPECT_EQ ((split (hex ("ab"), 0)), (splut {hex (""), hex ("ab")}));
        EXPECT_EQ ((split (hex ("ab"), 1)), (splut {hex ("ab"), hex ("")}));
        EXPECT_EQ ((split (hex ("abcd"), 0)), (splut {hex (""), hex ("abcd")}));
        EXPECT_EQ ((split (hex ("abcd"), 1)), (splut {hex ("ab"), hex ("cd")}));
        EXPECT_EQ ((split (hex ("abcd"), 2)), (splut {hex ("abcd"), hex ("")}));

        EXPECT_EQ ((split (string (""), 0)), (sploot {string (""), string ("")}));
        EXPECT_EQ ((split (string ("M"), 0)), (sploot {string (""), string ("M")}));
        EXPECT_EQ ((split (string ("M"), 1)), (sploot {string ("M"), string ("")}));
        EXPECT_EQ ((split (string ("MN"), 0)), (sploot {string (""), string ("MN")}));
        EXPECT_EQ ((split (string ("MN"), 1)), (sploot {string ("M"), string ("N")}));
        EXPECT_EQ ((split (string ("MN"), 2)), (sploot {string ("MN"), string ("")}));

    }

    TEST (String, Substr) {

        EXPECT_EQ ((substr (integer {"0x"}, 0, 0)), hex (""));
        EXPECT_EQ ((substr (integer {"0x01"}, 0, 0)), hex (""));
        EXPECT_EQ ((substr (integer {"0x01"}, 1, 0)), hex (""));
        EXPECT_EQ ((substr (integer {"0x01"}, 0, 1)), hex ("01"));
        EXPECT_EQ ((substr (integer {"0x0123"}, 0, 0)), hex (""));
        EXPECT_EQ ((substr (integer {"0x0123"}, 1, 0)), hex (""));
        EXPECT_EQ ((substr (integer {"0x0123"}, 2, 0)), hex (""));
        EXPECT_EQ ((substr (integer {"0x0123"}, 0, 1)), hex ("23"));
        EXPECT_EQ ((substr (integer {"0x0123"}, 0, 2)), hex ("2301"));
        EXPECT_EQ ((substr (integer {"0x0123"}, 1, 0)), hex (""));
        EXPECT_EQ ((substr (integer {"0x0123"}, 1, 1)), hex ("01"));
        EXPECT_EQ ((substr (integer {"0x0123"}, 2, 0)), hex (""));

        EXPECT_EQ ((substr (string {""}, 0, 0)), string (""));
        EXPECT_EQ ((substr (string {"a"}, 0, 0)), string (""));
        EXPECT_EQ ((substr (string {"a"}, 1, 0)), string (""));
        EXPECT_EQ ((substr (string {"a"}, 0, 1)), string ("a"));
        EXPECT_EQ ((substr (string {"ab"}, 0, 0)), string (""));
        EXPECT_EQ ((substr (string {"ab"}, 1, 0)), string (""));
        EXPECT_EQ ((substr (string {"ab"}, 2, 0)), string (""));
        EXPECT_EQ ((substr (string {"ab"}, 0, 1)), string ("a"));
        EXPECT_EQ ((substr (string {"ab"}, 0, 2)), string ("ab"));
        EXPECT_EQ ((substr (string {"ab"}, 1, 0)), string (""));
        EXPECT_EQ ((substr (string {"ab"}, 1, 1)), string ("b"));
        EXPECT_EQ ((substr (string {"ab"}, 2, 0)), string (""));

    }

    // TODO All these functiqons work on strings.

    TEST (String, BitNot) {

        EXPECT_EQ (integer {"0x"}, ~integer {"0x"});
        EXPECT_EQ (integer {"0x"}, bit_not (integer {"0x"}));

        EXPECT_EQ (integer {"0x80"}, ~integer {"0x7f"});
        EXPECT_EQ (integer {"0x80"}, bit_not (integer {"0x7f"}));

        EXPECT_EQ (integer {"0x00"}, ~integer {"0xff"});
        EXPECT_EQ (integer {"0x00"}, bit_not (integer {"0xff"}));

        EXPECT_EQ (integer {"0x7f"}, ~integer {"0x80"});
        EXPECT_EQ (integer {"0x7f"}, bit_not (integer {"0x80"}));

        EXPECT_EQ (integer {"0xff"}, ~integer {"0x00"});
        EXPECT_EQ (integer {"0xff"}, bit_not (integer {"0x00"}));

    }

    TEST (String, BitAnd) {

        EXPECT_EQ ((bit_and (integer ("0x"), integer ("0x"))), integer ("0x"));
        EXPECT_EQ ((bit_and (integer ("0x11"), integer ("0x22"))), integer ("0x00"));
        EXPECT_EQ ((bit_and (integer ("0x11"), integer ("0x11"))), integer ("0x11"));

    }

    TEST (String, BitOr) {

        EXPECT_EQ ((bit_or (integer ("0x"), integer ("0x"))), integer ("0x"));
        EXPECT_EQ ((bit_or (integer ("0x11"), integer ("0x11"))), integer ("0x11"));
        EXPECT_EQ ((bit_or (integer ("0x11"), integer ("0x22"))), integer ("0x33"));

    }

    TEST (String, BitXor) {

        EXPECT_EQ ((bit_xor (integer ("0x"), integer ("0x"))), integer ("0x"));
        EXPECT_EQ ((bit_xor (integer ("0x11"), integer ("0x11"))), integer ("0x00"));
        EXPECT_EQ ((bit_xor (integer ("0x11"), integer ("0x22"))), integer ("0x33"));

    }

    TEST (String, ShiftLeft) {

        EXPECT_EQ (left_shift (hex (""), 0), hex (""));
        EXPECT_EQ (left_shift (hex (""), 1), hex (""));

        EXPECT_EQ (left_shift (hex ("99"), 0), hex ("99"));
        EXPECT_EQ (left_shift (hex ("99"), 1), hex ("32"));
        EXPECT_EQ (left_shift (hex ("99"), 2), hex ("64"));

    }

    TEST (String, ShiftRight) {

        EXPECT_EQ (right_shift (hex (""), 0), hex (""));
        EXPECT_EQ (right_shift (hex (""), 0), hex (""));

        EXPECT_EQ (right_shift (hex ("99"), 0), hex ("99"));
        EXPECT_EQ (right_shift (hex ("99"), 1), hex ("4c"));
        EXPECT_EQ (right_shift (hex ("99"), 2), hex ("26"));

    }

}
