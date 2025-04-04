// Copyright (c) 2021 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/script.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin {
    
    TEST (NumberTest, TestPushNumber) {
        
        EXPECT_EQ (compile (push_data (0)), bytes {OP_0});
        EXPECT_EQ (compile (push_data (integer (0))), bytes {OP_0});
        EXPECT_EQ (compile (push_data (1)), bytes {OP_1});
        EXPECT_EQ (compile (push_data (integer (1))), bytes {OP_1});
        EXPECT_EQ (compile (push_data (-1)), bytes {OP_1NEGATE});
        EXPECT_EQ (compile (push_data (integer (-1))), bytes {OP_1NEGATE});
        EXPECT_EQ (compile (push_data (16)), bytes {OP_16});
        EXPECT_EQ (compile (push_data (integer (16))), bytes {OP_16});

        auto test_program_1 = bytes {OP_PUSHSIZE1, 0x82};
        auto test_program_2 = bytes {OP_PUSHSIZE1, 0x11};
        EXPECT_EQ (compile (push_data (-2)), test_program_1);
        EXPECT_EQ (compile (push_data (integer (-2))), test_program_1);
        EXPECT_EQ (compile (push_data (17)), test_program_2);
        EXPECT_EQ (compile (push_data (integer (17))), test_program_2);
        
        auto test_program_3 = bytes {OP_PUSHSIZE1, 0xff};
        auto test_program_4 = bytes {OP_PUSHSIZE1, 0x7f};
        EXPECT_EQ (compile (push_data (-127)), test_program_3);
        EXPECT_EQ (compile (push_data (integer (-127))), test_program_3);
        EXPECT_EQ (compile (push_data (127)), test_program_4);
        EXPECT_EQ (compile (push_data (integer (127))), test_program_4);
        
        auto test_program_5 = bytes {OP_PUSHSIZE2, 0xff, 0x80};
        auto test_program_6 = bytes {OP_PUSHSIZE2, 0xff, 0x00};
        EXPECT_EQ (compile (push_data (-255)), test_program_5);
        EXPECT_EQ (compile (push_data (integer (-255))), test_program_5);
        EXPECT_EQ (compile (push_data (255)), test_program_6);
        EXPECT_EQ (compile (push_data (integer (255))), test_program_6);
        
    }

    TEST (NumberTest, TestNumberConstructorsInt) {
        
        EXPECT_EQ (bytes_view (integer (0)), bytes ());
        EXPECT_EQ (bytes_view (integer (1)), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (integer (-1)), *encoding::hex::read  ("81"));
        EXPECT_EQ (bytes_view (integer (127)), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (integer (-127)), *encoding::hex::read  ("ff"));
        EXPECT_EQ (bytes_view (integer (128)), *encoding::hex::read  ("8000"));
        EXPECT_EQ (bytes_view (integer (-128)), *encoding::hex::read  ("8080"));
        EXPECT_EQ (bytes_view (integer (256)), *encoding::hex::read  ("0001"));
        EXPECT_EQ (bytes_view (integer (-256)), *encoding::hex::read  ("0081"));
        
    }
    
    TEST (NumberTest, TestNumberConstructorsDecimalPositive) {

        EXPECT_EQ (bytes_view (integer ("0")), *encoding::hex::read (""));
        EXPECT_EQ (bytes_view (integer ("127")), *encoding::hex::read ("7f"));
        EXPECT_EQ (bytes_view (integer ("128")), *encoding::hex::read ("8000"));
        EXPECT_EQ (bytes_view (integer ("256")), *encoding::hex::read ("0001"));
        
    }

    TEST (NumberTest, TestNumberConstructorsHexidecZ) {
        
        EXPECT_EQ (bytes_view (integer ("0")), bytes ());
        EXPECT_EQ (bytes_view (integer ("0x")), *encoding::hex::read  (""));
        EXPECT_EQ (bytes_view (integer ("0x00")), *encoding::hex::read  ("00"));
        EXPECT_EQ (bytes_view (integer ("0x80")), *encoding::hex::read  ("80"));
        EXPECT_EQ (bytes_view (integer ("0x0000")), *encoding::hex::read  ("0000"));
        EXPECT_EQ (bytes_view (integer ("0x8000")), *encoding::hex::read  ("0080"));
        EXPECT_EQ (bytes_view (integer ("0x000000")), *encoding::hex::read  ("000000"));
        EXPECT_EQ (bytes_view (integer ("0x800000")), *encoding::hex::read  ("000080"));

        EXPECT_EQ (bytes_view (integer ("1")), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (integer ("-1")), *encoding::hex::read  ("81"));
        EXPECT_EQ (bytes_view (integer ("0x01")), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (integer ("0x81")), *encoding::hex::read  ("81"));
        EXPECT_EQ (bytes_view (integer ("0x0001")), *encoding::hex::read  ("0100"));
        EXPECT_EQ (bytes_view (integer ("0x8001")), *encoding::hex::read  ("0180"));
        EXPECT_EQ (bytes_view (integer ("0x000001")), *encoding::hex::read  ("010000"));
        EXPECT_EQ (bytes_view (integer ("0x800001")), *encoding::hex::read  ("010080"));
        
        EXPECT_EQ (bytes_view (integer ("0x7f")), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (integer ("0xff")), *encoding::hex::read  ("ff"));
        EXPECT_EQ (bytes_view (integer ("0x007f")), *encoding::hex::read  ("7f00"));
        EXPECT_EQ (bytes_view (integer ("0x807f")), *encoding::hex::read  ("7f80"));
        EXPECT_EQ (bytes_view (integer ("0x00007f")), *encoding::hex::read  ("7f0000"));
        EXPECT_EQ (bytes_view (integer ("0x80007f")), *encoding::hex::read  ("7f0080"));
        
    }

    TEST (NumberTest, TestNumberMinimalZ) {
        
        EXPECT_TRUE (is_minimal (integer ("0")));
        EXPECT_FALSE (is_minimal (integer ("0x00")));
        EXPECT_FALSE (is_minimal (integer ("0x80")));
        EXPECT_FALSE (is_minimal (integer ("0x0000")));
        EXPECT_FALSE (is_minimal (integer ("0x8000")));
        EXPECT_FALSE (is_minimal (integer ("0x000000")));
        EXPECT_FALSE (is_minimal (integer ("0x800000")));

        EXPECT_TRUE (is_minimal (integer ("0x01")));
        EXPECT_TRUE (is_minimal (integer ("0x81")));
        EXPECT_FALSE (is_minimal (integer ("0x0001")));
        EXPECT_FALSE (is_minimal (integer ("0x8001")));
        EXPECT_FALSE (is_minimal (integer ("0x000001")));
        EXPECT_FALSE (is_minimal (integer ("0x800001")));
        
        EXPECT_TRUE (is_minimal (integer ("0x7f")));
        EXPECT_TRUE (is_minimal (integer ("0xff")));
        EXPECT_FALSE (is_minimal (integer ("0x007f")));
        EXPECT_FALSE (is_minimal (integer ("0x807f")));
        EXPECT_FALSE (is_minimal (integer ("0x00007f")));
        EXPECT_FALSE (is_minimal (integer ("0x80007f")));
        
    }
    
    TEST (NumberTest, TestNumberTrimZ) {
        
        EXPECT_EQ (bytes_view (trim (integer ("0x00"))), bytes ());
        EXPECT_EQ (bytes_view (trim (integer ("0x80"))), bytes ());
        EXPECT_EQ (bytes_view (trim (integer ("0x0000"))), bytes ());
        EXPECT_EQ (bytes_view (trim (integer ("0x8000"))), bytes ());
        EXPECT_EQ (bytes_view (trim (integer ("0x000000"))), bytes ());
        EXPECT_EQ (bytes_view (trim (integer ("0x800000"))), bytes ());
        
        EXPECT_EQ (bytes_view (trim (integer ("0x01"))), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (trim (integer ("0x81"))), *encoding::hex::read  ("81"));
        EXPECT_EQ (bytes_view (trim (integer ("0x0001"))), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (trim (integer ("0x8001"))), *encoding::hex::read  ("81"));
        EXPECT_EQ (bytes_view (trim (integer ("0x000001"))), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (trim (integer ("0x800001"))), *encoding::hex::read  ("81"));
        
        EXPECT_EQ (bytes_view (trim (integer ("0x7f"))), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (trim (integer ("0xff"))), *encoding::hex::read  ("ff"));
        EXPECT_EQ (bytes_view (trim (integer ("0x007f"))), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (trim (integer ("0x807f"))), *encoding::hex::read  ("ff"));
        EXPECT_EQ (bytes_view (trim (integer ("0x00007f"))), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (trim (integer ("0x80007f"))), *encoding::hex::read  ("ff"));
        
    }

    TEST (NumberTest, TestNumberSignZ) {
        
        EXPECT_TRUE (is_zero (integer ("0x00")));
        EXPECT_TRUE (is_zero (integer ("0x80")));
        EXPECT_TRUE (is_zero (integer ("0x0000")));
        EXPECT_TRUE (is_zero (integer ("0x8000")));
        EXPECT_TRUE (is_zero (integer ("0x000000")));
        EXPECT_TRUE (is_zero (integer ("0x800000")));
        
        EXPECT_FALSE (is_zero (integer ("0x01")));
        EXPECT_FALSE (is_zero (integer ("0x81")));
        EXPECT_FALSE (is_zero (integer ("0x0001")));
        EXPECT_FALSE (is_zero (integer ("0x8001")));
        EXPECT_FALSE (is_zero (integer ("0x000001")));
        EXPECT_FALSE (is_zero (integer ("0x800001")));
        
        EXPECT_FALSE (is_zero (integer ("0x0080")));
        EXPECT_FALSE (is_zero (integer ("0x8080")));
        EXPECT_FALSE (is_zero (integer ("0x000080")));
        EXPECT_FALSE (is_zero (integer ("0x800080")));

        EXPECT_TRUE (is_positive_zero (integer ("0x00")));
        EXPECT_FALSE (is_positive_zero (integer ("0x80")));
        EXPECT_TRUE (is_positive_zero (integer ("0x0000")));
        EXPECT_FALSE (is_positive_zero (integer ("0x8000")));
        EXPECT_TRUE (is_positive_zero (integer ("0x000000")));
        EXPECT_FALSE (is_positive_zero (integer ("0x800000")));
        
        EXPECT_FALSE (is_positive_zero (integer ("0x01")));
        EXPECT_FALSE (is_positive_zero (integer ("0x81")));
        EXPECT_FALSE (is_positive_zero (integer ("0x0001")));
        EXPECT_FALSE (is_positive_zero (integer ("0x8001")));
        EXPECT_FALSE (is_positive_zero (integer ("0x000001")));
        EXPECT_FALSE (is_positive_zero (integer ("0x800001")));
        
        EXPECT_FALSE (is_negative_zero (integer ("0x00")));
        EXPECT_TRUE (is_negative_zero (integer ("0x80")));
        EXPECT_FALSE (is_negative_zero (integer ("0x0000")));
        EXPECT_TRUE (is_negative_zero (integer ("0x8000")));
        EXPECT_FALSE (is_negative_zero (integer ("0x000000")));
        EXPECT_TRUE (is_negative_zero (integer ("0x800000")));

        EXPECT_FALSE (is_negative_zero (integer ("0x01")));
        EXPECT_FALSE (is_negative_zero (integer ("0x81")));
        EXPECT_FALSE (is_negative_zero (integer ("0x0001")));
        EXPECT_FALSE (is_negative_zero (integer ("0x8001")));
        EXPECT_FALSE (is_negative_zero (integer ("0x000001")));
        EXPECT_FALSE (is_negative_zero (integer ("0x800001")));
        
        EXPECT_FALSE (is_positive (integer ("0x00")));
        EXPECT_FALSE (is_positive (integer ("0x80")));
        EXPECT_FALSE (is_positive (integer ("0x0000")));
        EXPECT_FALSE (is_positive (integer ("0x8000")));
        EXPECT_FALSE (is_positive (integer ("0x000000")));
        EXPECT_FALSE (is_positive (integer ("0x800000")));
        
        EXPECT_FALSE (is_negative (integer ("0x00")));
        EXPECT_FALSE (is_negative (integer ("0x80")));
        EXPECT_FALSE (is_negative (integer ("0x0000")));
        EXPECT_FALSE (is_negative (integer ("0x8000")));
        EXPECT_FALSE (is_negative (integer ("0x000000")));
        EXPECT_FALSE (is_negative (integer ("0x800000")));
        
        EXPECT_TRUE (is_positive (integer ("0x01")));
        EXPECT_FALSE (is_positive (integer ("0x81")));
        EXPECT_TRUE (is_positive (integer ("0x0001")));
        EXPECT_FALSE (is_positive (integer ("0x8001")));
        EXPECT_TRUE (is_positive (integer ("0x000001")));
        EXPECT_FALSE (is_positive (integer ("0x800001")));
        
        EXPECT_FALSE (is_negative (integer ("0x01")));
        EXPECT_TRUE (is_negative (integer ("0x81")));
        EXPECT_FALSE (is_negative (integer ("0x0001")));
        EXPECT_TRUE (is_negative (integer ("0x8001")));
        EXPECT_FALSE (is_negative (integer ("0x000001")));
        EXPECT_TRUE (is_negative (integer ("0x800001")));
        
        EXPECT_TRUE (is_positive (integer ("0x0080")));
        EXPECT_FALSE (is_positive (integer ("0x8080")));
        EXPECT_TRUE (is_positive (integer ("0x000080")));
        EXPECT_FALSE (is_positive (integer ("0x800080")));
        
        EXPECT_FALSE (is_negative (integer ("0x0080")));
        EXPECT_TRUE (is_negative (integer ("0x8080")));
        EXPECT_FALSE (is_negative (integer ("0x000080")));
        EXPECT_TRUE (is_negative (integer ("0x800080")));
    
    }

    TEST (NumberTest, TestNumberConstructorsDecimalNegative) {
        
        //EXPECT_EQ (bytes_view (integer ("-0")), *encoding::hex::read  ("80"));
        EXPECT_EQ (bytes_view (integer ("-127")), *encoding::hex::read  ("ff"));
        EXPECT_EQ (bytes_view (integer ("-128")), *encoding::hex::read  ("8080"));
        EXPECT_EQ (bytes_view (integer ("-256")), *encoding::hex::read  ("0081"));

    }

    TEST (NumberTest, TestNumberCompare) {
        
        EXPECT_EQ (integer (0), integer ("0"));
        EXPECT_EQ (integer (0), integer ("0x00"));
        EXPECT_EQ (integer (0), integer ("0x80"));
        EXPECT_EQ (integer (0), integer ("0x0000"));
        EXPECT_EQ (integer (0), integer ("0x8000"));
        EXPECT_EQ (integer (0), integer ("0x000000"));
        EXPECT_EQ (integer (0), integer ("0x800000"));
        
        EXPECT_EQ (integer (1), integer ("0x01"));
        EXPECT_EQ (integer (-1), integer ("0x81"));
        EXPECT_EQ (integer (1), integer ("0x0001"));
        EXPECT_EQ (integer (-1), integer ("0x8001"));
        EXPECT_EQ (integer (1), integer ("0x000001"));
        EXPECT_EQ (integer (-1), integer ("0x800001"));
        
        EXPECT_EQ (integer (127), integer ("0x7f"));
        EXPECT_EQ (integer (-127), integer ("0xff"));
        EXPECT_EQ (integer (127), integer ("0x007f"));
        EXPECT_EQ (integer (-127), integer ("0x807f"));
        EXPECT_EQ (integer (127), integer ("0x00007f"));
        EXPECT_EQ (integer (-127), integer ("0x80007f"));
        
        EXPECT_EQ (integer (128), integer ("0x0080"));
        EXPECT_EQ (integer (-128), integer ("0x8080"));
        EXPECT_EQ (integer (128), integer ("0x000080"));
        EXPECT_EQ (integer (-128), integer ("0x800080"));
        
        EXPECT_EQ (integer (256), integer ("0x0100"));
        EXPECT_EQ (integer (-256), integer ("0x8100"));
        EXPECT_EQ (integer (256), integer ("0x000100"));
        EXPECT_EQ (integer (-256), integer ("0x800100"));
        
        EXPECT_LE (integer (0), integer (0));
        EXPECT_GE (integer (0), integer (0));
        
        EXPECT_LE (integer (1), integer (1));
        EXPECT_GE (integer (1), integer (1));
        
        EXPECT_LE (integer (-1), integer (-1));
        EXPECT_GE (integer (-1), integer (-1));
        
        EXPECT_LE (integer (127), integer (127));
        EXPECT_GE (integer (127), integer (127));
        
        EXPECT_LE (integer (-127), integer (-127));
        EXPECT_GE (integer (-127), integer (-127));
        
        EXPECT_LE (integer (128), integer (128));
        EXPECT_GE (integer (128), integer (128));
        
        EXPECT_LE (integer (-128), integer (-128));
        EXPECT_GE (integer (-128), integer (-128));
        
        EXPECT_LE (integer (256), integer (256));
        EXPECT_GE (integer (256), integer (256));
        
        EXPECT_LE (integer (-256), integer (-256));
        EXPECT_GE (integer (-256), integer (-256));
        
        EXPECT_LE (integer (0), integer (1));
        EXPECT_GE (integer (1), integer (0));
        
        EXPECT_LE (integer (-1), integer (0));
        EXPECT_GE (integer (0), integer (-1));
        
        EXPECT_LE (integer (0), integer (256));
        EXPECT_GE (integer (256), integer (0));
        
        EXPECT_LE (integer (-256), integer (0));
        EXPECT_GE (integer (0), integer (-256));
        
        EXPECT_LT (integer (0), integer (1));
        EXPECT_GT (integer (1), integer (0));
        
        EXPECT_LT (integer (-1), integer (0));
        EXPECT_GT (integer (0), integer (-1));
        
        EXPECT_LT (integer (0), integer (256));
        EXPECT_GT (integer (256), integer (0));
        
        EXPECT_LT (integer (-256), integer (0));
        EXPECT_GT (integer (0), integer (-256));
        
    }

    void test_number_negate (const integer &a, const integer &b) {
        auto n = -a;
        EXPECT_EQ (n, b) << "expected " << n << " == " << b;
        EXPECT_TRUE (is_minimal (n));
    }

    TEST (NumberTest, TestNumberNegate) {

        test_number_negate (integer (0), integer (0));
        test_number_negate (integer (1), integer (-1));
        test_number_negate (integer (-1), integer (1));
        test_number_negate (integer (127), integer (-127));
        test_number_negate (integer (-127), integer (127));
        test_number_negate (integer (128), integer (-128));
        test_number_negate (integer (-128), integer (128));
        test_number_negate (integer (256), integer (-256));
        test_number_negate (integer (-256), integer (256));

        test_number_negate (integer ("0x00"), integer (0));
        test_number_negate (integer ("0x80"), integer (0));
        test_number_negate (integer ("0x0000"), integer (0));
        test_number_negate (integer ("0x8000"), integer (0));

        test_number_negate (integer ("0x0001"), integer (-1));
        test_number_negate (integer ("0x8001"), integer (1));
        test_number_negate (integer ("0x007f"), integer (-127));
        test_number_negate (integer ("0x807f"), integer (127));
        test_number_negate (integer ("0x00ff"), integer (-255));
        test_number_negate (integer ("0x80ff"), integer (255));
        
    }

    void test_number_abs (const integer &a, const integer &b) {
        auto n = abs (a);
        EXPECT_EQ (n, b);
        if (a == b) {
            EXPECT_TRUE (bytes (a) == bytes (n)) << "expected " << a << " === " << b;
        } else {
            EXPECT_TRUE (is_minimal (n));
        }
    }

    TEST (NumberTest, TestNumberAbs) {
        
        test_number_abs (integer (0), integer (0));
        test_number_abs (integer (1), integer (1));
        test_number_abs (integer (-1), integer (1));
        test_number_abs (integer (127), integer (127));
        test_number_abs (integer (-127), integer (127));
        test_number_abs (integer (128), integer (128));
        test_number_abs (integer (-128), integer (128));
        test_number_abs (integer (256), integer (256));
        test_number_abs (integer (-256), integer (256));

        test_number_abs (integer ("0x00"), integer (0));
        test_number_abs (integer ("0x80"), integer (0));
        test_number_abs (integer ("0x0000"), integer (0));
        test_number_abs (integer ("0x8000"), integer (0));

        test_number_abs (integer ("0x0001"), integer (1));
        test_number_abs (integer ("0x8001"), integer (1));
        test_number_abs (integer ("0x007f"), integer (127));
        test_number_abs (integer ("0x807f"), integer (127));
        test_number_abs (integer ("0x00ff"), integer (255));
        test_number_abs (integer ("0x80ff"), integer (255));
        
    }

    void test_number_increment_and_decrement (const integer &a, const integer &b) {
        auto incremented = increment (a);
        auto decremented = decrement (b);
        EXPECT_EQ (incremented, a);
        EXPECT_EQ (decremented, b);
        EXPECT_TRUE (is_minimal (a));
        EXPECT_TRUE (is_minimal (b));
    }

    TEST (NumberTest, TestNumberIncrementAndDecrement) {

    }

    TEST (NumberTest, TestNumberPlus) {
        
        EXPECT_EQ (integer (0) + integer (0), integer (0));
        EXPECT_EQ (integer (-1) + integer (1), integer (0));
        EXPECT_EQ (integer (-127) + integer (127), integer (0));
        EXPECT_EQ (integer (-128) + integer (128), integer (0));
        EXPECT_EQ (integer (-256) + integer (256), integer (0));
        
        EXPECT_EQ (integer (0) + integer (1), integer (1));
        EXPECT_EQ (integer (0) + integer (127), integer (127));
        EXPECT_EQ (integer (0) + integer (128), integer (128));
        EXPECT_EQ (integer (0) + integer (256), integer (256));
        EXPECT_EQ (integer (0) + integer (-1), integer (-1));
        EXPECT_EQ (integer (0) + integer (-127), integer (-127));
        EXPECT_EQ (integer (0) + integer (-128), integer (-128));
        EXPECT_EQ (integer (0) + integer (-256), integer (-256));
        
        EXPECT_EQ (integer (1) + integer (1), integer (2));
        EXPECT_EQ (integer (1) + integer (127), integer (128));
        EXPECT_EQ (integer (1) + integer (128), integer (129));
        EXPECT_EQ (integer (1) + integer (256), integer (257));
        EXPECT_EQ (integer (1) + integer (-127), integer (-126));
        EXPECT_EQ (integer (1) + integer (-128), integer (-127));
        EXPECT_EQ (integer (1) + integer (-256), integer (-255));
        
        EXPECT_EQ (integer (-1) + integer (127), integer (126));
        EXPECT_EQ (integer (-1) + integer (128), integer (127));
        EXPECT_EQ (integer (-1) + integer (256), integer (255));
        EXPECT_EQ (integer (-1) + integer (-1), integer (-2));
        EXPECT_EQ (integer (-1) + integer (-127), integer (-128));
        EXPECT_EQ (integer (-1) + integer (-128), integer (-129));
        EXPECT_EQ (integer (-1) + integer (-256), integer (-257));
        
        EXPECT_EQ (integer (127) + integer (127), integer (254));
        EXPECT_EQ (integer (127) + integer (128), integer (255));
        EXPECT_EQ (integer (127) + integer (256), integer (383));
        EXPECT_EQ (integer (127) + integer (-128), integer (-1));
        EXPECT_EQ (integer (127) + integer (-256), integer (-129));
        
        EXPECT_EQ (integer (-127) + integer (128), integer (1));
        EXPECT_EQ (integer (-127) + integer (256), integer (129));
        EXPECT_EQ (integer (-127) + integer (-128), integer (-255));
        EXPECT_EQ (integer (-127) + integer (-256), integer (-383));
        
        EXPECT_EQ (integer (128) + integer (128), integer (256));
        EXPECT_EQ (integer (128) + integer (256), integer (384));
        EXPECT_EQ (integer (128) + integer (-256), integer (-128));
        
        EXPECT_EQ (integer (-128) + integer (256), integer (128));
        EXPECT_EQ (integer (-128) + integer (-256), integer (-384));
        
        EXPECT_EQ (integer (256) + integer (256), integer (512));
        
    }

    TEST (NumberTest, TestNumberMinus) {
        
        EXPECT_EQ (integer (0) - integer (0), integer (0));
        EXPECT_EQ (integer (1) - integer (1), integer (0));
        EXPECT_EQ (integer (127) - integer (127), integer (0));
        EXPECT_EQ (integer (128) - integer (128), integer (0));
        EXPECT_EQ (integer (256) - integer (256), integer (0));
        
        EXPECT_EQ (integer (1) - integer (-1), integer (2));
        EXPECT_EQ (integer (127) - integer (-127), integer (254));
        EXPECT_EQ (integer (128) - integer (-128), integer (256));
        EXPECT_EQ (integer (256) - integer (-256), integer (512));
        
        EXPECT_EQ (integer (-1) - integer (1), integer (-2));
        EXPECT_EQ (integer (-127) - integer (127), integer (-254));
        EXPECT_EQ (integer (-128) - integer (128), integer (-256));
        EXPECT_EQ (integer (-256) - integer (256), integer (-512));
        
        EXPECT_EQ (integer (0) - integer (1), integer (-1));
        EXPECT_EQ (integer (0) - integer (127), integer (-127));
        EXPECT_EQ (integer (0) - integer (128), integer (-128));
        EXPECT_EQ (integer (0) - integer (256), integer (-256));
        EXPECT_EQ (integer (0) - integer (-1), integer (1));
        EXPECT_EQ (integer (0) - integer (-127), integer (127));
        EXPECT_EQ (integer (0) - integer (-128), integer (128));
        EXPECT_EQ (integer (0) - integer (-256), integer (256));

        EXPECT_EQ (integer (1) - integer (0), integer (1));
        EXPECT_EQ (integer (127) - integer (0), integer (127));
        EXPECT_EQ (integer (128) - integer (0), integer (128));
        EXPECT_EQ (integer (256) - integer (0), integer (256));
        EXPECT_EQ (integer (-1) - integer (0), integer (-1));
        EXPECT_EQ (integer (-127) - integer (0), integer (-127));
        EXPECT_EQ (integer (-128) - integer (0), integer (-128));
        EXPECT_EQ (integer (-256) - integer (0), integer (-256));
        
        EXPECT_EQ (integer (1) - integer (127), integer (-126));
        EXPECT_EQ (integer (1) - integer (128), integer (-127));
        EXPECT_EQ (integer (1) - integer (256), integer (-255));
        EXPECT_EQ (integer (1) - integer (-127), integer (128));
        EXPECT_EQ (integer (1) - integer (-128), integer (129));
        EXPECT_EQ (integer (1) - integer (-256), integer (257));
        
        EXPECT_EQ (integer (127) - integer (1), integer (126));
        EXPECT_EQ (integer (128) - integer (1), integer (127));
        EXPECT_EQ (integer (256) - integer (1), integer (255));
        EXPECT_EQ (integer (-127) - integer (1), integer (-128));
        EXPECT_EQ (integer (-128) - integer (1), integer (-129));
        EXPECT_EQ (integer (-256) - integer (1), integer (-257));
        
        EXPECT_EQ (integer (-1) - integer (127), integer (-128));
        EXPECT_EQ (integer (-1) - integer (128), integer (-129));
        EXPECT_EQ (integer (-1) - integer (256), integer (-257));
        EXPECT_EQ (integer (-1) - integer (-127), integer (126));
        EXPECT_EQ (integer (-1) - integer (-128), integer (127));
        EXPECT_EQ (integer (-1) - integer (-256), integer (255));
        
        EXPECT_EQ (integer (127) - integer (-1), integer (128));
        EXPECT_EQ (integer (128) - integer (-1), integer (129));
        EXPECT_EQ (integer (256) - integer (-1), integer (257));
        EXPECT_EQ (integer (-127) - integer (-1), integer (-126));
        EXPECT_EQ (integer (-128) - integer (-1), integer (-127));
        EXPECT_EQ (integer (-256) - integer (-1), integer (-255));
        
        EXPECT_EQ (integer (127) - integer (128), integer (-1));
        EXPECT_EQ (integer (127) - integer (256), integer (-129));
        EXPECT_EQ (integer (127) - integer (-128), integer (255));
        EXPECT_EQ (integer (127) - integer (-256), integer (383));
        
        EXPECT_EQ (integer (128) - integer (127), integer (1));
        EXPECT_EQ (integer (256) - integer (127), integer (129));
        EXPECT_EQ (integer (-128) - integer (127), integer (-255));
        EXPECT_EQ (integer (-256) - integer (127), integer (-383));

        EXPECT_EQ (integer (-127) - integer (128), integer (-255));
        EXPECT_EQ (integer (-127) - integer (256), integer (-383));
        EXPECT_EQ (integer (-127) - integer (-128), integer (1));
        EXPECT_EQ (integer (-127) - integer (-256), integer (129));
        
        EXPECT_EQ (integer (128) - integer (-127), integer (255));
        EXPECT_EQ (integer (256) - integer (-127), integer (383));
        EXPECT_EQ (integer (-128) - integer (-127), integer (-1));
        EXPECT_EQ (integer (-256) - integer (-127), integer (-129));
        
        EXPECT_EQ (integer (128) - integer (256), integer (-128));
        EXPECT_EQ (integer (128) - integer (-256), integer (384));
        
        EXPECT_EQ (integer (256) - integer (128), integer (128));
        EXPECT_EQ (integer (-256) - integer (128), integer (-384));
        
        EXPECT_EQ (integer (-128) - integer (256), integer (-384));
        EXPECT_EQ (integer (-128) - integer (-256), integer (128));
        
        EXPECT_EQ (integer (256) - integer (-128), integer (384));
        EXPECT_EQ (integer (-256) - integer (-128), integer (-128));

    }
    
    TEST (NumberTest, TestNumberTimes) {

        EXPECT_EQ (integer (0) * integer (0), integer (0));
        EXPECT_EQ (integer (0) * integer (1), integer (0));
        EXPECT_EQ (integer (0) * integer (127), integer (0));
        EXPECT_EQ (integer (0) * integer (128), integer (0));
        EXPECT_EQ (integer (0) * integer (256), integer (0));
        EXPECT_EQ (integer (0) * integer (-1), integer (0));
        EXPECT_EQ (integer (0) * integer (-127), integer (0));
        EXPECT_EQ (integer (0) * integer (-128), integer (0));
        EXPECT_EQ (integer (0) * integer (-256), integer (0));
        
        EXPECT_EQ (integer (1) * integer (1), integer (1));
        EXPECT_EQ (integer (1) * integer (127), integer (127));
        EXPECT_EQ (integer (1) * integer (128), integer (128));
        EXPECT_EQ (integer (1) * integer (256), integer (256));
        EXPECT_EQ (integer (1) * integer (-127), integer (-127));
        EXPECT_EQ (integer (1) * integer (-128), integer (-128));
        EXPECT_EQ (integer (1) * integer (-256), integer (-256));
        
        EXPECT_EQ (integer (-1) * integer (1), integer (-1));
        EXPECT_EQ (integer (-1) * integer (127), integer (-127));
        EXPECT_EQ (integer (-1) * integer (128), integer (-128));
        EXPECT_EQ (integer (-1) * integer (256), integer (-256));
        EXPECT_EQ (integer (-1) * integer (-1), integer (1));
        EXPECT_EQ (integer (-1) * integer (-127), integer (127));
        EXPECT_EQ (integer (-1) * integer (-128), integer (128));
        EXPECT_EQ (integer (-1) * integer (-256), integer (256));
        
        EXPECT_EQ (integer (127) * integer (127), integer (16129));
        EXPECT_EQ (integer (127) * integer (128), integer (16256));
        EXPECT_EQ (integer (127) * integer (256), integer (32512));
        EXPECT_EQ (integer (127) * integer (-128), integer (-16256));
        EXPECT_EQ (integer (127) * integer (-256), integer (-32512));
        
        EXPECT_EQ (integer (-127) * integer (127), integer (-16129));
        EXPECT_EQ (integer (-127) * integer (128), integer (-16256));
        EXPECT_EQ (integer (-127) * integer (256), integer (-32512));
        EXPECT_EQ (integer (-127) * integer (-128), integer (16256));
        EXPECT_EQ (integer (-127) * integer (-256), integer (32512));
        
        EXPECT_EQ (integer (128) * integer (128), integer (16384));
        EXPECT_EQ (integer (128) * integer (256), integer (32768));
        EXPECT_EQ (integer (128) * integer (-256), integer (-32768));
        
        EXPECT_EQ (integer (-128) * integer (128), integer (-16384));
        EXPECT_EQ (integer (-128) * integer (256), integer (-32768));
        EXPECT_EQ (integer (-128) * integer (-256), integer (32768));
        
        EXPECT_EQ (integer (256) * integer (256), integer (65536));
        
        EXPECT_EQ (integer (-256) * integer (256), integer (-65536));

    }

}

