// Copyright (c) 2021 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/script.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin {
    
    TEST (NumberTest, TestPushNumber) {
        
        EXPECT_EQ (compile (push_data (0)), bytes {OP_0});
        EXPECT_EQ (compile (push_data (Z (0))), bytes {OP_0});
        EXPECT_EQ (compile (push_data (N (0))), bytes {OP_0});
        EXPECT_EQ (compile (push_data (1)), bytes {OP_1});
        EXPECT_EQ (compile (push_data (Z (1))), bytes {OP_1});
        EXPECT_EQ (compile (push_data (N (1))), bytes {OP_1});
        EXPECT_EQ (compile (push_data (-1)), bytes {OP_1NEGATE});
        EXPECT_EQ (compile (push_data (Z (-1))), bytes {OP_1NEGATE});
        EXPECT_EQ (compile (push_data (16)), bytes {OP_16});
        EXPECT_EQ (compile (push_data (Z (16))), bytes {OP_16});
        EXPECT_EQ (compile (push_data (N (16))), bytes {OP_16});

        auto test_program_1 = bytes {OP_PUSHSIZE1, 0x82};
        auto test_program_2 = bytes {OP_PUSHSIZE1, 0x11};
        EXPECT_EQ (compile (push_data (-2)), test_program_1);
        EXPECT_EQ (compile (push_data (Z (-2))), test_program_1);
        EXPECT_EQ (compile (push_data (17)), test_program_2);
        EXPECT_EQ (compile (push_data (Z (17))), test_program_2);
        EXPECT_EQ (compile (push_data (N (17))), test_program_2);
        
        auto test_program_3 = bytes {OP_PUSHSIZE1, 0xff};
        auto test_program_4 = bytes {OP_PUSHSIZE1, 0x7f};
        EXPECT_EQ (compile (push_data (-127)), test_program_3);
        EXPECT_EQ (compile (push_data (Z (-127))), test_program_3);
        EXPECT_EQ (compile (push_data (127)), test_program_4);
        EXPECT_EQ (compile (push_data (Z (127))), test_program_4);
        EXPECT_EQ (compile (push_data (N (127))), test_program_4);
        
        auto test_program_5 = bytes {OP_PUSHSIZE2, 0xff, 0x80};
        auto test_program_6 = bytes {OP_PUSHSIZE2, 0xff, 0x00};
        EXPECT_EQ (compile (push_data (-255)), test_program_5);
        EXPECT_EQ (compile (push_data (Z (-255))), test_program_5);
        EXPECT_EQ (compile (push_data (255)), test_program_6);
        EXPECT_EQ (compile (push_data (Z (255))), test_program_6);
        EXPECT_EQ (compile (push_data (N (255))), test_program_6);
        
    }
    
    TEST (NumberTest, TestNumberConstructorsInt) {
        
        EXPECT_EQ (bytes_view (Z (0)), bytes ());
        EXPECT_EQ (bytes_view (Z (1)), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (Z (-1)), *encoding::hex::read  ("81"));
        EXPECT_EQ (bytes_view (Z (127)), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (Z (-127)), *encoding::hex::read  ("ff"));
        EXPECT_EQ (bytes_view (Z (128)), *encoding::hex::read  ("8000"));
        EXPECT_EQ (bytes_view (Z (-128)), *encoding::hex::read  ("8080"));
        EXPECT_EQ (bytes_view (Z (256)), *encoding::hex::read  ("0001"));
        EXPECT_EQ (bytes_view (Z (-256)), *encoding::hex::read  ("0081"));

        EXPECT_EQ (bytes_view (N (0)), bytes ());
        EXPECT_EQ (bytes_view (N (1)), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (N (127)), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (N (128)), *encoding::hex::read  ("8000"));
        EXPECT_EQ (bytes_view (N (256)), *encoding::hex::read  ("0001"));
        
    }
    
    TEST (NumberTest, TestNumberConstructorsDecimalPositive) {

        EXPECT_EQ (bytes_view (Z ("0")), *encoding::hex::read  (""));
        EXPECT_EQ (bytes_view (Z ("127")), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (Z ("128")), *encoding::hex::read  ("8000"));
        EXPECT_EQ (bytes_view (Z ("256")), *encoding::hex::read  ("0001"));

        EXPECT_EQ (bytes_view (N ("1")), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (N ("127")), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (N ("128")), *encoding::hex::read  ("8000"));
        EXPECT_EQ (bytes_view (N ("256")), *encoding::hex::read  ("0001"));
        
    }
    
    TEST (NumberTest, TestNumberConstructorsHexidecZ) {
        
        EXPECT_EQ (bytes_view (Z ("0")), bytes ());
        EXPECT_EQ (bytes_view (Z ("0x00")), *encoding::hex::read  ("00"));
        EXPECT_EQ (bytes_view (Z ("0x80")), *encoding::hex::read  ("80"));
        EXPECT_EQ (bytes_view (Z ("0x0000")), *encoding::hex::read  ("0000"));
        EXPECT_EQ (bytes_view (Z ("0x8000")), *encoding::hex::read  ("0080"));
        EXPECT_EQ (bytes_view (Z ("0x000000")), *encoding::hex::read  ("000000"));
        EXPECT_EQ (bytes_view (Z ("0x800000")), *encoding::hex::read  ("000080"));

        EXPECT_EQ (bytes_view (Z ("1")), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (Z ("-1")), *encoding::hex::read  ("81"));
        EXPECT_EQ (bytes_view (Z ("0x01")), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (Z ("0x81")), *encoding::hex::read  ("81"));
        EXPECT_EQ (bytes_view (Z ("0x0001")), *encoding::hex::read  ("0100"));
        EXPECT_EQ (bytes_view (Z ("0x8001")), *encoding::hex::read  ("0180"));
        EXPECT_EQ (bytes_view (Z ("0x000001")), *encoding::hex::read  ("010000"));
        EXPECT_EQ (bytes_view (Z ("0x800001")), *encoding::hex::read  ("010080"));
        
        EXPECT_EQ (bytes_view (Z ("0x7f")), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (Z ("0xff")), *encoding::hex::read  ("ff"));
        EXPECT_EQ (bytes_view (Z ("0x007f")), *encoding::hex::read  ("7f00"));
        EXPECT_EQ (bytes_view (Z ("0x807f")), *encoding::hex::read  ("7f80"));
        EXPECT_EQ (bytes_view (Z ("0x00007f")), *encoding::hex::read  ("7f0000"));
        EXPECT_EQ (bytes_view (Z ("0x80007f")), *encoding::hex::read  ("7f0080"));
        
    }

    TEST (NumberTest, TestNumberMinimalZ) {
        
        EXPECT_TRUE (is_minimal_size (Z ("0")));
        EXPECT_FALSE (is_minimal_size (Z ("0x00")));
        EXPECT_FALSE (is_minimal_size (Z ("0x80")));
        EXPECT_FALSE (is_minimal_size (Z ("0x0000")));
        EXPECT_FALSE (is_minimal_size (Z ("0x8000")));
        EXPECT_FALSE (is_minimal_size (Z ("0x000000")));
        EXPECT_FALSE (is_minimal_size (Z ("0x800000")));

        EXPECT_TRUE (is_minimal_size (Z ("0x01")));
        EXPECT_TRUE (is_minimal_size (Z ("0x81")));
        EXPECT_FALSE (is_minimal_size (Z ("0x0001")));
        EXPECT_FALSE (is_minimal_size (Z ("0x8001")));
        EXPECT_FALSE (is_minimal_size (Z ("0x000001")));
        EXPECT_FALSE (is_minimal_size (Z ("0x800001")));
        
        EXPECT_TRUE (is_minimal_size (Z ("0x7f")));
        EXPECT_TRUE (is_minimal_size (Z ("0xff")));
        EXPECT_FALSE (is_minimal_size (Z ("0x007f")));
        EXPECT_FALSE (is_minimal_size (Z ("0x807f")));
        EXPECT_FALSE (is_minimal_size (Z ("0x00007f")));
        EXPECT_FALSE (is_minimal_size (Z ("0x80007f")));
        
    }
    
    TEST (NumberTest, TestNumberTrimZ) {
        
        EXPECT_EQ (bytes_view (trim (Z ("0x00"))), bytes ());
        EXPECT_EQ (bytes_view (trim (Z ("0x80"))), bytes ());
        EXPECT_EQ (bytes_view (trim (Z ("0x0000"))), bytes ());
        EXPECT_EQ (bytes_view (trim (Z ("0x8000"))), bytes ());
        EXPECT_EQ (bytes_view (trim (Z ("0x000000"))), bytes ());
        EXPECT_EQ (bytes_view (trim (Z ("0x800000"))), bytes ());
        
        EXPECT_EQ (bytes_view (trim (Z ("0x01"))), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (trim (Z ("0x81"))), *encoding::hex::read  ("81"));
        EXPECT_EQ (bytes_view (trim (Z ("0x0001"))), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (trim (Z ("0x8001"))), *encoding::hex::read  ("81"));
        EXPECT_EQ (bytes_view (trim (Z ("0x000001"))), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (trim (Z ("0x800001"))), *encoding::hex::read  ("81"));
        
        EXPECT_EQ (bytes_view (trim (Z ("0x7f"))), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (trim (Z ("0xff"))), *encoding::hex::read  ("ff"));
        EXPECT_EQ (bytes_view (trim (Z ("0x007f"))), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (trim (Z ("0x807f"))), *encoding::hex::read  ("ff"));
        EXPECT_EQ (bytes_view (trim (Z ("0x00007f"))), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (trim (Z ("0x80007f"))), *encoding::hex::read  ("ff"));
        
    }
    
    TEST (NumberTest, TestNumberSignZ) {
        
        EXPECT_TRUE (is_zero (Z ("0x00")));
        EXPECT_TRUE (is_zero (Z ("0x80")));
        EXPECT_TRUE (is_zero (Z ("0x0000")));
        EXPECT_TRUE (is_zero (Z ("0x8000")));
        EXPECT_TRUE (is_zero (Z ("0x000000")));
        EXPECT_TRUE (is_zero (Z ("0x800000")));
        
        EXPECT_FALSE (is_zero (Z ("0x01")));
        EXPECT_FALSE (is_zero (Z ("0x81")));
        EXPECT_FALSE (is_zero (Z ("0x0001")));
        EXPECT_FALSE (is_zero (Z ("0x8001")));
        EXPECT_FALSE (is_zero (Z ("0x000001")));
        EXPECT_FALSE (is_zero (Z ("0x800001")));
        
        EXPECT_FALSE (is_zero (Z ("0x0080")));
        EXPECT_FALSE (is_zero (Z ("0x8080")));
        EXPECT_FALSE (is_zero (Z ("0x000080")));
        EXPECT_FALSE (is_zero (Z ("0x800080")));

        EXPECT_EQ (Z ("0x00").sign_bit (), false);
        EXPECT_EQ (Z ("0x80").sign_bit (), true);
        EXPECT_EQ (Z ("0x0000").sign_bit (), false);
        EXPECT_EQ (Z ("0x8000").sign_bit (), true);
        EXPECT_EQ (Z ("0x000000").sign_bit (), false);
        EXPECT_EQ (Z ("0x800000").sign_bit (), true);
        
        EXPECT_EQ (Z ("0x01").sign_bit (), false);
        EXPECT_EQ (Z ("0x81").sign_bit (), true);
        EXPECT_EQ (Z ("0x0001").sign_bit (), false);
        EXPECT_EQ (Z ("0x8001").sign_bit (), true);
        EXPECT_EQ (Z ("0x000001").sign_bit (), false);
        EXPECT_EQ (Z ("0x800001").sign_bit (), true);
        
        EXPECT_EQ (Z ("0x0080").sign_bit (), false);
        EXPECT_EQ (Z ("0x8080").sign_bit (), true);
        EXPECT_EQ (Z ("0x000080").sign_bit (), false);
        EXPECT_EQ (Z ("0x800080").sign_bit (), true);

        EXPECT_TRUE (is_positive_zero (Z ("0x00")));
        EXPECT_FALSE (is_positive_zero (Z ("0x80")));
        EXPECT_TRUE (is_positive_zero (Z ("0x0000")));
        EXPECT_FALSE (is_positive_zero (Z ("0x8000")));
        EXPECT_TRUE (is_positive_zero (Z ("0x000000")));
        EXPECT_FALSE (is_positive_zero (Z ("0x800000")));
        
        EXPECT_FALSE (is_positive_zero (Z ("0x01")));
        EXPECT_FALSE (is_positive_zero (Z ("0x81")));
        EXPECT_FALSE (is_positive_zero (Z ("0x0001")));
        EXPECT_FALSE (is_positive_zero (Z ("0x8001")));
        EXPECT_FALSE (is_positive_zero (Z ("0x000001")));
        EXPECT_FALSE (is_positive_zero (Z ("0x800001")));
        
        EXPECT_FALSE (is_negative_zero (Z ("0x00")));
        EXPECT_TRUE (is_negative_zero (Z ("0x80")));
        EXPECT_FALSE (is_negative_zero (Z ("0x0000")));
        EXPECT_TRUE (is_negative_zero (Z ("0x8000")));
        EXPECT_FALSE (is_negative_zero (Z ("0x000000")));
        EXPECT_TRUE (is_negative_zero (Z ("0x800000")));

        EXPECT_FALSE (is_negative_zero (Z ("0x01")));
        EXPECT_FALSE (is_negative_zero (Z ("0x81")));
        EXPECT_FALSE (is_negative_zero (Z ("0x0001")));
        EXPECT_FALSE (is_negative_zero (Z ("0x8001")));
        EXPECT_FALSE (is_negative_zero (Z ("0x000001")));
        EXPECT_FALSE (is_negative_zero (Z ("0x800001")));
        
        EXPECT_FALSE (is_positive (Z ("0x00")));
        EXPECT_FALSE (is_positive (Z ("0x80")));
        EXPECT_FALSE (is_positive (Z ("0x0000")));
        EXPECT_FALSE (is_positive (Z ("0x8000")));
        EXPECT_FALSE (is_positive (Z ("0x000000")));
        EXPECT_FALSE (is_positive (Z ("0x800000")));
        
        EXPECT_FALSE (is_negative (Z ("0x00")));
        EXPECT_FALSE (is_negative (Z ("0x80")));
        EXPECT_FALSE (is_negative (Z ("0x0000")));
        EXPECT_FALSE (is_negative (Z ("0x8000")));
        EXPECT_FALSE (is_negative (Z ("0x000000")));
        EXPECT_FALSE (is_negative (Z ("0x800000")));
        
        EXPECT_TRUE (is_positive (Z ("0x01")));
        EXPECT_FALSE (is_positive (Z ("0x81")));
        EXPECT_TRUE (is_positive (Z ("0x0001")));
        EXPECT_FALSE (is_positive (Z ("0x8001")));
        EXPECT_TRUE (is_positive (Z ("0x000001")));
        EXPECT_FALSE (is_positive (Z ("0x800001")));
        
        EXPECT_FALSE (is_negative (Z ("0x01")));
        EXPECT_TRUE (is_negative (Z ("0x81")));
        EXPECT_FALSE (is_negative (Z ("0x0001")));
        EXPECT_TRUE (is_negative (Z ("0x8001")));
        EXPECT_FALSE (is_negative (Z ("0x000001")));
        EXPECT_TRUE (is_negative (Z ("0x800001")));
        
        EXPECT_TRUE (is_positive (Z ("0x0080")));
        EXPECT_FALSE (is_positive (Z ("0x8080")));
        EXPECT_TRUE (is_positive (Z ("0x000080")));
        EXPECT_FALSE (is_positive (Z ("0x800080")));
        
        EXPECT_FALSE (is_negative (Z ("0x0080")));
        EXPECT_TRUE (is_negative (Z ("0x8080")));
        EXPECT_FALSE (is_negative (Z ("0x000080")));
        EXPECT_TRUE (is_negative (Z ("0x800080")));
    
    }

    TEST (NumberTest, TestNumberConstructorsDecimalNegative) {
        
        //EXPECT_EQ (bytes_view (Z ("-0")), *encoding::hex::read  ("80"));
        EXPECT_EQ (bytes_view (Z ("-127")), *encoding::hex::read  ("ff"));
        EXPECT_EQ (bytes_view (Z ("-128")), *encoding::hex::read  ("8080"));
        EXPECT_EQ (bytes_view (Z ("-256")), *encoding::hex::read  ("0081"));
        
        //EXPECT_EQ (bytes_view (N ("-0")), *encoding::hex::read  ("80"));
        EXPECT_THROW (N ("-1"), std::logic_error);
        EXPECT_THROW (N ("-127"), std::logic_error);
        EXPECT_THROW (N ("-128"), std::logic_error);
        EXPECT_THROW (N ("-256"), std::logic_error);

    }
    
    TEST (NumberTest, TestNumberConstructorsN) {
        
        EXPECT_EQ (bytes_view (N ("0")), bytes ());
        EXPECT_EQ (bytes_view (N ("0x00")), *encoding::hex::read  ("00"));
        EXPECT_EQ (bytes_view (N ("0x80")), *encoding::hex::read  ("80"));
        EXPECT_EQ (bytes_view (N ("0x0000")), *encoding::hex::read  ("0000"));
        EXPECT_EQ (bytes_view (N ("0x8000")), *encoding::hex::read  ("0080"));
        EXPECT_EQ (bytes_view (N ("0x000000")), *encoding::hex::read  ("000000"));
        EXPECT_EQ (bytes_view (N ("0x800000")), *encoding::hex::read  ("000080"));
        
        EXPECT_EQ (bytes_view (N ("0x01")), *encoding::hex::read  ("01"));
        EXPECT_THROW (N ("0x81"), std::logic_error);
        EXPECT_EQ (bytes_view (N ("0x0001")), *encoding::hex::read  ("0100"));
        EXPECT_THROW (N ("0x8001"), std::logic_error);
        EXPECT_EQ (bytes_view (N ("0x000001")), *encoding::hex::read  ("010000"));
        EXPECT_THROW (N ("0x800001"), std::logic_error);
        
        EXPECT_EQ (bytes_view (N ("0x7f")), *encoding::hex::read  ("7f"));
        EXPECT_THROW (N ("0xff"), std::logic_error);
        EXPECT_EQ (bytes_view (N ("0x007f")), *encoding::hex::read  ("7f00"));
        EXPECT_THROW (N ("0x807f"), std::logic_error);
        EXPECT_EQ (bytes_view (N ("0x00007f")), *encoding::hex::read  ("7f0000"));
        EXPECT_THROW (N ("0x80007f"), std::logic_error);
        
    }

    TEST (NumberTest, TestNumberTrimN) {
        
        EXPECT_EQ (bytes_view (trim (N ("0x00"))), bytes ());
        EXPECT_EQ (bytes_view (trim (N ("0x80"))), bytes ());
        EXPECT_EQ (bytes_view (trim (N ("0x0000"))), bytes ());
        EXPECT_EQ (bytes_view (trim (N ("0x8000"))), bytes ());
        EXPECT_EQ (bytes_view (trim (N ("0x000000"))), bytes ());
        EXPECT_EQ (bytes_view (trim (N ("0x800000"))), bytes ());
        
        EXPECT_EQ (bytes_view (trim (N ("0x01"))), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (trim (N ("0x0001"))), *encoding::hex::read  ("01"));
        EXPECT_EQ (bytes_view (trim (N ("0x000001"))), *encoding::hex::read  ("01"));
        
        EXPECT_EQ (bytes_view (trim (N ("0x7f"))), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (trim (N ("0x007f"))), *encoding::hex::read  ("7f"));
        EXPECT_EQ (bytes_view (trim (N ("0x00007f"))), *encoding::hex::read  ("7f"));
        
    }
    
    TEST (NumberTest, TestNumberMinimalN) {
        
        EXPECT_TRUE (is_minimal_size (N ("0")));
        EXPECT_FALSE (is_minimal_size (N ("0x00")));
        EXPECT_FALSE (is_minimal_size (N ("0x80")));
        EXPECT_FALSE (is_minimal_size (N ("0x0000")));
        EXPECT_FALSE (is_minimal_size (N ("0x8000")));
        EXPECT_FALSE (is_minimal_size (N ("0x000000")));
        EXPECT_FALSE (is_minimal_size (N ("0x800000")));
        
        EXPECT_TRUE (is_minimal_size (N ("0x01")));
        EXPECT_FALSE (is_minimal_size (N ("0x0001")));
        EXPECT_FALSE (is_minimal_size (N ("0x000001")));
        
        EXPECT_TRUE (is_minimal_size (N ("0x7f")));
        EXPECT_FALSE (is_minimal_size (N ("0x007f")));
        EXPECT_FALSE (is_minimal_size (N ("0x00007f")));
        
    }

    TEST (NumberTest, TestNumberZeroN) {
        
        EXPECT_TRUE (is_zero (N ("0x00")));
        EXPECT_TRUE (is_zero (N ("0x80")));
        EXPECT_TRUE (is_zero (N ("0x0000")));
        EXPECT_TRUE (is_zero (N ("0x8000")));
        EXPECT_TRUE (is_zero (N ("0x000000")));
        EXPECT_TRUE (is_zero (N ("0x800000")));
        
        EXPECT_TRUE (is_positive_zero (N ("0x00")));
        EXPECT_FALSE (is_positive_zero (N ("0x80")));
        EXPECT_TRUE (is_positive_zero (N ("0x0000")));
        EXPECT_FALSE (is_positive_zero (N ("0x8000")));
        EXPECT_TRUE (is_positive_zero (N ("0x000000")));
        EXPECT_FALSE (is_positive_zero (N ("0x800000")));

        EXPECT_FALSE (is_negative_zero (N ("0x00")));
        EXPECT_TRUE (is_negative_zero (N ("0x80")));
        EXPECT_FALSE (is_negative_zero (N ("0x0000")));
        EXPECT_TRUE (is_negative_zero (N ("0x8000")));
        EXPECT_FALSE (is_negative_zero (N ("0x000000")));
        EXPECT_TRUE (is_negative_zero (N ("0x800000")));
        
    }
    
    TEST (NumberTest, TestNumberCompare) {
        
        EXPECT_EQ (Z (0), Z ("0"));
        EXPECT_EQ (Z (0), Z ("0x00"));
        EXPECT_EQ (Z (0), Z ("0x80"));
        EXPECT_EQ (Z (0), Z ("0x0000"));
        EXPECT_EQ (Z (0), Z ("0x8000"));
        EXPECT_EQ (Z (0), Z ("0x000000"));
        EXPECT_EQ (Z (0), Z ("0x800000"));
        
        EXPECT_EQ (N (0), N ("0"));
        EXPECT_EQ (N (0), N ("0x00"));
        EXPECT_EQ (N (0), N ("0x80"));
        EXPECT_EQ (N (0), N ("0x0000"));
        EXPECT_EQ (N (0), N ("0x8000"));
        EXPECT_EQ (N (0), N ("0x000000"));
        EXPECT_EQ (N (0), N ("0x800000"));
        
        EXPECT_EQ (Z (0), N (0));
        
        EXPECT_EQ (Z (1), Z ("0x01"));
        EXPECT_EQ (Z (-1), Z ("0x81"));
        EXPECT_EQ (Z (1), Z ("0x0001"));
        EXPECT_EQ (Z (-1), Z ("0x8001"));
        EXPECT_EQ (Z (1), Z ("0x000001"));
        EXPECT_EQ (Z (-1), Z ("0x800001"));
        
        EXPECT_EQ (N (1), N ("0x01"));
        EXPECT_EQ (N (1), N ("0x0001"));
        EXPECT_EQ (N (1), N ("0x000001"));
        
        EXPECT_EQ (Z (1), N (1));
        
        EXPECT_EQ (Z (127), Z ("0x7f"));
        EXPECT_EQ (Z (-127), Z ("0xff"));
        EXPECT_EQ (Z (127), Z ("0x007f"));
        EXPECT_EQ (Z (-127), Z ("0x807f"));
        EXPECT_EQ (Z (127), Z ("0x00007f"));
        EXPECT_EQ (Z (-127), Z ("0x80007f"));
        
        EXPECT_EQ (N (127), N ("0x7f"));
        EXPECT_EQ (N (127), N ("0x007f"));
        EXPECT_EQ (N (127), N ("0x00007f"));
        
        EXPECT_EQ (Z (127), N (127));
        
        EXPECT_EQ (Z (128), Z ("0x0080"));
        EXPECT_EQ (Z (-128), Z ("0x8080"));
        EXPECT_EQ (Z (128), Z ("0x000080"));
        EXPECT_EQ (Z (-128), Z ("0x800080"));
        
        EXPECT_EQ (N (128), N ("0x0080"));
        EXPECT_EQ (N (128), N ("0x000080"));
        
        EXPECT_EQ (Z (128), N (128));
        
        EXPECT_EQ (Z (256), Z ("0x0100"));
        EXPECT_EQ (Z (-256), Z ("0x8100"));
        EXPECT_EQ (Z (256), Z ("0x000100"));
        EXPECT_EQ (Z (-256), Z ("0x800100"));
                                                                                                                                                                                                                                        
        EXPECT_EQ (N (256), N ("0x0100"));
        EXPECT_EQ (N (256), N ("0x000100"));
        
        EXPECT_EQ (Z (256), N (256));
        
        EXPECT_LE (Z (0), Z (0));
        EXPECT_GE (Z (0), Z (0));
        
        EXPECT_LE (N (0), N (0));
        EXPECT_GE (N (0), N (0));
        
        EXPECT_LE (Z (0), N (0));
        EXPECT_GE (Z (0), N (0));
        
        EXPECT_LE (Z (1), Z (1));
        EXPECT_GE (Z (1), Z (1));
        
        EXPECT_LE (N (1), N (1));
        EXPECT_GE (N (1), N (1));
        
        EXPECT_LE (Z (1), N (1));
        EXPECT_GE (Z (1), N (1));
        
        EXPECT_LE (Z (-1), Z (-1));
        EXPECT_GE (Z (-1), Z (-1));
        
        EXPECT_LE (Z (127), Z (127));
        EXPECT_GE (Z (127), Z (127));
        
        EXPECT_LE (N (127), N (127));
        EXPECT_GE (N (127), N (127));
        
        EXPECT_LE (Z (127), N (127));
        EXPECT_GE (Z (127), N (127));
        
        EXPECT_LE (Z (-127), Z (-127));
        EXPECT_GE (Z (-127), Z (-127));
        
        EXPECT_LE (Z (128), Z (128));
        EXPECT_GE (Z (128), Z (128));
        
        EXPECT_LE (N (128), N (128));
        EXPECT_GE (N (128), N (128));
        
        EXPECT_LE (Z (128), N (128));
        EXPECT_GE (Z (128), N (128));
        
        EXPECT_LE (Z (-128), Z (-128));
        EXPECT_GE (Z (-128), Z (-128));
        
        EXPECT_LE (Z (256), Z (256));
        EXPECT_GE (Z (256), Z (256));
        
        EXPECT_LE (N (256), N (256));
        EXPECT_GE (N (256), N (256));
        
        EXPECT_LE (Z (256), N (256));
        EXPECT_GE (Z (256), N (256));
        
        EXPECT_LE (Z (-256), Z (-256));
        EXPECT_GE (Z (-256), Z (-256));
        
        EXPECT_LE (Z (0), Z (1));
        EXPECT_GE (Z (1), Z (0));
        
        EXPECT_LE (N (0), N (1));
        EXPECT_GE (N (1), N (0));
        
        EXPECT_LE (Z (0), N (1));
        EXPECT_GE (Z (1), N (0));
        
        EXPECT_LE (Z (-1), Z (0));
        EXPECT_GE (Z (0), Z (-1));
        
        EXPECT_LE (Z (0), Z (256));
        EXPECT_GE (Z (256), Z (0));
        
        EXPECT_LE (N (0), N (256));
        EXPECT_GE (N (256), N (0));
        
        EXPECT_LE (Z (0), N (256));
        EXPECT_GE (Z (256), N (0));
        
        EXPECT_LE (Z (-256), Z (0));
        EXPECT_GE (Z (0), Z (-256));
        
        EXPECT_LT (Z (0), Z (1));
        EXPECT_GT (Z (1), Z (0));
        
        EXPECT_LT (N (0), N (1));
        EXPECT_GT (N (1), N (0));
        
        EXPECT_LT (Z (0), N (1));
        EXPECT_GT (Z (1), N (0));
        
        EXPECT_LT (Z (-1), Z (0));
        EXPECT_GT (Z (0), Z (-1));
        
        EXPECT_LT (Z (0), Z (256));
        EXPECT_GT (Z (256), Z (0));
        
        EXPECT_LT (N (0), N (256));
        EXPECT_GT (N (256), N (0));
        
        EXPECT_LT (Z (0), N (256));
        EXPECT_GT (Z (256), N (0));
        
        EXPECT_LT (Z (-256), Z (0));
        EXPECT_GT (Z (0), Z (-256));
        
    }

    void test_number_negate (const Z &a, const Z &b) {
        auto n = -a;
        EXPECT_EQ (n, b) << "expected " << n << " == " << b;
        EXPECT_TRUE (is_minimal_size (n));
    }

    TEST (NumberTest, TestNumberNegate) {

        test_number_negate (Z (0), Z (0));
        test_number_negate (Z (1), Z (-1));
        test_number_negate (Z (-1), Z (1));
        test_number_negate (Z (127), Z (-127));
        test_number_negate (Z (-127), Z (127));
        test_number_negate (Z (128), Z (-128));
        test_number_negate (Z (-128), Z (128));
        test_number_negate (Z (256), Z (-256));
        test_number_negate (Z (-256), Z (256));

        test_number_negate (Z ("0x00"), Z (0));
        test_number_negate (Z ("0x80"), Z (0));
        test_number_negate (Z ("0x0000"), Z (0));
        test_number_negate (Z ("0x8000"), Z (0));

        test_number_negate (Z ("0x0001"), Z (-1));
        test_number_negate (Z ("0x8001"), Z (1));
        test_number_negate (Z ("0x007f"), Z (-127));
        test_number_negate (Z ("0x807f"), Z (127));
        test_number_negate (Z ("0x00ff"), Z (-255));
        test_number_negate (Z ("0x80ff"), Z (255));
        
    }

    void test_number_abs (const Z &a, const N &b) {
        auto n = abs (a);
        EXPECT_EQ (n, b);
        if (a == b) {
            EXPECT_TRUE (bytes (a) == bytes (n)) << "expected " << a << " === " << b;
        } else {
            EXPECT_TRUE (is_minimal_size (n));
        }
    }

    TEST (NumberTest, TestNumberAbs) {
        
        test_number_abs (Z (0), N (0));
        test_number_abs (Z (1), N (1));
        test_number_abs (Z (-1), N (1));
        test_number_abs (Z (127), N (127));
        test_number_abs (Z (-127), N (127));
        test_number_abs (Z (128), N (128));
        test_number_abs (Z (-128), N (128));
        test_number_abs (Z (256), N (256));
        test_number_abs (Z (-256), N (256));

        test_number_abs (Z ("0x00"), N (0));
        test_number_abs (Z ("0x80"), N (0));
        test_number_abs (Z ("0x0000"), N (0));
        test_number_abs (Z ("0x8000"), N (0));

        test_number_abs (Z ("0x0001"), N (1));
        test_number_abs (Z ("0x8001"), N (1));
        test_number_abs (Z ("0x007f"), N (127));
        test_number_abs (Z ("0x807f"), N (127));
        test_number_abs (Z ("0x00ff"), N (255));
        test_number_abs (Z ("0x80ff"), N (255));
        
    }

    void test_number_increment_and_decrement (const Z &a, const Z &b) {
        auto incremented = increment (a);
        auto decremented = decrement (b);
        EXPECT_EQ (incremented, a);
        EXPECT_EQ (decremented, b);
        EXPECT_TRUE (is_minimal_size (a));
        EXPECT_TRUE (is_minimal_size (b));
    }

    TEST (NumberTest, TestNumberIncrementAndDecrement) {

    }

    TEST (NumberTest, TestNumberPlus) {
        
        EXPECT_EQ (Z (0) + Z (0), Z (0));
        EXPECT_EQ (Z (-1) + Z (1), Z (0));
        EXPECT_EQ (Z (-127) + Z (127), Z (0));
        EXPECT_EQ (Z (-128) + Z (128), Z (0));
        EXPECT_EQ (Z (-256) + Z (256), Z (0));
        
        EXPECT_EQ (Z (0) + Z (1), Z (1));
        EXPECT_EQ (Z (0) + Z (127), Z (127));
        EXPECT_EQ (Z (0) + Z (128), Z (128));
        EXPECT_EQ (Z (0) + Z (256), Z (256));
        EXPECT_EQ (Z (0) + Z (-1), Z (-1));
        EXPECT_EQ (Z (0) + Z (-127), Z (-127));
        EXPECT_EQ (Z (0) + Z (-128), Z (-128));
        EXPECT_EQ (Z (0) + Z (-256), Z (-256));
        
        EXPECT_EQ (N (0) + N (1), N (1));
        EXPECT_EQ (N (0) + N (127), N (127));
        EXPECT_EQ (N (0) + N (128), N (128));
        EXPECT_EQ (N (0) + N (256), N (256));
        
        EXPECT_EQ (Z (1) + Z (1), Z (2));
        EXPECT_EQ (Z (1) + Z (127), Z (128));
        EXPECT_EQ (Z (1) + Z (128), Z (129));
        EXPECT_EQ (Z (1) + Z (256), Z (257));
        EXPECT_EQ (Z (1) + Z (-127), Z (-126));
        EXPECT_EQ (Z (1) + Z (-128), Z (-127));
        EXPECT_EQ (Z (1) + Z (-256), Z (-255));
        
        EXPECT_EQ (N (1) + N (1), N (2));
        EXPECT_EQ (N (1) + N (127), N (128));
        EXPECT_EQ (N (1) + N (128), N (129));
        EXPECT_EQ (N (1) + N (256), N (257));
        
        EXPECT_EQ (Z (-1) + Z (127), Z (126));
        EXPECT_EQ (Z (-1) + Z (128), Z (127));
        EXPECT_EQ (Z (-1) + Z (256), Z (255));
        EXPECT_EQ (Z (-1) + Z (-1), Z (-2));
        EXPECT_EQ (Z (-1) + Z (-127), Z (-128));
        EXPECT_EQ (Z (-1) + Z (-128), Z (-129));
        EXPECT_EQ (Z (-1) + Z (-256), Z (-257));
        
        EXPECT_EQ (Z (127) + Z (127), Z (254));
        EXPECT_EQ (Z (127) + Z (128), Z (255));
        EXPECT_EQ (Z (127) + Z (256), Z (383));
        EXPECT_EQ (Z (127) + Z (-128), Z (-1));
        EXPECT_EQ (Z (127) + Z (-256), Z (-129));
        
        EXPECT_EQ (N (127) + N (127), N (254));
        EXPECT_EQ (N (127) + N (128), N (255));
        EXPECT_EQ (N (127) + N (256), N (383));
        
        EXPECT_EQ (Z (-127) + Z (128), Z (1));
        EXPECT_EQ (Z (-127) + Z (256), Z (129));
        EXPECT_EQ (Z (-127) + Z (-128), Z (-255));
        EXPECT_EQ (Z (-127) + Z (-256), Z (-383));
        
        EXPECT_EQ (Z (128) + Z (128), Z (256));
        EXPECT_EQ (Z (128) + Z (256), Z (384));
        EXPECT_EQ (Z (128) + Z (-256), Z (-128));
        
        EXPECT_EQ (N (128) + N (128), N (256));
        EXPECT_EQ (N (128) + N (256), N (384));
        
        EXPECT_EQ (Z (-128) + Z (256), Z (128));
        EXPECT_EQ (Z (-128) + Z (-256), Z (-384));
        
        EXPECT_EQ (Z (256) + Z (256), Z (512));
        
        EXPECT_EQ (N (256) + N (256), N (512));
        
    }
    
    TEST (NumberTest, TestNumberMinus) {
        
        EXPECT_EQ (Z (0) - Z (0), Z (0));
        EXPECT_EQ (Z (1) - Z (1), Z (0));
        EXPECT_EQ (Z (127) - Z (127), Z (0));
        EXPECT_EQ (Z (128) - Z (128), Z (0));
        EXPECT_EQ (Z (256) - Z (256), Z (0));
        
        EXPECT_EQ (Z (1) - Z (-1), Z (2));
        EXPECT_EQ (Z (127) - Z (-127), Z (254));
        EXPECT_EQ (Z (128) - Z (-128), Z (256));
        EXPECT_EQ (Z (256) - Z (-256), Z (512));
        
        EXPECT_EQ (Z (-1) - Z (1), Z (-2));
        EXPECT_EQ (Z (-127) - Z (127), Z (-254));
        EXPECT_EQ (Z (-128) - Z (128), Z (-256));
        EXPECT_EQ (Z (-256) - Z (256), Z (-512));
        
        EXPECT_EQ (N (0) - N (0), N (0));
        EXPECT_EQ (N (1) - N (1), N (0));
        EXPECT_EQ (N (127) - N (127), N (0));
        EXPECT_EQ (N (128) - N (128), N (0));
        EXPECT_EQ (N (256) - N (256), N (0));
        
        EXPECT_EQ (Z (0) - Z (1), Z (-1));
        EXPECT_EQ (Z (0) - Z (127), Z (-127));
        EXPECT_EQ (Z (0) - Z (128), Z (-128));
        EXPECT_EQ (Z (0) - Z (256), Z (-256));
        EXPECT_EQ (Z (0) - Z (-1), Z (1));
        EXPECT_EQ (Z (0) - Z (-127), Z (127));
        EXPECT_EQ (Z (0) - Z (-128), Z (128));
        EXPECT_EQ (Z (0) - Z (-256), Z (256));
        
        EXPECT_EQ (N (0) - N (1), N (0));
        EXPECT_EQ (N (0) - N (127), N (0));
        EXPECT_EQ (N (0) - N (128), N (0));
        EXPECT_EQ (N (0) - N (256), N (0));
        
        EXPECT_EQ (Z (1) - Z (0), Z (1));
        EXPECT_EQ (Z (127) - Z (0), Z (127));
        EXPECT_EQ (Z (128) - Z (0), Z (128));
        EXPECT_EQ (Z (256) - Z (0), Z (256));
        EXPECT_EQ (Z (-1) - Z (0), Z (-1));
        EXPECT_EQ (Z (-127) - Z (0), Z (-127));
        EXPECT_EQ (Z (-128) - Z (0), Z (-128));
        EXPECT_EQ (Z (-256) - Z (0), Z (-256));
        
        EXPECT_EQ (N (1) - N (0), N (1));
        EXPECT_EQ (N (127) - N (0), N (127));
        EXPECT_EQ (N (128) - N (0), N (128));
        EXPECT_EQ (N (256) - N (0), N (256));
        
        EXPECT_EQ (Z (1) - Z (127), Z (-126));
        EXPECT_EQ (Z (1) - Z (128), Z (-127));
        EXPECT_EQ (Z (1) - Z (256), Z (-255));
        EXPECT_EQ (Z (1) - Z (-127), Z (128));
        EXPECT_EQ (Z (1) - Z (-128), Z (129));
        EXPECT_EQ (Z (1) - Z (-256), Z (257));
        
        EXPECT_EQ (N (1) - N (127), N (0));
        EXPECT_EQ (N (1) - N (128), N (0));
        EXPECT_EQ (N (1) - N (256), N (0));
        
        EXPECT_EQ (Z (127) - Z (1), Z (126));
        EXPECT_EQ (Z (128) - Z (1), Z (127));
        EXPECT_EQ (Z (256) - Z (1), Z (255));
        EXPECT_EQ (Z (-127) - Z (1), Z (-128));
        EXPECT_EQ (Z (-128) - Z (1), Z (-129));
        EXPECT_EQ (Z (-256) - Z (1), Z (-257));
        
        EXPECT_EQ (N (127) - N (1), N (126));
        EXPECT_EQ (N (128) - N (1), N (127));
        EXPECT_EQ (N (256) - N (1), N (255));
        
        EXPECT_EQ (Z (-1) - Z (127), Z (-128));
        EXPECT_EQ (Z (-1) - Z (128), Z (-129));
        EXPECT_EQ (Z (-1) - Z (256), Z (-257));
        EXPECT_EQ (Z (-1) - Z (-127), Z (126));
        EXPECT_EQ (Z (-1) - Z (-128), Z (127));
        EXPECT_EQ (Z (-1) - Z (-256), Z (255));
        
        EXPECT_EQ (Z (127) - Z (-1), Z (128));
        EXPECT_EQ (Z (128) - Z (-1), Z (129));
        EXPECT_EQ (Z (256) - Z (-1), Z (257));
        EXPECT_EQ (Z (-127) - Z (-1), Z (-126));
        EXPECT_EQ (Z (-128) - Z (-1), Z (-127));
        EXPECT_EQ (Z (-256) - Z (-1), Z (-255));
        
        EXPECT_EQ (Z (127) - Z (128), Z (-1));
        EXPECT_EQ (Z (127) - Z (256), Z (-129));
        EXPECT_EQ (Z (127) - Z (-128), Z (255));
        EXPECT_EQ (Z (127) - Z (-256), Z (383));
        
        EXPECT_EQ (N (127) - N (128), N (0));
        EXPECT_EQ (N (127) - N (256), N (0));
        
        EXPECT_EQ (Z (128) - Z (127), Z (1));
        EXPECT_EQ (Z (256) - Z (127), Z (129));
        EXPECT_EQ (Z (-128) - Z (127), Z (-255));
        EXPECT_EQ (Z (-256) - Z (127), Z (-383));
        
        EXPECT_EQ (N (128) - N (127), N (1));
        EXPECT_EQ (N (256) - N (127), N (129));

        EXPECT_EQ (Z (-127) - Z (128), Z (-255));
        EXPECT_EQ (Z (-127) - Z (256), Z (-383));
        EXPECT_EQ (Z (-127) - Z (-128), Z (1));
        EXPECT_EQ (Z (-127) - Z (-256), Z (129));
        
        EXPECT_EQ (Z (128) - Z (-127), Z (255));
        EXPECT_EQ (Z (256) - Z (-127), Z (383));
        EXPECT_EQ (Z (-128) - Z (-127), Z (-1));
        EXPECT_EQ (Z (-256) - Z (-127), Z (-129));
        
        EXPECT_EQ (Z (128) - Z (256), Z (-128));
        EXPECT_EQ (Z (128) - Z (-256), Z (384));
        
        EXPECT_EQ (N (128) - N (256), N (0));
        
        EXPECT_EQ (Z (256) - Z (128), Z (128));
        EXPECT_EQ (Z (-256) - Z (128), Z (-384));
        
        EXPECT_EQ (N (256) - N (128), N (128));
        
        EXPECT_EQ (Z (-128) - Z (256), Z (-384));
        EXPECT_EQ (Z (-128) - Z (-256), Z (128));
        
        EXPECT_EQ (Z (256) - Z (-128), Z (384));
        EXPECT_EQ (Z (-256) - Z (-128), Z (-128));
        
    }
    
    TEST (NumberTest, TestNumberTimes) {
        
        EXPECT_EQ (Z(0) * Z (0), Z (0));
        EXPECT_EQ (Z(0) * Z (1), Z (0));
        EXPECT_EQ (Z(0) * Z (127), Z (0));
        EXPECT_EQ (Z(0) * Z (128), Z (0));
        EXPECT_EQ (Z(0) * Z (256), Z (0));
        EXPECT_EQ (Z(0) * Z (-1), Z (0));
        EXPECT_EQ (Z(0) * Z (-127), Z (0));
        EXPECT_EQ (Z(0) * Z (-128), Z (0));
        EXPECT_EQ (Z(0) * Z (-256), Z (0));
        
        EXPECT_EQ (N(0) * N (1), N (0));
        EXPECT_EQ (N(0) * N (127), N (0));
        EXPECT_EQ (N(0) * N (128), N (0));
        EXPECT_EQ (N(0) * N (256), N (0));
        
        EXPECT_EQ (Z(1) * Z (1), Z (1));
        EXPECT_EQ (Z(1) * Z (127), Z (127));
        EXPECT_EQ (Z(1) * Z (128), Z (128));
        EXPECT_EQ (Z(1) * Z (256), Z (256));
        EXPECT_EQ (Z(1) * Z (-127), Z (-127));
        EXPECT_EQ (Z(1) * Z (-128), Z (-128));
        EXPECT_EQ (Z(1) * Z (-256), Z (-256));
        
        EXPECT_EQ (N (1) * N (1), N (1));
        EXPECT_EQ (N (1) * N (127), N (127));
        EXPECT_EQ (N (1) * N (128), N (128));
        EXPECT_EQ (N (1) * N (256), N (256));
        
        EXPECT_EQ (Z (-1) * Z (1), Z (-1));
        EXPECT_EQ (Z (-1) * Z (127), Z (-127));
        EXPECT_EQ (Z (-1) * Z (128), Z (-128));
        EXPECT_EQ (Z (-1) * Z (256), Z (-256));
        EXPECT_EQ (Z (-1) * Z (-1), Z (1));
        EXPECT_EQ (Z (-1) * Z (-127), Z (127));
        EXPECT_EQ (Z (-1) * Z (-128), Z (128));
        EXPECT_EQ (Z (-1) * Z (-256), Z (256));
        
        EXPECT_EQ (Z (127) * Z (127), Z (16129));
        EXPECT_EQ (Z (127) * Z (128), Z (16256));
        EXPECT_EQ (Z (127) * Z (256), Z (32512));
        EXPECT_EQ (Z (127) * Z (-128), Z (-16256));
        EXPECT_EQ (Z (127) * Z (-256), Z (-32512));
        
        EXPECT_EQ (N (127) * N (127), N (16129));
        EXPECT_EQ (N (127) * N (128), N (16256));
        EXPECT_EQ (N (127) * N (256), N (32512));
        
        EXPECT_EQ (Z (-127) * Z (127), Z (-16129));
        EXPECT_EQ (Z (-127) * Z (128), Z (-16256));
        EXPECT_EQ (Z (-127) * Z (256), Z (-32512));
        EXPECT_EQ (Z (-127) * Z (-128), Z (16256));
        EXPECT_EQ (Z (-127) * Z (-256), Z (32512));
        
        EXPECT_EQ (Z (128) * Z (128), Z (16384));
        EXPECT_EQ (Z (128) * Z (256), Z (32768));
        EXPECT_EQ (Z (128) * Z (-256), Z (-32768));
        
        EXPECT_EQ (N (128) * N (128), N (16384));
        EXPECT_EQ (N (128) * N (256), N (32768));
        
        EXPECT_EQ (Z (-128) * Z (128), Z (-16384));
        EXPECT_EQ (Z (-128) * Z (256), Z (-32768));
        EXPECT_EQ (Z (-128) * Z (-256), Z (32768));
        
        EXPECT_EQ (Z (256) * Z (256), Z (65536));
        
        EXPECT_EQ (N (256) * N (256), N (65536));
        
        EXPECT_EQ (Z (-256) * Z (256), Z (-65536));
        
    }

}

