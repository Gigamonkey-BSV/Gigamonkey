// Copyright (c) 2021 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/script/script.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin {
    
    TEST(NumberTest, TestPushNumber) {
        
        EXPECT_EQ(compile(push_data(0)), bytes{OP_0});
        EXPECT_EQ(compile(push_data(Z(0))), bytes{OP_0});
        EXPECT_EQ(compile(push_data(N(0))), bytes{OP_0});
        EXPECT_EQ(compile(push_data(1)), bytes{OP_1});
        EXPECT_EQ(compile(push_data(Z(1))), bytes{OP_1});
        EXPECT_EQ(compile(push_data(N(1))), bytes{OP_1});
        EXPECT_EQ(compile(push_data(-1)), bytes{OP_1NEGATE});
        EXPECT_EQ(compile(push_data(Z(-1))), bytes{OP_1NEGATE});
        EXPECT_EQ(compile(push_data(16)), bytes{OP_16});
        EXPECT_EQ(compile(push_data(Z(16))), bytes{OP_16});
        EXPECT_EQ(compile(push_data(N(16))), bytes{OP_16});
        
        auto test_program_1 = bytes{OP_PUSHSIZE1, 0x82};
        auto test_program_2 = bytes{OP_PUSHSIZE1, 0x11};
        EXPECT_EQ(compile(push_data(-2)), test_program_1);
        EXPECT_EQ(compile(push_data(Z(-2))), test_program_1);
        EXPECT_EQ(compile(push_data(17)), test_program_2);
        EXPECT_EQ(compile(push_data(Z(17))), test_program_2);
        EXPECT_EQ(compile(push_data(N(17))), test_program_2);
        
        auto test_program_3 = bytes{OP_PUSHSIZE1, 0xff};
        auto test_program_4 = bytes{OP_PUSHSIZE1, 0x7f};
        EXPECT_EQ(compile(push_data(-127)), test_program_3);
        EXPECT_EQ(compile(push_data(Z(-127))), test_program_3);
        EXPECT_EQ(compile(push_data(127)), test_program_4);
        EXPECT_EQ(compile(push_data(Z(127))), test_program_4);
        EXPECT_EQ(compile(push_data(N(127))), test_program_4);
        
        auto test_program_5 = bytes{OP_PUSHSIZE2, 0xff, 0x80};
        auto test_program_6 = bytes{OP_PUSHSIZE2, 0xff, 0x00};
        EXPECT_EQ(compile(push_data(-255)), test_program_5);
        EXPECT_EQ(compile(push_data(Z(-255))), test_program_5);
        EXPECT_EQ(compile(push_data(255)), test_program_6);
        EXPECT_EQ(compile(push_data(Z(255))), test_program_6);
        EXPECT_EQ(compile(push_data(N(255))), test_program_6);
        
    }
    
    TEST(NumberTest, TestNumberConstructorsInt) {
        
        EXPECT_EQ(bytes_view(Z(0)), bytes());
        EXPECT_EQ(bytes_view(Z(1)), bytes::from_hex("01"));
        EXPECT_EQ(bytes_view(Z(-1)), bytes::from_hex("81"));
        EXPECT_EQ(bytes_view(Z(127)), bytes::from_hex("7f"));
        EXPECT_EQ(bytes_view(Z(-127)), bytes::from_hex("ff"));
        EXPECT_EQ(bytes_view(Z(128)), bytes::from_hex("8000"));
        EXPECT_EQ(bytes_view(Z(-128)), bytes::from_hex("8080"));
        EXPECT_EQ(bytes_view(Z(256)), bytes::from_hex("0001"));
        EXPECT_EQ(bytes_view(Z(-256)), bytes::from_hex("0081"));
        
        EXPECT_EQ(bytes_view(N(0)), bytes());
        EXPECT_EQ(bytes_view(N(1)), bytes::from_hex("01"));
        EXPECT_EQ(bytes_view(N(127)), bytes::from_hex("7f"));
        EXPECT_EQ(bytes_view(N(128)), bytes::from_hex("8000"));
        EXPECT_EQ(bytes_view(N(256)), bytes::from_hex("0001"));
        
    }
    
    TEST(NumberTest, TestNumberConstructorsDecimalPositive) {
        
        EXPECT_EQ(bytes_view(Z("0")), bytes::from_hex("00"));
        EXPECT_EQ(bytes_view(Z("127")), bytes::from_hex("7f"));
        EXPECT_EQ(bytes_view(Z("128")), bytes::from_hex("8000"));
        EXPECT_EQ(bytes_view(Z("256")), bytes::from_hex("0001"));
        
        EXPECT_EQ(bytes_view(N("0")), bytes::from_hex("00"));
        EXPECT_EQ(bytes_view(N("1")), bytes::from_hex("01"));
        EXPECT_EQ(bytes_view(N("127")), bytes::from_hex("7f"));
        EXPECT_EQ(bytes_view(N("128")), bytes::from_hex("8000"));
        EXPECT_EQ(bytes_view(N("256")), bytes::from_hex("0001"));
        
    }
    
    TEST(NumberTest, TestNumberConstructorsHexZ) {
        
        EXPECT_EQ(bytes_view(Z("")), bytes());
        EXPECT_EQ(bytes_view(Z("0x00")), bytes::from_hex("00"));
        EXPECT_EQ(bytes_view(Z("0x80")), bytes::from_hex("80"));
        EXPECT_EQ(bytes_view(Z("0x0000")), bytes::from_hex("0000"));
        EXPECT_EQ(bytes_view(Z("0x8000")), bytes::from_hex("0080"));
        EXPECT_EQ(bytes_view(Z("0x000000")), bytes::from_hex("000000"));
        EXPECT_EQ(bytes_view(Z("0x800000")), bytes::from_hex("000080"));
        
        EXPECT_EQ(bytes_view(Z("1")), bytes::from_hex("01"));
        EXPECT_EQ(bytes_view(Z("-1")), bytes::from_hex("81"));
        EXPECT_EQ(bytes_view(Z("0x01")), bytes::from_hex("01"));
        EXPECT_EQ(bytes_view(Z("0x81")), bytes::from_hex("81"));
        EXPECT_EQ(bytes_view(Z("0x0001")), bytes::from_hex("0100"));
        EXPECT_EQ(bytes_view(Z("0x8001")), bytes::from_hex("0180"));
        EXPECT_EQ(bytes_view(Z("0x000001")), bytes::from_hex("010000"));
        EXPECT_EQ(bytes_view(Z("0x800001")), bytes::from_hex("010080"));
        
        EXPECT_EQ(bytes_view(Z("0x7f")), bytes::from_hex("7f"));
        EXPECT_EQ(bytes_view(Z("0xff")), bytes::from_hex("ff"));
        EXPECT_EQ(bytes_view(Z("0x007f")), bytes::from_hex("7f00"));
        EXPECT_EQ(bytes_view(Z("0x807f")), bytes::from_hex("7f80"));
        EXPECT_EQ(bytes_view(Z("0x00007f")), bytes::from_hex("7f0000"));
        EXPECT_EQ(bytes_view(Z("0x80007f")), bytes::from_hex("7f0080"));
        
    }
    
    TEST(NumberTest, TestNumberMinimalZ) {
        
        EXPECT_TRUE(Z("").minimal());
        EXPECT_FALSE(Z("0x00").minimal());
        EXPECT_FALSE(Z("0x80").minimal());
        EXPECT_FALSE(Z("0x0000").minimal());
        EXPECT_FALSE(Z("0x8000").minimal());
        EXPECT_FALSE(Z("0x000000").minimal());
        EXPECT_FALSE(Z("0x800000").minimal());
        
        EXPECT_TRUE(Z("0x01").minimal());
        EXPECT_TRUE(Z("0x81").minimal());
        EXPECT_FALSE(Z("0x0001").minimal());
        EXPECT_FALSE(Z("0x8001").minimal());
        EXPECT_FALSE(Z("0x000001").minimal());
        EXPECT_FALSE(Z("0x800001").minimal());
        
        EXPECT_TRUE(Z("0x7f").minimal());
        EXPECT_TRUE(Z("0xff").minimal());
        EXPECT_FALSE(Z("0x007f").minimal());
        EXPECT_FALSE(Z("0x807f").minimal());
        EXPECT_FALSE(Z("0x00007f").minimal());
        EXPECT_FALSE(Z("0x80007f").minimal());
        
    }
    
    TEST(NumberTest, TestNumberTrimZ) {
        
        EXPECT_EQ(bytes_view(Z("0x00").trim()), bytes());
        EXPECT_EQ(bytes_view(Z("0x80").trim()), bytes());
        EXPECT_EQ(bytes_view(Z("0x0000").trim()), bytes());
        EXPECT_EQ(bytes_view(Z("0x8000").trim()), bytes());
        EXPECT_EQ(bytes_view(Z("0x000000").trim()), bytes());
        EXPECT_EQ(bytes_view(Z("0x800000").trim()), bytes());
        
        EXPECT_EQ(bytes_view(Z("0x01").trim()), bytes::from_hex("01"));
        EXPECT_EQ(bytes_view(Z("0x81").trim()), bytes::from_hex("81"));
        EXPECT_EQ(bytes_view(Z("0x0001").trim()), bytes::from_hex("01"));
        EXPECT_EQ(bytes_view(Z("0x8001").trim()), bytes::from_hex("81"));
        EXPECT_EQ(bytes_view(Z("0x000001").trim()), bytes::from_hex("01"));
        EXPECT_EQ(bytes_view(Z("0x800001").trim()), bytes::from_hex("81"));
        
        EXPECT_EQ(bytes_view(Z("0x7f").trim()), bytes::from_hex("7f"));
        EXPECT_EQ(bytes_view(Z("0xff").trim()), bytes::from_hex("ff"));
        EXPECT_EQ(bytes_view(Z("0x007f").trim()), bytes::from_hex("7f"));
        EXPECT_EQ(bytes_view(Z("0x807f").trim()), bytes::from_hex("ff"));
        EXPECT_EQ(bytes_view(Z("0x00007f").trim()), bytes::from_hex("7f"));
        EXPECT_EQ(bytes_view(Z("0x80007f").trim()), bytes::from_hex("ff"));
        
    }
    
    TEST(NumberTest, TestNumberSignZ) {
        
        EXPECT_TRUE(Z("0x00").is_zero());
        EXPECT_TRUE(Z("0x80").is_zero());
        EXPECT_TRUE(Z("0x0000").is_zero());
        EXPECT_TRUE(Z("0x8000").is_zero());
        EXPECT_TRUE(Z("0x000000").is_zero());
        EXPECT_TRUE(Z("0x800000").is_zero());
        
        EXPECT_FALSE(Z("0x01").is_zero());
        EXPECT_FALSE(Z("0x81").is_zero());
        EXPECT_FALSE(Z("0x0001").is_zero());
        EXPECT_FALSE(Z("0x8001").is_zero());
        EXPECT_FALSE(Z("0x000001").is_zero());
        EXPECT_FALSE(Z("0x800001").is_zero());
        
        EXPECT_FALSE(Z("0x0080").is_zero());
        EXPECT_FALSE(Z("0x8080").is_zero());
        EXPECT_FALSE(Z("0x000080").is_zero());
        EXPECT_FALSE(Z("0x800080").is_zero());
        
        EXPECT_EQ(Z("0x00").sign_bit(), false);
        EXPECT_EQ(Z("0x80").sign_bit(), true);
        EXPECT_EQ(Z("0x0000").sign_bit(), false);
        EXPECT_EQ(Z("0x8000").sign_bit(), true);
        EXPECT_EQ(Z("0x000000").sign_bit(), false);
        EXPECT_EQ(Z("0x800000").sign_bit(), true);
        
        EXPECT_EQ(Z("0x01").sign_bit(), false);
        EXPECT_EQ(Z("0x81").sign_bit(), true);
        EXPECT_EQ(Z("0x0001").sign_bit(), false);
        EXPECT_EQ(Z("0x8001").sign_bit(), true);
        EXPECT_EQ(Z("0x000001").sign_bit(), false);
        EXPECT_EQ(Z("0x800001").sign_bit(), true);
        
        EXPECT_EQ(Z("0x0080").sign_bit(), false);
        EXPECT_EQ(Z("0x8080").sign_bit(), true);
        EXPECT_EQ(Z("0x000080").sign_bit(), false);
        EXPECT_EQ(Z("0x800080").sign_bit(), true);
        
        EXPECT_TRUE(Z("0x00").is_positive_zero());
        EXPECT_FALSE(Z("0x80").is_positive_zero());
        EXPECT_TRUE(Z("0x0000").is_positive_zero());
        EXPECT_FALSE(Z("0x8000").is_positive_zero());
        EXPECT_TRUE(Z("0x000000").is_positive_zero());
        EXPECT_FALSE(Z("0x800000").is_positive_zero());
        
        EXPECT_FALSE(Z("0x01").is_positive_zero());
        EXPECT_FALSE(Z("0x81").is_positive_zero());
        EXPECT_FALSE(Z("0x0001").is_positive_zero());
        EXPECT_FALSE(Z("0x8001").is_positive_zero());
        EXPECT_FALSE(Z("0x000001").is_positive_zero());
        EXPECT_FALSE(Z("0x800001").is_positive_zero());
        
        EXPECT_FALSE(Z("0x00").is_negative_zero());
        EXPECT_TRUE(Z("0x80").is_negative_zero());
        EXPECT_FALSE(Z("0x0000").is_negative_zero());
        EXPECT_TRUE(Z("0x8000").is_negative_zero());
        EXPECT_FALSE(Z("0x000000").is_negative_zero());
        EXPECT_TRUE(Z("0x800000").is_negative_zero());
        
        EXPECT_FALSE(Z("0x01").is_negative_zero());
        EXPECT_FALSE(Z("0x81").is_negative_zero());
        EXPECT_FALSE(Z("0x0001").is_negative_zero());
        EXPECT_FALSE(Z("0x8001").is_negative_zero());
        EXPECT_FALSE(Z("0x000001").is_negative_zero());
        EXPECT_FALSE(Z("0x800001").is_negative_zero());
        
        EXPECT_FALSE(Z("0x00").is_positive());
        EXPECT_FALSE(Z("0x80").is_positive());
        EXPECT_FALSE(Z("0x0000").is_positive());
        EXPECT_FALSE(Z("0x8000").is_positive());
        EXPECT_FALSE(Z("0x000000").is_positive());
        EXPECT_FALSE(Z("0x800000").is_positive());
        
        EXPECT_FALSE(Z("0x00").is_negative());
        EXPECT_FALSE(Z("0x80").is_negative());
        EXPECT_FALSE(Z("0x0000").is_negative());
        EXPECT_FALSE(Z("0x8000").is_negative());
        EXPECT_FALSE(Z("0x000000").is_negative());
        EXPECT_FALSE(Z("0x800000").is_negative());
        
        EXPECT_TRUE(Z("0x01").is_positive());
        EXPECT_FALSE(Z("0x81").is_positive());
        EXPECT_TRUE(Z("0x0001").is_positive());
        EXPECT_FALSE(Z("0x8001").is_positive());
        EXPECT_TRUE(Z("0x000001").is_positive());
        EXPECT_FALSE(Z("0x800001").is_positive());
        
        EXPECT_FALSE(Z("0x01").is_negative());
        EXPECT_TRUE(Z("0x81").is_negative());
        EXPECT_FALSE(Z("0x0001").is_negative());
        EXPECT_TRUE(Z("0x8001").is_negative());
        EXPECT_FALSE(Z("0x000001").is_negative());
        EXPECT_TRUE(Z("0x800001").is_negative());
        
        EXPECT_TRUE(Z("0x0080").is_positive());
        EXPECT_FALSE(Z("0x8080").is_positive());
        EXPECT_TRUE(Z("0x000080").is_positive());
        EXPECT_FALSE(Z("0x800080").is_positive());
        
        EXPECT_FALSE(Z("0x0080").is_negative());
        EXPECT_TRUE(Z("0x8080").is_negative());
        EXPECT_FALSE(Z("0x000080").is_negative());
        EXPECT_TRUE(Z("0x800080").is_negative());
    
    }
    
    TEST(NumberTest, TestNumberConstructorsDecimalNegative) {
        
        EXPECT_EQ(bytes_view(Z("-0")), bytes::from_hex("80"));
        EXPECT_EQ(bytes_view(Z("-127")), bytes::from_hex("ff"));
        EXPECT_EQ(bytes_view(Z("-128")), bytes::from_hex("8080"));
        EXPECT_EQ(bytes_view(Z("-256")), bytes::from_hex("0081"));
        
        EXPECT_EQ(bytes_view(N("-0")), bytes::from_hex("80"));
        EXPECT_THROW(N("-1"), std::logic_error);
        EXPECT_THROW(N("-127"), std::logic_error);
        EXPECT_THROW(N("-128"), std::logic_error);
        EXPECT_THROW(N("-256"), std::logic_error);
        
    }
    
    TEST(NumberTest, TestNumberConstructorsN) {
        
        EXPECT_EQ(bytes_view(N("")), bytes());
        EXPECT_EQ(bytes_view(N("0x00")), bytes::from_hex("00"));
        EXPECT_EQ(bytes_view(N("0x80")), bytes::from_hex("80"));
        EXPECT_EQ(bytes_view(N("0x0000")), bytes::from_hex("0000"));
        EXPECT_EQ(bytes_view(N("0x8000")), bytes::from_hex("0080"));
        EXPECT_EQ(bytes_view(N("0x000000")), bytes::from_hex("000000"));
        EXPECT_EQ(bytes_view(N("0x800000")), bytes::from_hex("000080"));
        
        EXPECT_EQ(bytes_view(N("0x01")), bytes::from_hex("01"));
        EXPECT_THROW(N("0x81"), std::logic_error);
        EXPECT_EQ(bytes_view(N("0x0001")), bytes::from_hex("0100"));
        EXPECT_THROW(N("0x8001"), std::logic_error);
        EXPECT_EQ(bytes_view(N("0x000001")), bytes::from_hex("010000"));
        EXPECT_THROW(N("0x800001"), std::logic_error);
        
        EXPECT_EQ(bytes_view(N("0x7f")), bytes::from_hex("7f"));
        EXPECT_THROW(N("0xff"), std::logic_error);
        EXPECT_EQ(bytes_view(N("0x007f")), bytes::from_hex("7f00"));
        EXPECT_THROW(N("0x807f"), std::logic_error);
        EXPECT_EQ(bytes_view(N("0x00007f")), bytes::from_hex("7f0000"));
        EXPECT_THROW(N("0x80007f"), std::logic_error);
        
    }
    
    TEST(NumberTest, TestNumberTrimN) {
        
        EXPECT_EQ(bytes_view(N("0x00").trim()), bytes());
        EXPECT_EQ(bytes_view(N("0x80").trim()), bytes());
        EXPECT_EQ(bytes_view(N("0x0000").trim()), bytes());
        EXPECT_EQ(bytes_view(N("0x8000").trim()), bytes());
        EXPECT_EQ(bytes_view(N("0x000000").trim()), bytes());
        EXPECT_EQ(bytes_view(N("0x800000").trim()), bytes());
        
        EXPECT_EQ(bytes_view(N("0x01").trim()), bytes::from_hex("01"));
        EXPECT_EQ(bytes_view(N("0x0001").trim()), bytes::from_hex("01"));
        EXPECT_EQ(bytes_view(N("0x000001").trim()), bytes::from_hex("01"));
        
        EXPECT_EQ(bytes_view(N("0x7f").trim()), bytes::from_hex("7f"));
        EXPECT_EQ(bytes_view(N("0x007f").trim()), bytes::from_hex("7f"));
        EXPECT_EQ(bytes_view(N("0x00007f").trim()), bytes::from_hex("7f"));
        
    }
    
    TEST(NumberTest, TestNumberMinimalN) {
        
        EXPECT_TRUE(N("").minimal());
        EXPECT_FALSE(N("0x00").minimal());
        EXPECT_FALSE(N("0x80").minimal());
        EXPECT_FALSE(N("0x0000").minimal());
        EXPECT_FALSE(N("0x8000").minimal());
        EXPECT_FALSE(N("0x000000").minimal());
        EXPECT_FALSE(N("0x800000").minimal());
        
        EXPECT_TRUE(N("0x01").minimal());
        EXPECT_FALSE(N("0x0001").minimal());
        EXPECT_FALSE(N("0x000001").minimal());
        
        EXPECT_TRUE(N("0x7f").minimal());
        EXPECT_FALSE(N("0x007f").minimal());
        EXPECT_FALSE(N("0x00007f").minimal());
        
    }
    
    TEST(NumberTest, TestNumberSignN) {
        
        EXPECT_TRUE(N("0x00").is_zero());
        EXPECT_TRUE(N("0x80").is_zero());
        EXPECT_TRUE(N("0x0000").is_zero());
        EXPECT_TRUE(N("0x8000").is_zero());
        EXPECT_TRUE(N("0x000000").is_zero());
        EXPECT_TRUE(N("0x800000").is_zero());
        
        EXPECT_TRUE(N("0x00").is_positive_zero());
        EXPECT_FALSE(N("0x80").is_positive_zero());
        EXPECT_TRUE(N("0x0000").is_positive_zero());
        EXPECT_FALSE(N("0x8000").is_positive_zero());
        EXPECT_TRUE(N("0x000000").is_positive_zero());
        EXPECT_FALSE(N("0x800000").is_positive_zero());
        
        EXPECT_FALSE(N("0x00").is_negative_zero());
        EXPECT_TRUE(N("0x80").is_negative_zero());
        EXPECT_FALSE(N("0x0000").is_negative_zero());
        EXPECT_TRUE(N("0x8000").is_negative_zero());
        EXPECT_FALSE(N("0x000000").is_negative_zero());
        EXPECT_TRUE(N("0x800000").is_negative_zero());
        
        EXPECT_FALSE(N("0x00").is_positive());
        EXPECT_FALSE(N("0x80").is_positive());
        EXPECT_FALSE(N("0x0000").is_positive());
        EXPECT_FALSE(N("0x8000").is_positive());
        EXPECT_FALSE(N("0x000000").is_positive());
        EXPECT_FALSE(N("0x800000").is_positive());
        
        EXPECT_FALSE(N("0x00").is_negative());
        EXPECT_FALSE(N("0x80").is_negative());
        EXPECT_FALSE(N("0x0000").is_negative());
        EXPECT_FALSE(N("0x8000").is_negative());
        EXPECT_FALSE(N("0x000000").is_negative());
        EXPECT_FALSE(N("0x800000").is_negative());
        
    }
    
    TEST(NumberTest, TestNumberCompare) {
        
        EXPECT_EQ(Z(0), Z(""));
        EXPECT_EQ(Z(0), Z("0x00"));
        EXPECT_EQ(Z(0), Z("0x80"));
        EXPECT_EQ(Z(0), Z("0x0000"));
        EXPECT_EQ(Z(0), Z("0x8000"));
        EXPECT_EQ(Z(0), Z("0x000000"));
        EXPECT_EQ(Z(0), Z("0x800000"));
        
        EXPECT_EQ(N(0), N(""));
        EXPECT_EQ(N(0), N("0x00"));
        EXPECT_EQ(N(0), N("0x80"));
        EXPECT_EQ(N(0), N("0x0000"));
        EXPECT_EQ(N(0), N("0x8000"));
        EXPECT_EQ(N(0), N("0x000000"));
        EXPECT_EQ(N(0), N("0x800000"));
        
        EXPECT_EQ(Z(0), N(0));
        
        EXPECT_EQ(Z(1), Z("0x01"));
        EXPECT_EQ(Z(-1), Z("0x81"));
        EXPECT_EQ(Z(1), Z("0x0001"));
        EXPECT_EQ(Z(-1), Z("0x8001"));
        EXPECT_EQ(Z(1), Z("0x000001"));
        EXPECT_EQ(Z(-1), Z("0x800001"));
        
        EXPECT_EQ(N(1), N("0x01"));
        EXPECT_EQ(N(1), N("0x0001"));
        EXPECT_EQ(N(1), N("0x000001"));
        
        EXPECT_EQ(Z(1), N(1));
        
        EXPECT_EQ(Z(127), Z("0x7f"));
        EXPECT_EQ(Z(-127), Z("0xff"));
        EXPECT_EQ(Z(127), Z("0x007f"));
        EXPECT_EQ(Z(-127), Z("0x807f"));
        EXPECT_EQ(Z(127), Z("0x00007f"));
        EXPECT_EQ(Z(-127), Z("0x80007f"));
        
        EXPECT_EQ(N(127), N("0x7f"));
        EXPECT_EQ(N(127), N("0x007f"));
        EXPECT_EQ(N(127), N("0x00007f"));
        
        EXPECT_EQ(Z(127), N(127));
        
        EXPECT_EQ(Z(128), Z("0x0080"));
        EXPECT_EQ(Z(-128), Z("0x8080"));
        EXPECT_EQ(Z(128), Z("0x000080"));
        EXPECT_EQ(Z(-128), Z("0x800080"));
        
        EXPECT_EQ(N(128), N("0x0080"));
        EXPECT_EQ(N(128), N("0x000080"));
        
        EXPECT_EQ(Z(128), N(128));
        
        EXPECT_EQ(Z(256), Z("0x0100"));
        EXPECT_EQ(Z(-256), Z("0x8100"));
        EXPECT_EQ(Z(256), Z("0x000100"));
        EXPECT_EQ(Z(-256), Z("0x800100"));
                                                                                                                                                                                                                                        
        EXPECT_EQ(N(256), N("0x0100"));
        EXPECT_EQ(N(256), N("0x000100"));
        
        EXPECT_EQ(Z(256), N(256));
        
        EXPECT_LE(Z(0), Z(0));
        EXPECT_GE(Z(0), Z(0));
        
        EXPECT_LE(N(0), N(0));
        EXPECT_GE(N(0), N(0));
        
        EXPECT_LE(Z(0), N(0));
        EXPECT_GE(Z(0), N(0));
        
        EXPECT_LE(Z(1), Z(1));
        EXPECT_GE(Z(1), Z(1));
        
        EXPECT_LE(N(1), N(1));
        EXPECT_GE(N(1), N(1));
        
        EXPECT_LE(Z(1), N(1));
        EXPECT_GE(Z(1), N(1));
        
        EXPECT_LE(Z(-1), Z(-1));
        EXPECT_GE(Z(-1), Z(-1));
        
        EXPECT_LE(Z(127), Z(127));
        EXPECT_GE(Z(127), Z(127));
        
        EXPECT_LE(N(127), N(127));
        EXPECT_GE(N(127), N(127));
        
        EXPECT_LE(Z(127), N(127));
        EXPECT_GE(Z(127), N(127));
        
        EXPECT_LE(Z(-127), Z(-127));
        EXPECT_GE(Z(-127), Z(-127));
        
        EXPECT_LE(Z(128), Z(128));
        EXPECT_GE(Z(128), Z(128));
        
        EXPECT_LE(N(128), N(128));
        EXPECT_GE(N(128), N(128));
        
        EXPECT_LE(Z(128), N(128));
        EXPECT_GE(Z(128), N(128));
        
        EXPECT_LE(Z(-128), Z(-128));
        EXPECT_GE(Z(-128), Z(-128));
        
        EXPECT_LE(Z(256), Z(256));
        EXPECT_GE(Z(256), Z(256));
        
        EXPECT_LE(N(256), N(256));
        EXPECT_GE(N(256), N(256));
        
        EXPECT_LE(Z(256), N(256));
        EXPECT_GE(Z(256), N(256));
        
        EXPECT_LE(Z(-256), Z(-256));
        EXPECT_GE(Z(-256), Z(-256));
        
        EXPECT_LE(Z(0), Z(1));
        EXPECT_GE(Z(1), Z(0));
        
        EXPECT_LE(N(0), N(1));
        EXPECT_GE(N(1), N(0));
        
        EXPECT_LE(Z(0), N(1));
        EXPECT_GE(Z(1), N(0));
        
        EXPECT_LE(Z(-1), Z(0));
        EXPECT_GE(Z(0), Z(-1));
        
        EXPECT_LE(Z(0), Z(256));
        EXPECT_GE(Z(256), Z(0));
        
        EXPECT_LE(N(0), N(256));
        EXPECT_GE(N(256), N(0));
        
        EXPECT_LE(Z(0), N(256));
        EXPECT_GE(Z(256), N(0));
        
        EXPECT_LE(Z(-256), Z(0));
        EXPECT_GE(Z(0), Z(-256));
        
        EXPECT_LT(Z(0), Z(1));
        EXPECT_GT(Z(1), Z(0));
        
        EXPECT_LT(N(0), N(1));
        EXPECT_GT(N(1), N(0));
        
        EXPECT_LT(Z(0), N(1));
        EXPECT_GT(Z(1), N(0));
        
        EXPECT_LT(Z(-1), Z(0));
        EXPECT_GT(Z(0), Z(-1));
        
        EXPECT_LT(Z(0), Z(256));
        EXPECT_GT(Z(256), Z(0));
        
        EXPECT_LT(N(0), N(256));
        EXPECT_GT(N(256), N(0));
        
        EXPECT_LT(Z(0), N(256));
        EXPECT_GT(Z(256), N(0));
        
        EXPECT_LT(Z(-256), Z(0));
        EXPECT_GT(Z(0), Z(-256));
        
    }
    
    TEST(NumberTest, TestNumberNegate) {
        
        EXPECT_EQ(-Z(0), Z(0));
        EXPECT_EQ(-Z(1), Z(-1));
        EXPECT_EQ(-Z(-1), Z(1));
        EXPECT_EQ(-Z(127), Z(-127));
        EXPECT_EQ(-Z(-127), Z(127));
        EXPECT_EQ(-Z(128), Z(-128));
        EXPECT_EQ(-Z(-128), Z(128));
        EXPECT_EQ(-Z(256), Z(-256));
        EXPECT_EQ(-Z(-256), Z(256));
        
    }
    
    TEST(NumberTest, TestNumberAbs) {
        
        EXPECT_EQ(Z(0).abs(), N(0));
        EXPECT_EQ(Z(1).abs(), N(1));
        EXPECT_EQ(Z(-1).abs(), N(1));
        EXPECT_EQ(Z(127).abs(), N(127));
        EXPECT_EQ(Z(-127).abs(), N(127));
        EXPECT_EQ(Z(128).abs(), N(128));
        EXPECT_EQ(Z(-128).abs(), N(128));
        EXPECT_EQ(Z(256).abs(), N(256));
        EXPECT_EQ(Z(-256).abs(), N(256));
        
    }
    
    TEST(NumberTest, TestNumberPlus) {
        
        EXPECT_EQ(Z(0) + Z(0), Z(0));
        EXPECT_EQ(Z(-1) + Z(1), Z(0));
        EXPECT_EQ(Z(-127) + Z(127), Z(0));
        EXPECT_EQ(Z(-128) + Z(128), Z(0));
        EXPECT_EQ(Z(-256) + Z(256), Z(0));
        
        EXPECT_EQ(Z(0) + Z(1), Z(1));
        EXPECT_EQ(Z(0) + Z(127), Z(127));
        EXPECT_EQ(Z(0) + Z(128), Z(128));
        EXPECT_EQ(Z(0) + Z(256), Z(256));
        EXPECT_EQ(Z(0) + Z(-1), Z(-1));
        EXPECT_EQ(Z(0) + Z(-127), Z(-127));
        EXPECT_EQ(Z(0) + Z(-128), Z(-128));
        EXPECT_EQ(Z(0) + Z(-256), Z(-256));
        
        EXPECT_EQ(N(0) + N(1), N(1));
        EXPECT_EQ(N(0) + N(127), N(127));
        EXPECT_EQ(N(0) + N(128), N(128));
        EXPECT_EQ(N(0) + N(256), N(256));
        
        EXPECT_EQ(Z(1) + Z(1), Z(2));
        EXPECT_EQ(Z(1) + Z(127), Z(128));
        EXPECT_EQ(Z(1) + Z(128), Z(129));
        EXPECT_EQ(Z(1) + Z(256), Z(257));
        EXPECT_EQ(Z(1) + Z(-127), Z(-126));
        EXPECT_EQ(Z(1) + Z(-128), Z(-127));
        EXPECT_EQ(Z(1) + Z(-256), Z(-255));
        
        EXPECT_EQ(N(1) + N(1), N(2));
        EXPECT_EQ(N(1) + N(127), N(128));
        EXPECT_EQ(N(1) + N(128), N(129));
        EXPECT_EQ(N(1) + N(256), N(257));
        
        EXPECT_EQ(Z(-1) + Z(127), Z(126));
        EXPECT_EQ(Z(-1) + Z(128), Z(127));
        EXPECT_EQ(Z(-1) + Z(256), Z(255));
        EXPECT_EQ(Z(-1) + Z(-1), Z(-2));
        EXPECT_EQ(Z(-1) + Z(-127), Z(-128));
        EXPECT_EQ(Z(-1) + Z(-128), Z(-129));
        EXPECT_EQ(Z(-1) + Z(-256), Z(-257));
        
        EXPECT_EQ(Z(127) + Z(127), Z(254));
        EXPECT_EQ(Z(127) + Z(128), Z(255));
        EXPECT_EQ(Z(127) + Z(256), Z(383));
        EXPECT_EQ(Z(127) + Z(-128), Z(-1));
        EXPECT_EQ(Z(127) + Z(-256), Z(-129));
        
        EXPECT_EQ(N(127) + N(127), N(254));
        EXPECT_EQ(N(127) + N(128), N(255));
        EXPECT_EQ(N(127) + N(256), N(383));
        
        EXPECT_EQ(Z(-127) + Z(128), Z(1));
        EXPECT_EQ(Z(-127) + Z(256), Z(129));
        EXPECT_EQ(Z(-127) + Z(-128), Z(-255));
        EXPECT_EQ(Z(-127) + Z(-256), Z(-383));
        
        EXPECT_EQ(Z(128) + Z(128), Z(256));
        EXPECT_EQ(Z(128) + Z(256), Z(384));
        EXPECT_EQ(Z(128) + Z(-256), Z(-128));
        
        EXPECT_EQ(N(128) + N(128), N(256));
        EXPECT_EQ(N(128) + N(256), N(384));
        
        EXPECT_EQ(Z(-128) + Z(256), Z(128));
        EXPECT_EQ(Z(-128) + Z(-256), Z(-384));
        
        EXPECT_EQ(Z(256) + Z(256), Z(512));
        
        EXPECT_EQ(N(256) + N(256), N(512));
        
    }
    
    TEST(NumberTest, TestNumberMinus) {
        
        EXPECT_EQ(Z(0) - Z(0), Z(0));
        EXPECT_EQ(Z(1) - Z(1), Z(0));
        EXPECT_EQ(Z(127) - Z(127), Z(0));
        EXPECT_EQ(Z(128) - Z(128), Z(0));
        EXPECT_EQ(Z(256) - Z(256), Z(0));
        
        EXPECT_EQ(Z(1) - Z(-1), Z(2));
        EXPECT_EQ(Z(127) - Z(-127), Z(254));
        EXPECT_EQ(Z(128) - Z(-128), Z(256));
        EXPECT_EQ(Z(256) - Z(-256), Z(512));
        
        EXPECT_EQ(Z(-1) - Z(1), Z(-2));
        EXPECT_EQ(Z(-127) - Z(127), Z(-254));
        EXPECT_EQ(Z(-128) - Z(128), Z(-256));
        EXPECT_EQ(Z(-256) - Z(256), Z(-512));
        
        EXPECT_EQ(N(0) - N(0), N(0));
        EXPECT_EQ(N(1) - N(1), N(0));
        EXPECT_EQ(N(127) - N(127), N(0));
        EXPECT_EQ(N(128) - N(128), N(0));
        EXPECT_EQ(N(256) - N(256), N(0));
        
        EXPECT_EQ(Z(0) - Z(1), Z(-1));
        EXPECT_EQ(Z(0) - Z(127), Z(-127));
        EXPECT_EQ(Z(0) - Z(128), Z(-128));
        EXPECT_EQ(Z(0) - Z(256), Z(-256));
        EXPECT_EQ(Z(0) - Z(-1), Z(1));
        EXPECT_EQ(Z(0) - Z(-127), Z(127));
        EXPECT_EQ(Z(0) - Z(-128), Z(128));
        EXPECT_EQ(Z(0) - Z(-256), Z(256));
        
        EXPECT_EQ(N(0) - N(1), N(0));
        EXPECT_EQ(N(0) - N(127), N(0));
        EXPECT_EQ(N(0) - N(128), N(0));
        EXPECT_EQ(N(0) - N(256), N(0));
        
        EXPECT_EQ(Z(1) - Z(0), Z(1));
        EXPECT_EQ(Z(127) - Z(0), Z(127));
        EXPECT_EQ(Z(128) - Z(0), Z(128));
        EXPECT_EQ(Z(256) - Z(0), Z(256));
        EXPECT_EQ(Z(-1) - Z(0), Z(-1));
        EXPECT_EQ(Z(-127) - Z(0), Z(-127));
        EXPECT_EQ(Z(-128) - Z(0), Z(-128));
        EXPECT_EQ(Z(-256) - Z(0), Z(-256));
        
        EXPECT_EQ(N(1) - N(0), N(1));
        EXPECT_EQ(N(127) - N(0), N(127));
        EXPECT_EQ(N(128) - N(0), N(128));
        EXPECT_EQ(N(256) - N(0), N(256));
        
        EXPECT_EQ(Z(1) - Z(127), Z(-126));
        EXPECT_EQ(Z(1) - Z(128), Z(-127));
        EXPECT_EQ(Z(1) - Z(256), Z(-255));
        EXPECT_EQ(Z(1) - Z(-127), Z(128));
        EXPECT_EQ(Z(1) - Z(-128), Z(129));
        EXPECT_EQ(Z(1) - Z(-256), Z(257));
        
        EXPECT_EQ(N(1) - N(127), N(0));
        EXPECT_EQ(N(1) - N(128), N(0));
        EXPECT_EQ(N(1) - N(256), N(0));
        
        EXPECT_EQ(Z(127) - Z(1), Z(126));
        EXPECT_EQ(Z(128) - Z(1), Z(127));
        EXPECT_EQ(Z(256) - Z(1), Z(255));
        EXPECT_EQ(Z(-127) - Z(1), Z(-128));
        EXPECT_EQ(Z(-128) - Z(1), Z(-129));
        EXPECT_EQ(Z(-256) - Z(1), Z(-257));
        
        EXPECT_EQ(N(127) - N(1), N(126));
        EXPECT_EQ(N(128) - N(1), N(127));
        EXPECT_EQ(N(256) - N(1), N(255));
        
        EXPECT_EQ(Z(-1) - Z(127), Z(-128));
        EXPECT_EQ(Z(-1) - Z(128), Z(-129));
        EXPECT_EQ(Z(-1) - Z(256), Z(-257));
        EXPECT_EQ(Z(-1) - Z(-127), Z(126));
        EXPECT_EQ(Z(-1) - Z(-128), Z(127));
        EXPECT_EQ(Z(-1) - Z(-256), Z(255));
        
        EXPECT_EQ(Z(127) - Z(-1), Z(128));
        EXPECT_EQ(Z(128) - Z(-1), Z(129));
        EXPECT_EQ(Z(256) - Z(-1), Z(257));
        EXPECT_EQ(Z(-127) - Z(-1), Z(-126));
        EXPECT_EQ(Z(-128) - Z(-1), Z(-127));
        EXPECT_EQ(Z(-256) - Z(-1), Z(-255));
        
        EXPECT_EQ(Z(127) - Z(128), Z(-1));
        EXPECT_EQ(Z(127) - Z(256), Z(-129));
        EXPECT_EQ(Z(127) - Z(-128), Z(255));
        EXPECT_EQ(Z(127) - Z(-256), Z(383));
        
        EXPECT_EQ(N(127) - N(128), N(0));
        EXPECT_EQ(N(127) - N(256), N(0));
        
        EXPECT_EQ(Z(128) - Z(127), Z(1));
        EXPECT_EQ(Z(256) - Z(127), Z(129));
        EXPECT_EQ(Z(-128) - Z(127), Z(-255));
        EXPECT_EQ(Z(-256) - Z(127), Z(-383));
        
        EXPECT_EQ(N(128) - N(127), N(1));
        EXPECT_EQ(N(256) - N(127), N(129));
        
        EXPECT_EQ(Z(-127) - Z(128), Z(-255));
        EXPECT_EQ(Z(-127) - Z(256), Z(-383));
        EXPECT_EQ(Z(-127) - Z(-128), Z(1));
        EXPECT_EQ(Z(-127) - Z(-256), Z(129));
        
        EXPECT_EQ(Z(128) - Z(-127), Z(255));
        EXPECT_EQ(Z(256) - Z(-127), Z(383));
        EXPECT_EQ(Z(-128) - Z(-127), Z(-1));
        EXPECT_EQ(Z(-256) - Z(-127), Z(-129));
        
        EXPECT_EQ(Z(128) - Z(256), Z(-128));
        EXPECT_EQ(Z(128) - Z(-256), Z(384));
        
        EXPECT_EQ(N(128) - N(256), N(0));
        
        EXPECT_EQ(Z(256) - Z(128), Z(128));
        EXPECT_EQ(Z(-256) - Z(128), Z(-384));
        
        EXPECT_EQ(N(256) - N(128), N(128));
        
        EXPECT_EQ(Z(-128) - Z(256), Z(-384));
        EXPECT_EQ(Z(-128) - Z(-256), Z(128));
        
        EXPECT_EQ(Z(256) - Z(-128), Z(384));
        EXPECT_EQ(Z(-256) - Z(-128), Z(-128));
        
    }
    
    TEST(NumberTest, TestNumberTimes) {
        
        EXPECT_EQ(Z(0) * Z(0), Z(0));
        EXPECT_EQ(Z(0) * Z(1), Z(0));
        EXPECT_EQ(Z(0) * Z(127), Z(0));
        EXPECT_EQ(Z(0) * Z(128), Z(0));
        EXPECT_EQ(Z(0) * Z(256), Z(0));
        EXPECT_EQ(Z(0) * Z(-1), Z(0));
        EXPECT_EQ(Z(0) * Z(-127), Z(0));
        EXPECT_EQ(Z(0) * Z(-128), Z(0));
        EXPECT_EQ(Z(0) * Z(-256), Z(0));
        
        EXPECT_EQ(N(0) * N(1), N(0));
        EXPECT_EQ(N(0) * N(127), N(0));
        EXPECT_EQ(N(0) * N(128), N(0));
        EXPECT_EQ(N(0) * N(256), N(0));
        
        EXPECT_EQ(Z(1) * Z(1), Z(1));
        EXPECT_EQ(Z(1) * Z(127), Z(127));
        EXPECT_EQ(Z(1) * Z(128), Z(128));
        EXPECT_EQ(Z(1) * Z(256), Z(256));
        EXPECT_EQ(Z(1) * Z(-127), Z(-127));
        EXPECT_EQ(Z(1) * Z(-128), Z(-128));
        EXPECT_EQ(Z(1) * Z(-256), Z(-256));
        
        EXPECT_EQ(N(1) * N(1), N(1));
        EXPECT_EQ(N(1) * N(127), N(127));
        EXPECT_EQ(N(1) * N(128), N(128));
        EXPECT_EQ(N(1) * N(256), N(256));
        
        EXPECT_EQ(Z(-1) * Z(1), Z(-1));
        EXPECT_EQ(Z(-1) * Z(127), Z(-127));
        EXPECT_EQ(Z(-1) * Z(128), Z(-128));
        EXPECT_EQ(Z(-1) * Z(256), Z(-256));
        EXPECT_EQ(Z(-1) * Z(-1), Z(1));
        EXPECT_EQ(Z(-1) * Z(-127), Z(127));
        EXPECT_EQ(Z(-1) * Z(-128), Z(128));
        EXPECT_EQ(Z(-1) * Z(-256), Z(256));
        
        EXPECT_EQ(Z(127) * Z(127), Z(16129));
        EXPECT_EQ(Z(127) * Z(128), Z(16256));
        EXPECT_EQ(Z(127) * Z(256), Z(32512));
        EXPECT_EQ(Z(127) * Z(-128), Z(-16256));
        EXPECT_EQ(Z(127) * Z(-256), Z(-32512));
        
        EXPECT_EQ(N(127) * N(127), N(16129));
        EXPECT_EQ(N(127) * N(128), N(16256));
        EXPECT_EQ(N(127) * N(256), N(32512));
        
        EXPECT_EQ(Z(-127) * Z(127), Z(-16129));
        EXPECT_EQ(Z(-127) * Z(128), Z(-16256));
        EXPECT_EQ(Z(-127) * Z(256), Z(-32512));
        EXPECT_EQ(Z(-127) * Z(-128), Z(16256));
        EXPECT_EQ(Z(-127) * Z(-256), Z(32512));
        
        EXPECT_EQ(Z(128) * Z(128), Z(16384));
        EXPECT_EQ(Z(128) * Z(256), Z(32768));
        EXPECT_EQ(Z(128) * Z(-256), Z(-32768));
        
        EXPECT_EQ(N(128) * N(128), N(16384));
        EXPECT_EQ(N(128) * N(256), N(32768));
        
        EXPECT_EQ(Z(-128) * Z(128), Z(-16384));
        EXPECT_EQ(Z(-128) * Z(256), Z(-32768));
        EXPECT_EQ(Z(-128) * Z(-256), Z(32768));
        
        EXPECT_EQ(Z(256) * Z(256), Z(65536));
        
        EXPECT_EQ(N(256) * N(256), N(65536));
        
        EXPECT_EQ(Z(-256) * Z(256), Z(-65536));
        
    }
    /*
    TEST(NumberTest, TestNumberShift) {
        
        int64 small = 0xf98def;
        int64 big = 0xf98def000000;
        
        for (int i = 0; i < 25; i++) {
            EXPECT_EQ(Z(small) >> i, Z(small >> i));
            EXPECT_EQ(Z(-small) >> i, Z(-(small >> i)));
            
            EXPECT_EQ(Z(big) << i, Z(big << i));
            EXPECT_EQ(Z(-big) << i, Z(-(big << i)));
        }
        
    }*/

}
