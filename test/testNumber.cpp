// Copyright (c) 2021 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/script/script.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin {
    
    TEST(NumberTest, TestNumber) {
        
        EXPECT_EQ(compile(push_data(0)), bytes{OP_0});
        EXPECT_EQ(compile(push_data(Z(0))), bytes{OP_0});
        EXPECT_EQ(compile(push_data(1)), bytes{OP_1});
        EXPECT_EQ(compile(push_data(Z(1))), bytes{OP_1});
        EXPECT_EQ(compile(push_data(-1)), bytes{OP_1NEGATE});
        EXPECT_EQ(compile(push_data(Z(-1))), bytes{OP_1NEGATE});
        EXPECT_EQ(compile(push_data(16)), bytes{OP_16});
        EXPECT_EQ(compile(push_data(Z(16))), bytes{OP_16});
        
        auto test_program_1 = bytes{OP_PUSHSIZE1, 0x82};
        auto test_program_2 = bytes{OP_PUSHSIZE1, 0x82};
        auto test_program_3 = bytes{OP_PUSHSIZE1, 0x11};
        auto test_program_4 = bytes{OP_PUSHSIZE1, 0x11};
        EXPECT_EQ(compile(push_data(-2)), test_program_1);
        EXPECT_EQ(compile(push_data(Z(-2))), test_program_2);
        EXPECT_EQ(compile(push_data(17)), test_program_3);
        EXPECT_EQ(compile(push_data(Z(17))), test_program_4);
        
        auto test_program_5 = bytes{OP_PUSHSIZE2, 0xff, 0x80};
        auto test_program_6 = bytes{OP_PUSHSIZE2, 0xff, 0x80};
        auto test_program_7 = bytes{OP_PUSHSIZE2, 0xff, 0x00};
        auto test_program_8 = bytes{OP_PUSHSIZE2, 0xff, 0x00};
        EXPECT_EQ(compile(push_data(-255)), test_program_5);
        EXPECT_EQ(compile(push_data(Z(-255))), test_program_6);
        EXPECT_EQ(compile(push_data(255)), test_program_7);
        EXPECT_EQ(compile(push_data(Z(255))), test_program_8);
        
    }

}
