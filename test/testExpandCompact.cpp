// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/timechain.hpp>
#include "gtest/gtest.h"
#include <type_traits>

namespace Gigamonkey::work {
    
    struct test_case {
        uint256 Input;
        uint256 Expected;
        
        test_case() : Input{}, Expected{} {}
        test_case(target t, std::string x) : Input{t.expand()}, Expected{x} {}
    };
    
    bool check(cross<test_case> x) {
        for (int i = 0; i < x.size(); i++) for(int j = 0; j < x.size(); j++) 
            if ((i == j && x[i].Input != x[j].Expected) || (i != j && x[i].Input == x[j].Expected)) return false;
        return true;
    }

    // can result in stack smashing
    TEST(ExpandCompactTest, TestExpandCompact) {
        cross<test_case> tests{
            test_case{target{0x03, 0xabcdef}, 
                std::string{"0x0000000000000000000000000000000000000000000000000000000000abcdef"}}, 
            test_case{target{0x04, 0xabcdef}, 
                std::string{"0x00000000000000000000000000000000000000000000000000000000abcdef00"}}, 
            test_case{target{0x05, 0xabcdef}, 
                std::string{"0x000000000000000000000000000000000000000000000000000000abcdef0000"}}, 
            test_case{target{0x20, 0xabcdef}, 
                std::string{"0xabcdef0000000000000000000000000000000000000000000000000000000000"}}, 
            test_case{target{0x21, 0xabcdef}, 
                std::string{"0xcdef000000000000000000000000000000000000000000000000000000000000"}}, 
            test_case{target{0x22, 0xabcdef}, 
                std::string{"0xef00000000000000000000000000000000000000000000000000000000000000"}}};
        
        EXPECT_EQ(std::is_standard_layout<cross<test_case>>::value, true);
        EXPECT_EQ(std::is_standard_layout<cross<test_case>>::value, true);
                
        //EXPECT_TRUE(check(tests));
    }

}


