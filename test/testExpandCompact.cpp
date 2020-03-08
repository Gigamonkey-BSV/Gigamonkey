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
    
    template <typename f>
    bool dot_cross(f foo, list<test_case> test_cases) {
        list<test_case> input = test_cases;
        while (!input.empty()) {
            list<test_case> expected = input;
            while(!expected.empty()) {
                uint256 in = input.first().Input;
                uint256 ex = expected.first().Expected;
                if ((in == ex && !foo(in, ex)) || (in != ex && foo(in, ex))) return false;
                expected = expected.rest();
            }
            input = input.rest();
        }
        return true;
    }
    
    bool check(list<test_case> test_cases) {
        auto expect_equal = [](uint256 a, uint256 b) -> bool {
            return a == b;
        };
        
        return dot_cross(expect_equal, test_cases);
    }

    // can result in stack smashing
    TEST(ExpandCompactTest, TestExpandCompact) {
        
        auto tests = list<test_case>{} << 
            test_case{target{2, 0xabcdef}, 
                std::string{"0x000000000000000000000000000000000000000000000000000000000000abcd"}} << 
            test_case{target{3, 0xabcdef}, 
                std::string{"0x0000000000000000000000000000000000000000000000000000000000abcdef"}} << 
            test_case{target{4, 0xabcdef}, 
                std::string{"0x00000000000000000000000000000000000000000000000000000000abcdef00"}} << 
            test_case{target{5, 0xabcdef}, 
                std::string{"0x000000000000000000000000000000000000000000000000000000abcdef0000"}} << 
            test_case{target{32, 0xabcdef}, 
                std::string{"0xabcdef0000000000000000000000000000000000000000000000000000000000"}} <<
            test_case{target{33, 0xabcdef}, 
                std::string{"0xcdef000000000000000000000000000000000000000000000000000000000000"}} <<
            test_case{SuccessHalf, 
                std::string{"0x8000000000000000000000000000000000000000000000000000000000000000"}} <<
            test_case{SuccessQuarter, 
                std::string{"0x4000000000000000000000000000000000000000000000000000000000000000"}} <<
            test_case{SuccessEighth, 
                std::string{"0x2000000000000000000000000000000000000000000000000000000000000000"}} <<
            test_case{SuccessSixteenth, 
                std::string{"0x1000000000000000000000000000000000000000000000000000000000000000"}};
                
        EXPECT_TRUE(check(tests));
    }

}


