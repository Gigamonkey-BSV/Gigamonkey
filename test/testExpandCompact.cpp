// Copyright (c) 2019 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/timechain.hpp>
#include "dot_cross.hpp"
#include "gtest/gtest.h"
#include <type_traits>

namespace Gigamonkey::work {
    
    struct test_case {
        uint256 Input;
        uint256 Expected;
        
        test_case () : Input {}, Expected {} {}
        test_case (compact t, std::string x) : Input {t.expand ()}, Expected {x} {}
    };
    
    bool check (list<test_case> test_cases) {
        list<uint256> input = data::for_each ([] (test_case t) -> uint256 {
            return t.Input;
        }, test_cases) ;
        list<uint256> expected = data::for_each ([] (test_case t) -> uint256 {
            return t.Expected;
        }, test_cases);
        auto expect_equal = [] (uint256 a, uint256 b) -> bool {
            return a != 0 && a == b;
        };
        
        return dot_cross (expect_equal, input, expected);
    }

    // can result in stack smashing
    TEST (ExpandCompactTest, TestExpandCompact) {
        
        // Negative tests
        auto negative_test = compact {32, 0x800000};
        EXPECT_FALSE (negative_test.valid ());
        
        auto tests = list<test_case> {} <<
            test_case {compact {2, 0xabcd},
                std::string {"0x00000000000000000000000000000000000000000000000000000000000000ab"}} <<
            test_case {compact {3, 0xabcd},
                std::string {"0x000000000000000000000000000000000000000000000000000000000000abcd"}} <<
            test_case {compact {4, 0xabcd},
                std::string {"0x0000000000000000000000000000000000000000000000000000000000abcd00"}} <<
            test_case {compact {5, 0xabcd},
                std::string {"0x00000000000000000000000000000000000000000000000000000000abcd0000"}} <<
            test_case {compact {33, 0xabcd},
                std::string {"0xabcd000000000000000000000000000000000000000000000000000000000000"}} <<
            test_case {SuccessHalf,
                std::string {"0x8000000000000000000000000000000000000000000000000000000000000000"}} <<
            test_case {SuccessQuarter,
                std::string {"0x4000000000000000000000000000000000000000000000000000000000000000"}} <<
            test_case {SuccessEighth,
                std::string {"0x2000000000000000000000000000000000000000000000000000000000000000"}} <<
            test_case {SuccessSixteenth,
                std::string {"0x1000000000000000000000000000000000000000000000000000000000000000"}};
                
        EXPECT_TRUE (check (tests));
        
        // TODO
        /*
        uint32_big a(work::compact{32, 0x0080ff});
        uint32_big b{536903935};
        
        EXPECT_EQ(a, b);*/
    }

}


