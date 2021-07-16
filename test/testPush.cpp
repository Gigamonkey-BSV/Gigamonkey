// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/pattern.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin::interpreter {
    
    struct test_case {
        bool Expected;
        string Bytes;
        
        bool valid() const {
            ptr<bytes> b = encoding::hex::read(Bytes);
            if (b == nullptr) return false;
            program p = decompile(*b);
            if (p.size() != 1) return false;
            instruction i = p.first();
            if (!i.valid()) return false;
            return is_minimal(i) == Expected;
        }
    };

    // can result in stack smashing
    TEST(PushTest, TestPush) {
        for(const auto& x : list<test_case>{
            test_case{true,  "00"}, 
            test_case{true,  "51"}, 
            test_case{true,  "0100"}, 
            test_case{false, "0101"}, 
            test_case{true,  "52"}, 
            test_case{false, "0102"}, 
            test_case{true,  "60"}, 
            test_case{false, "0110"}, 
            test_case{true , "0111"}, 
            test_case{true , "020101"}, 
            test_case{false, "4c00"}, 
            test_case{false, "4d0000"}, 
            test_case{false, "4e00000000"}, 
            test_case{false, "4c0100"}, 
            test_case{false, "4c020001"}, 
            test_case{true,  "4c4c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                "00000000000000000000000000000000000000000000000000000000"}}) {
            EXPECT_TRUE(x.valid());
        }
        
    }

}

