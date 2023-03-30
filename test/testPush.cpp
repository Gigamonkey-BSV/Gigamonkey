// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/pattern.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin::interpreter {
    
    struct test_case {
        bool Expected;
        string Bytes;
        
        bool valid () const {
            maybe<bytes> b = encoding::hex::read (Bytes);
            if (!bool (b)) return false;
            program p = decompile (*b);
            if (p.size () != 1) return false;
            instruction i = p.first ();
            if (!i.valid ()) return false;
            return is_minimal (i) == Expected;
        }
    };

    // can result in stack smashing
    TEST (PushTest, TestPushMinimal) {
        for (const auto &x : list<test_case> {
            test_case {true,  "00"},
            test_case {true,  "51"},
            test_case {true,  "0100"},
            test_case {false, "0101"},
            test_case {true,  "52"},
            test_case {false, "0102"},
            test_case {true,  "60"},
            test_case {false, "0110"},
            test_case {true , "0111"},
            test_case {true , "020101"},
            test_case {false, "4c00"},
            test_case {false, "4d0000"},
            test_case {false, "4e00000000"},
            test_case {false, "4c0100"},
            test_case {false, "4c020001"},
            test_case {true,  "4c4c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                "00000000000000000000000000000000000000000000000000000000"}}) {
            maybe<bytes> b = encoding::hex::read (x.Bytes);
            ASSERT_TRUE (bool (b));
            program p = decompile (*b);
            ASSERT_TRUE (p.size () == 1) << "decompiled " << x.Bytes << " as " << p << "; size is " << p.size ();
            instruction i = p.first ();
            ASSERT_TRUE (i.verify (0) == SCRIPT_ERR_OK) << x.Bytes << " failed to verify";
            EXPECT_TRUE (is_minimal (i) == x.Expected) << "expect " << x.Expected << " for " << x.Bytes << "\n\t";
        }
        
    }

    // can result in stack smashing
    TEST (PushTest, TestPushExpectedSize) {
        auto test_size = [] (size_t actual, size_t expected, string test_case) -> void {
            EXPECT_EQ (expected, actual) << "Failure on " << test_case << "; expected " << expected << " got " << actual;
        };
        
        test_size (instruction {OP_0}.serialized_size (), 1, "0:A");
        test_size (instruction {bytes {}}.serialized_size (), 1, "0:B");
        test_size (compile (instruction {OP_0}).size (), 1, "0:C");
        test_size (instruction {bytes {0x00}}.serialized_size (), 2, "0:B");
        
        test_size (instruction {OP_1NEGATE}.serialized_size (), 1, "-1:A");
        test_size (instruction {bytes {0x81}}.serialized_size (), 1, "-1:B");
        test_size (compile (instruction {OP_1NEGATE}).size (), 1, "-1:C");
        
        test_size (instruction {OP_1}.serialized_size (), 1, "1:A");
        test_size (instruction {bytes {0x01}}.serialized_size (), 1, "1:B");
        test_size (compile (instruction {OP_1}).size (), 1, "1:C");
        
        test_size (instruction {OP_16}.serialized_size (), 1, "16:A");
        test_size (instruction {bytes {0x10}}.serialized_size (), 1, "16:B");
        test_size (compile (instruction {OP_16}).size (), 1, "16:C");
        
        test_size (instruction {bytes {0x11}}.serialized_size (), 2, "17:A");
        test_size (compile (instruction {bytes {0x11}}).size (), 2, "17:B");
        
        test_size (instruction {bytes {0x82}}.serialized_size (), 2, "-2:A");
        test_size (compile (instruction {bytes {0x82}}).size (), 2, "-2:B");
        
        test_size (instruction {bytes {0x11, 0x00}}.serialized_size (), 3, "17,0:A");
        test_size (compile (instruction {bytes {0x11, 0x00}}).size (), 3, "17,0:B");
        
    }

}

