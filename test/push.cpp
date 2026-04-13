// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/pattern.hpp>
#include <gigamonkey/script/interpreter.hpp>
#include "gtest/gtest.h"

namespace Gigamonkey::Bitcoin {
    
    struct test_case {
        bool Expected;
        string Bytes;
        
        bool valid () const {
            maybe<bytes> b = encoding::hex::read (Bytes);
            if (!bool (b)) return false;
            segment p = decompile (*b);
            if (p.size () != 1) return false;
            instruction i = p.first ();
            if (!i.valid ()) return false;
            return is_minimal_instruction (i) == Expected;
        }
    };

    // can result in stack smashing
    TEST (Push, Minimal) {
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
            segment p = decompile (*b);
            instruction i = p.first ();
            // all pushes are expected to be valid with empty flags.
            ASSERT_TRUE (i.verify (flag {}) == Error::OK) << x.Bytes << " failed to verify";
            EXPECT_TRUE (is_minimal_instruction (i) == x.Expected) << "expect " << x.Expected << " for " << x.Bytes << "\n\t";
        }
        
    }

    // can result in stack smashing
    TEST (Push, ExpectedSize) {
        auto test_size = [] (size_t actual, size_t expected, string test_case) -> void {
            EXPECT_EQ (expected, actual) << "Failure on " << test_case << "; expected " << expected << " got " << actual;
        };
        
        test_size (instruction {OP_0}.serialized_size (), 1, "0:A");
        test_size (instruction {bytes {}}.serialized_size (), 1, "0:B");
        test_size (compile ({instruction {OP_0}}).size (), 1, "0:C");
        test_size (instruction {bytes {0x00}}.serialized_size (), 2, "0:B");
        
        test_size (instruction {OP_1NEGATE}.serialized_size (), 1, "-1:A");
        test_size (instruction {bytes {0x81}}.serialized_size (), 1, "-1:B");
        test_size (compile ({instruction {OP_1NEGATE}}).size (), 1, "-1:C");
        
        test_size (instruction {OP_1}.serialized_size (), 1, "1:A");
        test_size (instruction {bytes {0x01}}.serialized_size (), 1, "1:B");
        test_size (compile ({instruction {OP_1}}).size (), 1, "1:C");
        
        test_size (instruction {OP_16}.serialized_size (), 1, "16:A");
        test_size (instruction {bytes {0x10}}.serialized_size (), 1, "16:B");
        test_size (compile ({instruction {OP_16}}).size (), 1, "16:C");
        
        test_size (instruction {bytes {0x11}}.serialized_size (), 2, "17:A");
        test_size (compile ({instruction {bytes {0x11}}}).size (), 2, "17:B");
        
        test_size (instruction {bytes {0x82}}.serialized_size (), 2, "-2:A");
        test_size (compile ({instruction {bytes {0x82}}}).size (), 2, "-2:B");
        
        test_size (instruction {bytes {0x11, 0x00}}.serialized_size (), 3, "17,0:A");
        test_size (compile ({instruction {bytes {0x11, 0x00}}}).size (), 3, "17,0:B");
        
    }

    TEST (Push, ScriptMinimal) {

        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_FALSE}, bytes {}, flag::VERIFY_MINIMALDATA))) << "OP_FALSE require minimal";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_FALSE}, bytes {}, flag {}))) << "OP_FALSE";

        // other ways of pushing an empty string to the stack.
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x00}, bytes {}, flag::VERIFY_MINIMALDATA))) << "empty push 2";
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA2, 0x00, 0x00}, bytes {}, flag::VERIFY_MINIMALDATA))) << "empty push 3";
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA4, 0x00, 0x00, 0x00, 0x00}, bytes {}, flag::VERIFY_MINIMALDATA))) << "empty push 4";

        // but they are all ok when we stop worrying about minimal data.
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_PUSHDATA1, 0x00}, bytes {}, flag {}))), "empty push 2";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_PUSHDATA2, 0x00, 0x00}, bytes {}, flag {}))), "empty push 3";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_PUSHDATA4, 0x00, 0x00, 0x00, 0x00}, bytes {}, flag {}))), "empty push 4";

        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_1NEGATE}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_1}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_16}, bytes {}, flag::VERIFY_MINIMALDATA)));

        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_1NEGATE}, bytes {}, flag {})));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_1}, bytes {}, flag {})));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_16}, bytes {}, flag {})));

        // Non-minimal ways of pushing -1, 1, and 16
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHSIZE1, 0x81}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHSIZE1, 0x01}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHSIZE1, 0x10}, bytes {}, flag::VERIFY_MINIMALDATA)));

        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x81}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x01}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x10}, bytes {}, flag::VERIFY_MINIMALDATA)));

        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x81}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x01}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x10}, bytes {}, flag::VERIFY_MINIMALDATA)));

        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x81}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x01}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x10}, bytes {}, flag::VERIFY_MINIMALDATA)));

        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHSIZE1, 0x81}, bytes {}, flag {})));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHSIZE1, 0x01}, bytes {}, flag {})));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHSIZE1, 0x10}, bytes {}, flag {})));

        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x81}, bytes {}, flag {})));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x01}, bytes {}, flag {})));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x10}, bytes {}, flag {})));

        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x81}, bytes {}, flag {})));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x01}, bytes {}, flag {})));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x10}, bytes {}, flag {})));

        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x81}, bytes {}, flag {})));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x01}, bytes {}, flag {})));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x10}, bytes {}, flag {})));

        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHSIZE1, 0x20}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHSIZE1, 0x20}, bytes {}, flag {})));

        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x20}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x20}, bytes {}, flag {})));

        EXPECT_NE (Error::OK, (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x20}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x20}, bytes {}, flag {})));

        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x20}, bytes {}, flag::VERIFY_MINIMALDATA)));
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x20}, bytes {}, flag {})));

        // we could have a lot more here but we don't.

    }

    TEST (Push, Script) {

        EXPECT_NE (Error::OK,   (evaluate (bytes {}, bytes {}))) << "empty script";

        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_TRUE}, bytes {}, flag {}))) << "OP_TRUE";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_7}, bytes {}, flag {}))) << "OP_7";

        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHSIZE1, 0x01}, bytes {}, flag {}))) << "40";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_PUSHSIZE1, 0x00}, bytes {}, flag {}))) << "50";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_PUSHSIZE1, 0x80}, bytes {}, flag {}))) << "60";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHSIZE2, 0x01, 0x00}, bytes {}, flag {}))) << "70";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHSIZE3, 0x01, 0x00, 0x00}, bytes {}, flag {}))) << "80";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_PUSHSIZE1, 0x00}, bytes {}, flag {}))) << "90";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_PUSHSIZE2, 0x00, 0x00}, bytes {}, flag {}))) << "100";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_PUSHSIZE3, 0x00, 0x00, 0x00}, bytes {}))) << "110";

        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHSIZE1}, bytes {}, flag {}))) << "invalid PUSHSIZE1";
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHSIZE2, 0x01}, bytes {}, flag {}))) << "invalid PUSHSIZE2";
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHSIZE3, 0x01, 0x00}, bytes {}, flag {}))) << "invalid PUSHSIZE3";

        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_PUSHDATA1, 0x00}, bytes {}, flag {}))), "PUSHDATA1 empty push";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x01}, bytes {}, flag {}))) << "160";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x02, 0x00, 0x01}, bytes {}, flag {}))) << "170";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x03, 0x00, 0x00, 0x01}, bytes {}, flag {}))) << "180";
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x01}, bytes {}, flag {}))) << "PUSHDATA1 invalid push 1";
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x02, 0x01}, bytes {}, flag {}))) << "PUSHDATA1 invalid push 2";
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA1, 0x03, 0x00, 0x01}, bytes {}, flag {}))) << "PUSHDATA1 invalid push 3";

        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_PUSHDATA2, 0x00, 0x00}, bytes {}, flag {}))) << "PUSHDATA2 empty push";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x01}, bytes {}, flag {}))) << "210";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA2, 0x02, 0x00, 0x00, 0x01}, bytes {}, flag {}))) << "220";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA2, 0x03, 0x00, 0x00, 0x00, 0x01}, bytes {}, flag {}))) << "230";
        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00}, bytes {}, flag {}))) << "PUSHDATA2 invalid push";

        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_PUSHDATA4, 0x00, 0x00, 0x00, 0x00}, bytes {}, flag {}))) << "PUSHDATA4 empty push";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x01}, bytes {}, flag {}))) << "PUSHDATA4 size 1";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA4, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00}, bytes {}, flag {}))) << "PUSHDATA4 size 2";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_PUSHDATA4, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00}, bytes {}, flag {}))) << "PUSHDATA4 size 3";

        EXPECT_NE (Error::OK,   (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00}, bytes {}, flag {}))) << "PUSHDATA4 invalid push";
    }

    TEST (Push, UnlockPushOnly) {

        EXPECT_EQ (Error::OK, (evaluate (bytes {}, bytes {OP_TRUE}, flag {})));
        EXPECT_EQ (Error::OK, (evaluate (bytes {}, bytes {OP_TRUE}, flag::VERIFY_SIGPUSHONLY)));

        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_TRUE}, bytes {}, flag {})));
        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_TRUE}, bytes {}, flag::VERIFY_SIGPUSHONLY)));

        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_0, OP_0, OP_EQUAL}, bytes {}, flag {})));
        EXPECT_NE (Error::OK, (evaluate (bytes {OP_0, OP_0, OP_EQUAL}, bytes {}, flag::VERIFY_SIGPUSHONLY)));

        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_0, OP_0}, bytes {OP_EQUAL}, flag {})));
        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_0, OP_0}, bytes {OP_EQUAL}, flag::VERIFY_SIGPUSHONLY)));

    }

}

