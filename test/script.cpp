// Copyright (c) 2019-2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/hash.hpp>
#include <gigamonkey/script/interpreter.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/wif.hpp>
#include <data/encoding/hex.hpp>
#include "gtest/gtest.h"
#include <iostream>

namespace Gigamonkey::Bitcoin {

    void test_program (const bytes &b, bool expected, string explanation = "") {
        if (expected) {
            segment p;
            EXPECT_NO_THROW (p = decompile (b)) << explanation;
            EXPECT_EQ (compile (p), b);
        } else {
            EXPECT_THROW (decompile (b), invalid_program) << explanation;
        }
    }

    TEST (Script, Decompile) {
        // empty program
        test_program (bytes {}, true);

        // list of ops
        test_program (bytes {OP_FALSE, OP_1NEGATE, OP_1, OP_NOP, OP_TOALTSTACK, OP_DROP,
            OP_EQUALVERIFY, OP_1ADD, OP_CHECKMULTISIGVERIFY, OP_NOP10}, true);

        // invalid push
        test_program (bytes {OP_PUSHSIZE1}, false);
        test_program (bytes {OP_PUSHSIZE2, 0x23}, false);
        test_program (bytes {OP_PUSHDATA1, 0x02, 0x11}, false);
        test_program (bytes {OP_PUSHDATA2, 0x02, 0x00, 0x12}, false);
        test_program (bytes {OP_PUSHDATA4, 0x02, 0x00, 0x00, 0x00, 0x13}, false);

        // op return with no data
        test_program (bytes {OP_RETURN}, true);
        test_program (bytes {OP_FALSE, OP_RETURN}, true);

        // op return with data
        test_program (bytes {OP_RETURN, OP_PUSHSIZE1}, false);
        test_program (bytes {OP_FALSE, OP_RETURN, OP_PUSHSIZE1}, false);
    }

    TEST (Script, Profile) {
        script_config default_profile {};
        script_config v1_after_genesis {1, epoch::genesis};
        script_config v2_after_genesis {2, epoch::genesis};
        script_config v1_before_genesis {1, epoch::exodus};
        script_config v2_before_genesis {2, epoch::exodus};

        EXPECT_EQ (default_profile, v1_after_genesis);

        // malleability checks should be turned on in version 1, off in version 2.
        EXPECT_TRUE (verify_signature_low_S (v1_before_genesis.Flags));
        EXPECT_TRUE (verify_null_dummy (v1_before_genesis.Flags));
        EXPECT_TRUE (verify_unlock_push_only (v1_before_genesis.Flags));
        EXPECT_TRUE (verify_minimal_push (v1_before_genesis.Flags));
        EXPECT_TRUE (verify_clean_stack (v1_before_genesis.Flags));
        EXPECT_TRUE (verify_minimal_if (v1_before_genesis.Flags));
        EXPECT_TRUE (verify_null_fail (v1_before_genesis.Flags));
        EXPECT_TRUE (verify_compressed_pubkey (v1_before_genesis.Flags));

        EXPECT_FALSE (verify_signature_low_S (v2_before_genesis.Flags));
        EXPECT_FALSE (verify_null_dummy (v2_before_genesis.Flags));
        EXPECT_FALSE (verify_unlock_push_only (v2_before_genesis.Flags));
        EXPECT_FALSE (verify_minimal_push (v2_before_genesis.Flags));
        EXPECT_FALSE (verify_clean_stack (v2_before_genesis.Flags));
        EXPECT_FALSE (verify_minimal_if (v2_before_genesis.Flags));
        EXPECT_FALSE (verify_null_fail (v2_before_genesis.Flags));
        EXPECT_FALSE (verify_compressed_pubkey (v2_before_genesis.Flags));

        EXPECT_TRUE (verify_signature_low_S (v1_after_genesis.Flags));
        EXPECT_TRUE (verify_null_dummy (v1_after_genesis.Flags));
        EXPECT_TRUE (verify_unlock_push_only (v1_after_genesis.Flags));
        EXPECT_TRUE (verify_minimal_push (v1_after_genesis.Flags));
        EXPECT_TRUE (verify_clean_stack (v1_after_genesis.Flags));
        EXPECT_TRUE (verify_minimal_if (v1_after_genesis.Flags));
        EXPECT_TRUE (verify_null_fail (v1_after_genesis.Flags));
        EXPECT_TRUE (verify_compressed_pubkey (v1_after_genesis.Flags));

        EXPECT_FALSE (verify_signature_low_S (v2_after_genesis.Flags));
        EXPECT_FALSE (verify_null_dummy (v2_after_genesis.Flags));
        EXPECT_FALSE (verify_unlock_push_only (v2_after_genesis.Flags));
        EXPECT_FALSE (verify_minimal_push (v2_after_genesis.Flags));
        EXPECT_FALSE (verify_clean_stack (v2_after_genesis.Flags));
        EXPECT_FALSE (verify_minimal_if (v2_after_genesis.Flags));
        EXPECT_FALSE (verify_null_fail (v2_after_genesis.Flags));
        EXPECT_FALSE (verify_compressed_pubkey (v2_after_genesis.Flags));

        // before genesis p2sh should be enabled.
        EXPECT_TRUE (v1_before_genesis.verify_P2SH ());
        EXPECT_TRUE (v2_before_genesis.verify_P2SH ());

        EXPECT_FALSE (v1_after_genesis.verify_P2SH ());
        EXPECT_FALSE (v2_after_genesis.verify_P2SH ());

        EXPECT_FALSE (custom_script_limits (v1_before_genesis.Flags));
        EXPECT_FALSE (custom_script_limits (v2_before_genesis.Flags));

        EXPECT_TRUE (custom_script_limits (v1_after_genesis.Flags));
        EXPECT_TRUE (custom_script_limits (v2_after_genesis.Flags));

        EXPECT_FALSE (safe_return_data (v1_before_genesis.Flags));
        EXPECT_FALSE (safe_return_data (v2_before_genesis.Flags));

        EXPECT_TRUE (safe_return_data (v1_after_genesis.Flags));
        EXPECT_TRUE (safe_return_data (v2_after_genesis.Flags));

    }

    void error (Error r, string explanation = "") {
        EXPECT_TRUE (bool (r)) << explanation;
        EXPECT_NE (r, Error::FAIL) << explanation << "; " << r;
    }

    // TODO different op codes should be invalid under different script profiles
    TEST (Script, InvalidOpcode) {

         // invalid op codes
         EXPECT_EQ (Error::BAD_OPCODE, (evaluate (bytes {OP_RESERVED}, bytes {}))) << "OP_RESERVED is an invalid op code";
         EXPECT_EQ (Error::BAD_OPCODE, (evaluate (bytes {OP_RESERVED1}, bytes {}))) << "OP_RESERVED1 is an invalid op code";
         EXPECT_EQ (Error::BAD_OPCODE, (evaluate (bytes {OP_RESERVED2}, bytes {}))) << "OP_RESERVED2 is an invalid op code";
         EXPECT_EQ (Error::BAD_OPCODE, (evaluate (bytes {FIRST_UNDEFINED_OP_VALUE}, bytes {}))) << "FIRST_UNDEFINED_OP_VALUE is an invalid op code";
         EXPECT_EQ (Error::BAD_OPCODE, (evaluate (bytes {OP_INVALIDOPCODE}, bytes {}))) << "OP_BADOPCODE is an invalid op code";

    }

    // TODO there are different NOPs that are treated as different things
    // under different script profiles.
    TEST (Script, NOP) {

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_NOP}, bytes {}, flag {}))) << "OP_NOP 1";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_1, OP_NOP}, bytes {}, flag::VERIFY_CLEANSTACK))) << "OP_NOP 2";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_0, OP_NOP}, bytes {}, flag::VERIFY_CLEANSTACK))) << "OP_NOP 3";

    }

    TEST (Script, Opcodes) {

        // OP_DEPTH
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {}, bytes {OP_DEPTH}, flag {}))) << "OP DEPTH 1";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_FALSE}, bytes {OP_DEPTH}, flag {}))) << "OP DEPTH 2";

        // OP_EQUAL
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_FALSE, OP_FALSE}, bytes {OP_EQUAL}))) << "EQUAL 1";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_FALSE, OP_PUSHSIZE1, 0x00}, bytes {OP_EQUAL}, flag {}))) << "EQUAL 2";

        // OP_SIZE
        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_0, OP_SIZE}, bytes {OP_0, OP_EQUAL}, flag {})));
        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_1, OP_SIZE}, bytes {OP_1, OP_EQUAL}, flag {})));
        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_16, OP_SIZE}, bytes {OP_1, OP_EQUAL}, flag {})));
        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_PUSHSIZE3, 0x11, 0x12, 0x13, OP_SIZE}, bytes {OP_3, OP_EQUAL}, flag {})));

    }

    TEST (Script, Verify) {

        EXPECT_EQ (Error::VERIFY, (evaluate (bytes {OP_FALSE}, bytes {OP_VERIFY}, flag {}))) << "OP_VERIFY 1";

        EXPECT_EQ (Error::INVALID_STACK_OPERATION,
            (evaluate (bytes {OP_TRUE}, bytes {OP_VERIFY}, flag {}))) << "OP_VERIFY 2";

        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_FALSE, OP_TRUE}, bytes {OP_VERIFY}, flag {}))) << "OP_VERIFY 3";

        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_TRUE, OP_TRUE}, bytes {OP_VERIFY}, flag {}))) << "OP_VERIFY 4";

    }

    TEST (Script, AltStack) {

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_TOALTSTACK}, bytes {}, flag {}))) << "OP_TOALTSTACK";
        EXPECT_EQ (Error::INVALID_ALTSTACK_OPERATION, (evaluate (bytes {OP_FROMALTSTACK}, bytes {}, flag {}))) << "OP_FROMALTSTACK";

        // OP_TOALTSTACK
        error (evaluate (bytes {}, bytes {OP_TOALTSTACK}, flag {}), "alt stack 0");
        error (evaluate (bytes {}, bytes {OP_FROMALTSTACK}, flag {}), "alt stack 1");

        // OP_TOALTSTACK
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_1}, bytes {OP_TOALTSTACK}, flag {}))) << "alt stack 2";
        // OP_FROMALTSTACK
        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_1}, bytes {OP_TOALTSTACK, OP_FROMALTSTACK}, flag {}))) << "alt stack 3";
    }

    // we tested those particular ops first in order to make the following definitions.
    template <typename X>
    segment stack_equal (list<X> stack) {
        list<instruction> test_program;
        for (const X &b : reverse (stack)) {
            test_program <<= push_data (b);
            test_program <<= OP_EQUALVERIFY;
        }

        test_program <<= OP_DEPTH;
        test_program <<= OP_0;
        test_program <<= OP_EQUAL;

        return test_program;
    }

    template <typename X>
    segment stack_initialize (list<X> stack) {
        list<instruction> test_program;
        for (const X &b : stack) test_program <<= push_data (b);
        return test_program;
    }

    template <typename X>
    void test_op_error (op Op, list<X> start, string explanation) {
        error (evaluate (compile (stack_initialize<X> (start)), bytes {Op}, flag {}), explanation);
    }

    template <typename X>
    void test_op (op Op, list<X> start, list<X> expected, string explanation = "") {
        EXPECT_EQ (Error::OK,
            (evaluate (compile (stack_initialize<X> (start) << Op), compile (stack_equal<X> (expected)), flag {})))
                << explanation;
    }

    void test_pick_roll_error (list<int> start, string explanation) {
        test_op_error<int> (OP_PICK, start, explanation);
        test_op_error<int> (OP_ROLL, start, explanation);
    }

    void test_pick_roll (list<int> start, list<int> expected_roll, list<int> expected_pick, string explanation) {
        test_op<int> (OP_PICK, start, expected_pick, explanation);
        test_op<int> (OP_ROLL, start, expected_roll, explanation);
    }

    TEST (Script, PickRoll) {

        test_pick_roll_error ({0}, "error 0");
        test_pick_roll_error ({9, 1}, "error 1");
        test_pick_roll_error ({12, 9, 2}, "error 2");
        test_pick_roll_error ({34, 12, 9, 3}, "error 3");

        test_pick_roll ({12, 0}, {12}, {12, 12}, "success 0");
        test_pick_roll ({34, 12, 1}, {12, 34}, {34, 12, 34}, "success 1");
        test_pick_roll ({17, 34, 12, 2}, {34, 12, 17}, {17, 34, 12, 17}, "success 2");

    }

    auto test_stack_op_error = &test_op_error<int>;

    auto test_stack_op = &test_op<int>;

    TEST (Script, StackOps) {

        test_stack_op (OP_DROP, {3}, {}, "DROP");
        test_stack_op (OP_2DROP, {4, 5}, {}, "2DROP");

        test_stack_op (OP_DUP, {0}, {0, 0}, "DUP 0");
        test_stack_op (OP_DUP, {1}, {1, 1}, "DUP 1");
        test_stack_op (OP_DUP, {2}, {2, 2}, "DUP 2");

        test_stack_op (OP_IFDUP, {0}, {0}, "IFDUP 0");
        test_stack_op (OP_IFDUP, {1}, {1, 1}, "IFDUP 1");
        test_stack_op (OP_IFDUP, {2}, {2, 2}, "IFDUP 2");

        test_stack_op (OP_2DUP, {0, 1}, {0, 1, 0, 1}, "2DUP");
        test_stack_op (OP_3DUP, {0, 1, 2}, {0, 1, 2, 0, 1, 2}, "3DUP");

        test_stack_op (OP_SWAP, {8, 9}, {9, 8}, "SWAP");
        test_stack_op (OP_2SWAP, {10, 11, 12, 13}, {12, 13, 10, 11}, "2SWAP");

        test_stack_op (OP_OVER, {-1, -2}, {-1, -2, -1}, "OVER");
        test_stack_op (OP_2OVER, {-1, -2, -3, -4}, {-1, -2, -3, -4, -1, -2}, "2OVER");

        test_stack_op (OP_ROT, {1, 2, 3}, {2, 3, 1}, "ROT");
        test_stack_op (OP_2ROT, {1, 2, 3, 4, 5, 6}, {3, 4, 5, 6, 1, 2}, "2ROT");

        test_stack_op (OP_NIP, {1, 2}, {2}, "NIP");
        test_stack_op (OP_TUCK, {1, 2}, {2, 1, 2}, "TUCK");

    }

    void test_hash_op (op Op, slice<const byte> input, slice<const byte> result, bool expected = true) {
        if (expected)
            EXPECT_EQ (Error::OK,
                (evaluate (compile ({push_data (input)}), compile (segment {Op, push_data (result), OP_EQUAL}), {})));
        else EXPECT_EQ (Error::FAIL, (evaluate (compile ({push_data (input)}), compile (segment {Op, push_data (result), OP_EQUAL}), {})));
    }

    TEST (Script, HashOps) {
        test_hash_op (OP_SHA1, bytes {}, *encoding::hex::read ("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        test_hash_op (OP_SHA256, bytes {}, *encoding::hex::read ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
        test_hash_op (OP_RIPEMD160, bytes {}, *encoding::hex::read ("9c1185a5c5e9fc54612808977ee8f548b2258d31"));
        test_hash_op (OP_HASH160, bytes {}, RIPEMD_160 (SHA2_256 (bytes {})));
        test_hash_op (OP_HASH256, bytes {}, SHA2_256 (SHA2_256 (bytes {})));
    }

    void test_data_op_error (op Op, list<bytes> start, string explanation = "") {
        test_op_error (Op, start, explanation);
    }

    void test_data_op (op Op, list<bytes> start, list<bytes> expected, string explanation = "") {
        test_op (Op, start, expected, explanation);
    }

    TEST (Script, EqualVerify) {

        // OP_EQUALVERIFY
        EXPECT_EQ (Error::INVALID_STACK_OPERATION,
            (evaluate (bytes {OP_FALSE, OP_FALSE}, bytes {OP_EQUALVERIFY}, flag {})))
                << "EQUALVERIFY 1";

        auto eval_err_2 = evaluate (bytes {OP_1, OP_1}, bytes {OP_EQUALVERIFY}, flag {});

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, eval_err_2) << "OP_EQUALVERIFY 2";

        error (evaluate (bytes {OP_FALSE, OP_TRUE}, bytes {OP_EQUALVERIFY}, flag {}), "EQUALVERIFY 2");

        EXPECT_EQ (Error::OK,
            (evaluate (bytes {OP_FALSE, OP_FALSE}, bytes {OP_EQUALVERIFY, OP_1}, flag::VERIFY_CLEANSTACK)))
                << "EQUALVERIFY 3";

        test_data_op (OP_EQUALVERIFY, {{0x01}, {0x01}}, {});
        test_data_op_error (OP_EQUALVERIFY, {{0x01}, {0x01, 0x00}}, {});
        test_data_op_error (OP_EQUALVERIFY, {{0x81}, {0x01}});

        auto eval_err_1 = evaluate (bytes {OP_0, OP_1}, bytes {OP_EQUALVERIFY}, flag {});

        EXPECT_EQ (Error::EQUALVERIFY, eval_err_1) << "OP_EQUALVERIFY 1";

        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_FALSE, OP_1, OP_1}, bytes {OP_EQUALVERIFY}, flag {}))) << "OP_EQUALVERIFY 3";

        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_TRUE, OP_1, OP_1}, bytes {OP_EQUALVERIFY}, flag {}))) << "OP_EQUALVERIFY 4";

    }

    TEST (Script, BoolOps) {

        // should replace 0 to 1, everything other than zero to zero
        test_data_op (OP_NOT, {{}}, {{0x01}});
        test_data_op (OP_NOT, {{0x00}}, {{0x01}});
        test_data_op (OP_NOT, {{0x80}}, {{0x01}});
        test_data_op (OP_NOT, {{0x01}}, {{}});
        test_data_op (OP_NOT, {{0x02}}, {{}});
        test_data_op (OP_NOT, {{0x81}}, {{}});

        test_data_op (OP_BOOLAND, {{}, {}}, {{}});
        test_data_op (OP_BOOLOR, {{}, {}}, {{}});
        test_data_op (OP_BOOLAND, {{0x00}, {0x00}}, {{}});
        test_data_op (OP_BOOLOR, {{0x00}, {0x00}}, {{}});

        test_data_op (OP_BOOLAND, {{0x01}, {}}, {{}});
        test_data_op (OP_BOOLOR, {{0x01}, {}}, {{0x01}});
        test_data_op (OP_BOOLAND, {{0x81}, {}}, {{}});
        test_data_op (OP_BOOLOR, {{0x81}, {}}, {{0x01}});

        test_data_op (OP_BOOLAND, {{}, {0x01}}, {{}});
        test_data_op (OP_BOOLOR, {{}, {0x01}}, {{0x01}});
        test_data_op (OP_BOOLAND, {{}, {0x81}}, {{}});
        test_data_op (OP_BOOLOR, {{}, {0x81}}, {{0x01}});

        test_data_op (OP_BOOLAND, {{0x01}, {0x01}}, {{0x01}});
        test_data_op (OP_BOOLOR, {{0x01}, {0x01}}, {{0x01}});

    }

    TEST (Script, BitOps) {

        test_data_op_error (OP_AND, {{}, {0x00}}, "AND args must be the same size 1");
        test_data_op_error (OP_OR, {{}, {0x00}}, "OR args must be the same size 1");
        test_data_op_error (OP_XOR, {{}, {0x00}}, "XOR args must be the same size 1");

        test_data_op_error (OP_AND, {{0x00}, {}}, "AND args must be the same size 2");
        test_data_op_error (OP_OR, {{0x00}, {}}, "OR args must be the same size 2");
        test_data_op_error (OP_XOR, {{0x00}, {}}, "XOR args must be the same size 2");

        test_data_op (OP_INVERT, {{}}, {{}}, "INVERT {}");
        test_data_op (OP_INVERT, {{0xff}}, {{0x00}}, "INVERT {ff}");
        test_data_op (OP_INVERT, {{0x00}}, {{0xff}}, "INVERT {00}");

        test_data_op (OP_AND, {{}, {}}, {{}}, "{} AND {}");
        test_data_op (OP_OR, {{}, {}}, {{}}, "{} OR {}");
        test_data_op (OP_XOR, {{}, {}}, {{}}, "{} XOR {}");

        test_data_op (OP_AND, {{0x74}, {0xa3}}, {{0x20}}, "{74} AND {a3}");
        test_data_op (OP_AND, {{0xa3}, {0x74}}, {{0x20}}, "{a3} AND {74}");

        test_data_op (OP_OR, {{0x74}, {0xa3}}, {{0xf7}}, "{74} OR {a3}");
        test_data_op (OP_OR, {{0xa3}, {0x74}}, {{0xf7}}, "{a3} OR {74}");

        test_data_op (OP_XOR, {{0x74}, {0xa3}}, {{0xd7}}, "{74} XOR {a3}");
        test_data_op (OP_XOR, {{0xa3}, {0x74}}, {{0xd7}}, "{a3} XOR {74}");

    }

    TEST (Script, StringOps) {

        test_data_op (OP_CAT, {{}, {}}, {{}});
        test_data_op (OP_CAT, {{0x78}, {}}, {{0x78}});
        test_data_op (OP_CAT, {{}, {0x78}}, {{0x78}});
        test_data_op (OP_CAT, {{0xab}, {0xcd}}, {{0xab, 0xcd}});

        test_data_op_error (OP_SPLIT, {{0xab, 0xcd}, {0x81}});
        test_data_op (OP_SPLIT, {{0xab, 0xcd}, {}}, {{}, {0xab, 0xcd}});
        test_data_op (OP_SPLIT, {{0xab, 0xcd}, {0x01}}, {{0xab}, {0xcd}});
        test_data_op (OP_SPLIT, {{0xab, 0xcd}, {0x02}}, {{0xab, 0xcd}, {}});
        test_data_op_error (OP_SPLIT, {{0xab, 0xcd}, {0x03}});

        test_data_op_error (OP_LEFT, {{0xab, 0xcd}, {0x81}});
        test_data_op (OP_LEFT, {{0xab, 0xcd}, {}}, {{}});
        test_data_op (OP_LEFT, {{0xab, 0xcd}, {0x01}}, {{0xab}});
        test_data_op (OP_LEFT, {{0xab, 0xcd}, {0x02}}, {{0xab, 0xcd}});
        test_data_op_error (OP_LEFT, {{0xab, 0xcd}, {0x03}});

        test_data_op_error (OP_RIGHT, {{0xab, 0xcd}, {0x81}});
        test_data_op (OP_RIGHT, {{0xab, 0xcd}, {}}, {{}});
        test_data_op (OP_RIGHT, {{0xab, 0xcd}, {0x01}}, {{0xcd}});
        test_data_op (OP_RIGHT, {{0xab, 0xcd}, {0x02}}, {{0xab, 0xcd}});
        test_data_op_error (OP_RIGHT, {{0xab, 0xcd}, {0x03}});

        test_data_op_error (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x81}, {0x00}});
        test_data_op_error (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {}, {0x81}});
        test_data_op_error (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {}, {0x04}});
        test_data_op_error (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x01}, {0x03}});
        test_data_op_error (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x02}, {0x02}});
        test_data_op_error (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x03}, {0x01}});

        test_data_op (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x00}, {0x00}}, {{}});
        test_data_op (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x01}, {0x00}}, {{}});
        test_data_op (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x02}, {0x00}}, {{}});
        test_data_op (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x03}, {0x00}}, {{}});
        test_data_op (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x00}, {0x01}}, {{0xab}});
        test_data_op (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x01}, {0x01}}, {{0xcd}});
        test_data_op (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x02}, {0x01}}, {{0xef}});
        test_data_op (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x00}, {0x02}}, {{0xab, 0xcd}});
        test_data_op (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x01}, {0x02}}, {{0xcd, 0xef}});
        test_data_op (OP_SUBSTR, {{0xab, 0xcd, 0xef}, {0x00}, {0x03}}, {{0xab, 0xcd, 0xef}});

    }

    TEST (Script, Shift) {

        // negative numbers not allowed.
        test_data_op_error (OP_LSHIFT, {{}, {0x81}});
        test_data_op_error (OP_RSHIFT, {{}, {0x81}});

        test_data_op (OP_LSHIFT, {{}, {}}, {{}});
        test_data_op (OP_RSHIFT, {{}, {}}, {{}});
        test_data_op (OP_LSHIFT, {{}, {0x01}}, {{}});
        test_data_op (OP_RSHIFT, {{}, {0x01}}, {{}});

        test_data_op (OP_LSHIFT, {{0xff}, {}}, {{0xff}});
        test_data_op (OP_RSHIFT, {{0xff}, {}}, {{0xff}});
        test_data_op (OP_LSHIFT, {{0xff}, {0x01}}, {{0xfe}});
        test_data_op (OP_RSHIFT, {{0xff}, {0x01}}, {{0x7f}});
        test_data_op (OP_LSHIFT, {{0xff}, {0x02}}, {{0xfc}});
        test_data_op (OP_RSHIFT, {{0xff}, {0x02}}, {{0x3f}});
        test_data_op (OP_LSHIFT, {{0xff}, {0x04}}, {{0xf0}});
        test_data_op (OP_RSHIFT, {{0xff}, {0x04}}, {{0x0f}});
        test_data_op (OP_LSHIFT, {{0xff}, {0x08}}, {{0x00}});
        test_data_op (OP_RSHIFT, {{0xff}, {0x08}}, {{0x00}});

        test_data_op (OP_LSHIFT, {{0xff, 0xff}, {}}, {{0xff, 0xff}});
        test_data_op (OP_RSHIFT, {{0xff, 0xff}, {}}, {{0xff, 0xff}});
        test_data_op (OP_LSHIFT, {{0xff, 0xff}, {0x01}}, {{0xff, 0xfe}});
        test_data_op (OP_RSHIFT, {{0xff, 0xff}, {0x01}}, {{0x7f, 0xff}});
        test_data_op (OP_LSHIFT, {{0xff, 0xff}, {0x02}}, {{0xff, 0xfc}});
        test_data_op (OP_RSHIFT, {{0xff, 0xff}, {0x02}}, {{0x3f, 0xff}});
        test_data_op (OP_LSHIFT, {{0xff, 0xff}, {0x04}}, {{0xff, 0xf0}});
        test_data_op (OP_RSHIFT, {{0xff, 0xff}, {0x04}}, {{0x0f, 0xff}});
        test_data_op (OP_LSHIFT, {{0xff, 0xff}, {0x08}}, {{0xff, 0x00}});
        test_data_op (OP_RSHIFT, {{0xff, 0xff}, {0x08}}, {{0x00, 0xff}});

    }

    TEST (Script, Bin2Num2Bin) {

        // Different representations of zero.
        test_data_op (OP_BIN2NUM, {{}}, {{}});
        test_data_op (OP_BIN2NUM, {{0x00}}, {{}});
        test_data_op (OP_BIN2NUM, {{0x80}}, {{}});
        test_data_op (OP_BIN2NUM, {{0x00, 0x00}}, {{}});
        test_data_op (OP_BIN2NUM, {{0x00, 0x80}}, {{}});

        test_data_op (OP_BIN2NUM, {{0x01}}, {{0x01}});
        test_data_op (OP_BIN2NUM, {{0x01, 0x00}}, {{0x01}}, "1 size 2");

        test_data_op (OP_BIN2NUM, {{0x81}}, {{0x81}});
        test_data_op (OP_BIN2NUM, {{0x01, 0x80}}, {{0x81}}, "-1 size 2");

        test_data_op (OP_BIN2NUM, {{0x81, 0x00}}, {{0x81, 0x00}});
        test_data_op (OP_BIN2NUM, {{0x81, 0x00, 0x00}}, {{0x81, 0x00}}, "129 size 3");

        test_data_op (OP_BIN2NUM, {{0x81, 0x80}}, {{0x81, 0x80}});
        test_data_op (OP_BIN2NUM, {{0x81, 0x00, 0x80}}, {{0x81, 0x80}});

        test_data_op_error (OP_NUM2BIN, {{}, {0x81}}, "size -1 is an error 1");
        test_data_op_error (OP_NUM2BIN, {{0x00}, {0x81}}, "size -1 is an error 2");
        test_data_op_error (OP_NUM2BIN, {{0x80}, {0x00}}, "-0 to size 0");
        test_data_op_error (OP_NUM2BIN, {{0x01}, {0x00}}, "1 to size 0");
        test_data_op_error (OP_NUM2BIN, {{0x81}, {0x00}}, "-1 to size 0");
        test_data_op_error (OP_NUM2BIN, {{0x00, 0x01}, {0x00}});
        test_data_op_error (OP_NUM2BIN, {{0x00, 0x01}, {0x01}});
        test_data_op_error (OP_NUM2BIN, {{0x00, 0x81}, {0x00}});
        test_data_op_error (OP_NUM2BIN, {{0x00, 0x81}, {0x01}});
        test_data_op_error (OP_NUM2BIN, {{0xf0, 0x80}, {0x00}});
        test_data_op_error (OP_NUM2BIN, {{0xf0, 0x80}, {0x01}});

        test_data_op (OP_NUM2BIN, {{}, {}}, {{}});
        test_data_op (OP_NUM2BIN, {{}, {0x01}}, {{0x00}});
        test_data_op (OP_NUM2BIN, {{}, {0x02}}, {{0x00, 0x00}});

        test_data_op (OP_NUM2BIN, {{0x00}, {0x01}}, {{0x00}});
        test_data_op (OP_NUM2BIN, {{0x00}, {0x02}}, {{0x00, 0x00}});

        test_data_op (OP_NUM2BIN, {{0x80}, {0x01}}, {{0x80}});
        test_data_op (OP_NUM2BIN, {{0x80}, {0x02}}, {{0x00, 0x80}});
        test_data_op (OP_NUM2BIN, {{0x80}, {0x03}}, {{0x00, 0x00, 0x80}});

        test_data_op (OP_NUM2BIN, {{0x00, 0x01}, {0x02}}, {{0x00, 0x01}});
        test_data_op (OP_NUM2BIN, {{0x00, 0x81}, {0x02}}, {{0x00, 0x81}});
        test_data_op (OP_NUM2BIN, {{0xf0, 0x80}, {0x02}}, {{0xf0, 0x80}});

        test_data_op (OP_NUM2BIN, {{0x00, 0x01}, {0x03}}, {{0x00, 0x01, 0x00}});
        test_data_op (OP_NUM2BIN, {{0x00, 0x81}, {0x03}}, {{0x00, 0x01, 0x80}});
        test_data_op (OP_NUM2BIN, {{0xf0, 0x80}, {0x03}}, {{0xf0, 0x00, 0x80}});

    }

    TEST (Script, NumberCompare) {

        // number representations organized in equal sets ordered from least to greatest.
        list<list<bytes>> equals_test_cases {
            {{0xf0, 0x80}, {0xf0, 0x00, 0x80}},
            {{0x81}, {0x01, 0x80}, {0x01, 0x00, 0x80}},
            {{}, {0x00}, {0x80}, {0x00, 0x00}, {0x00, 0x80}},
            {{0x01}, {0x01, 0x00}, {0x01, 0x00, 0x00}},
            {{0xf0, 0x00}, {0xf0, 0x00, 0x00}}};

        while (data::size (equals_test_cases) > 0) {
            list<bytes> current_set = first (equals_test_cases);
            equals_test_cases = rest (equals_test_cases);

            while (data::size (current_set) > 0) {
                bytes left = first (current_set);
                list<bytes> right_set = current_set;

                current_set = rest (current_set);

                while (data::size (right_set) > 0) {

                    bytes right = first (right_set);
                    right_set = rest (right_set);

                    EXPECT_EQ (Error::OK,
                        (evaluate (compile (stack_initialize<bytes> ({left, right})), {OP_NUMEQUAL}, flag {})));

                    EXPECT_EQ (Error::OK,
                        (evaluate (compile (stack_initialize<bytes> ({right, left})), {OP_NUMEQUAL}, flag {})));

                    EXPECT_EQ (Error::FAIL, (evaluate (compile (stack_initialize<bytes> ({left, right})), {OP_NUMNOTEQUAL}, flag {})));
                    EXPECT_EQ (Error::FAIL, (evaluate (compile (stack_initialize<bytes> ({right, left})), {OP_NUMNOTEQUAL}, flag {})));

                    EXPECT_EQ (Error::FAIL, (evaluate (compile (stack_initialize<bytes> ({left, right})), {OP_LESSTHAN}, flag {})));
                    EXPECT_EQ (Error::FAIL, (evaluate (compile (stack_initialize<bytes> ({left, right})), {OP_GREATERTHAN}, flag {})));
                    EXPECT_EQ (Error::FAIL, (evaluate (compile (stack_initialize<bytes> ({right, left})), {OP_LESSTHAN}, flag {})));
                    EXPECT_EQ (Error::FAIL, (evaluate (compile (stack_initialize<bytes> ({right, left})), {OP_GREATERTHAN}, flag {})));

                    EXPECT_EQ (Error::OK,   (evaluate (compile (stack_initialize<bytes> ({left, right})), {OP_LESSTHANOREQUAL}, flag {})));
                    EXPECT_EQ (Error::OK,   (evaluate (compile (stack_initialize<bytes> ({left, right})), {OP_GREATERTHANOREQUAL}, flag {})));
                    EXPECT_EQ (Error::OK,   (evaluate (compile (stack_initialize<bytes> ({right, left})), {OP_LESSTHANOREQUAL}, flag {})));
                    EXPECT_EQ (Error::OK,   (evaluate (compile (stack_initialize<bytes> ({right, left})), {OP_GREATERTHANOREQUAL}, flag {})));

                }

                auto right_sets = equals_test_cases;
                while (data::size (right_sets) > 0) {
                    right_set = first (right_sets);
                    right_sets = rest (right_sets);

                    while (data::size (right_set) > 0) {
                        bytes right = first (right_set);
                        right_set = rest (right_set);

                        EXPECT_EQ (Error::FAIL, (evaluate (compile (stack_initialize<bytes> ({left, right})), {OP_NUMEQUAL}, flag {})));
                        EXPECT_EQ (Error::FAIL, (evaluate (compile (stack_initialize<bytes> ({right, left})), {OP_NUMEQUAL}, flag {})));

                        EXPECT_EQ (Error::OK,   (evaluate (compile (stack_initialize<bytes> ({left, right})), {OP_NUMNOTEQUAL}, flag {})));
                        EXPECT_EQ (Error::OK,   (evaluate (compile (stack_initialize<bytes> ({right, left})), {OP_NUMNOTEQUAL}, flag {})));

                        EXPECT_EQ (Error::OK,   (evaluate (compile (stack_initialize<bytes> ({left, right})), {OP_LESSTHAN}, flag {})));
                        EXPECT_EQ (Error::FAIL, (evaluate (compile (stack_initialize<bytes> ({left, right})), {OP_GREATERTHAN}, flag {})));
                        EXPECT_EQ (Error::FAIL, (evaluate (compile (stack_initialize<bytes> ({right, left})), {OP_LESSTHAN}, flag {})));
                        EXPECT_EQ (Error::OK,   (evaluate (compile (stack_initialize<bytes> ({right, left})), {OP_GREATERTHAN}, flag {})));

                        EXPECT_EQ (Error::OK,   (evaluate (compile (stack_initialize<bytes> ({left, right})), {OP_LESSTHANOREQUAL}, flag {})));
                        EXPECT_EQ (Error::FAIL, (evaluate (compile (stack_initialize<bytes> ({left, right})), {OP_GREATERTHANOREQUAL}, flag {})));
                        EXPECT_EQ (Error::FAIL, (evaluate (compile (stack_initialize<bytes> ({right, left})), {OP_LESSTHANOREQUAL}, flag {})));
                        EXPECT_EQ (Error::OK,   (evaluate (compile (stack_initialize<bytes> ({right, left})), {OP_GREATERTHANOREQUAL}, flag {})));

                    }
                }
            }
        }

    }

    TEST (Script, NumberWithin) {

        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_0, OP_0, OP_0}, bytes {OP_WITHIN}, flag {}))) << "Within 1";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_0, OP_0, OP_1}, bytes {OP_WITHIN}, flag {}))) << "Within 2";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_1, OP_0, OP_1}, bytes {OP_WITHIN}, flag {}))) << "Within 3";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_1, OP_0, OP_2}, bytes {OP_WITHIN}, flag {}))) << "Within 4";

    }

    TEST (Script, NumberEqualVerify) {

        test_data_op (OP_NUMEQUALVERIFY, {{0x01}, {0x01, 0x00}}, {});
        test_data_op_error (OP_NUMEQUALVERIFY, {{0x81}, {0x01}});

        error (evaluate (bytes {OP_0, OP_1}, bytes {OP_NUMEQUALVERIFY}, flag {}), "OP_NUMEQUALVERIFY 1");

        EXPECT_EQ (Error::INVALID_STACK_OPERATION,
            (evaluate (bytes {OP_1, OP_1}, bytes {OP_NUMEQUALVERIFY}, flag {}))) << "OP_NUMEQUALVERIFY 2";

        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_FALSE, OP_1, OP_1}, bytes {OP_NUMEQUALVERIFY}, flag {}))) << "OP_NUMEQUALVERIFY 3";

        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_TRUE, OP_1, OP_1}, bytes {OP_NUMEQUALVERIFY}, flag {}))) << "OP_NUMEQUALVERIFY 4";

    }

    TEST (Script, NumberOps) {

        test_data_op (OP_0NOTEQUAL, {{}}, {{}}, "OP_0NOTEQUAL 1");
        test_data_op (OP_0NOTEQUAL, {{0x00}}, {{}}, "OP_0NOTEQUAL 2");
        test_data_op (OP_0NOTEQUAL, {{0x80}}, {{}}, "OP_0NOTEQUAL 3");
        test_data_op (OP_0NOTEQUAL, {{0x01}}, {{0x01}}, "OP_0NOTEQUAL 4");
        test_data_op (OP_0NOTEQUAL, {{0x81}}, {{0x01}}, "OP_0NOTEQUAL 5");

        test_data_op (OP_1ADD, {{}}, {{0x01}}, "OP_1ADD");
        test_data_op (OP_1ADD, {{0x00}}, {{0x01}}, "OP_1ADD");
        test_data_op (OP_1ADD, {{0x80}}, {{0x01}}, "OP_1ADD");

        test_data_op (OP_1SUB, {{}}, {{0x81}}, "OP_1SUB");
        test_data_op (OP_1SUB, {{0x01}}, {{}}, "OP_1SUB");

        test_stack_op (OP_2MUL, {0}, {0}, "OP_2MUL");
        test_stack_op (OP_2DIV, {0}, {0}, "OP_2DIV");
        test_stack_op (OP_2MUL, {1}, {2}, "OP_2MUL");
        test_stack_op (OP_2DIV, {1}, {0}, "OP_2DIV");
        test_stack_op (OP_2MUL, {-1}, {-2}, "OP_2MUL");
        test_stack_op (OP_2DIV, {-1}, {0}, "OP_2DIV");
        test_stack_op (OP_2MUL, {2}, {4}, "OP_2MUL");
        test_stack_op (OP_2DIV, {2}, {1}, "OP_2DIV");
        test_stack_op (OP_2MUL, {-2}, {-4}, "OP_2MUL");
        test_stack_op (OP_2DIV, {-2}, {-1}, "OP_2DIV");
        test_stack_op (OP_2MUL, {3}, {6}, "OP_2MUL");
        test_stack_op (OP_2DIV, {3}, {1}, "OP_2DIV");
        test_stack_op (OP_2MUL, {-3}, {-6}, "OP_2MUL");
        test_stack_op (OP_2DIV, {-3}, {-1}, "OP_2DIV");
        test_stack_op (OP_2MUL, {4}, {8}, "OP_2MUL");
        test_stack_op (OP_2DIV, {4}, {2}, "OP_2DIV");
        test_stack_op (OP_2MUL, {-4}, {-8}, "OP_2MUL");
        test_stack_op (OP_2DIV, {-4}, {-2}, "OP_2DIV");

        test_data_op (OP_NEGATE, {{}}, {{}}, "OP_NEGATE");
        test_data_op (OP_NEGATE, {{0x80}}, {{}}, "OP_NEGATE");
        test_data_op (OP_NEGATE, {{0x00}}, {{}}, "OP_NEGATE");
        test_data_op (OP_NEGATE, {{0x01}}, {{0x81}}, "OP_NEGATE");
        test_data_op (OP_NEGATE, {{0x81}}, {{0x01}}, "OP_NEGATE");

        // interesting thing about ABS is that the number is only
        // trimmed to minimal size if it is changed.
        test_data_op (OP_ABS, {{}}, {{}}, "OP_ABS");
        test_data_op (OP_ABS, {{0x00}}, {{0x00}}, "OP_ABS");
        test_data_op (OP_ABS, {{0x01}}, {{0x01}}, "OP_ABS");
        test_data_op (OP_ABS, {{0x81}}, {{0x01}}, "OP_ABS");
        test_data_op (OP_ABS, {{0x01, 0x00}}, {{0x01, 0x00}}, "OP_ABS");
        test_data_op (OP_ABS, {{0x01, 0x80}}, {{0x01}}, "OP_ABS");

        test_stack_op (OP_ADD, {1, 2}, {3}, "OP_ADD");
        test_stack_op (OP_ADD, {1, -2}, {-1}, "OP_ADD");

        test_stack_op (OP_SUB, {1, 2}, {-1}, "OP_SUB");
        test_stack_op (OP_SUB, {1, -2}, {3}, "OP_SUB");

        test_stack_op (OP_MUL, {1, 1}, {1}, "OP_MUL");
        test_stack_op (OP_MUL, {1, 2}, {2}, "OP_MUL");
        test_stack_op (OP_MUL, {1, -1}, {-1}, "OP_MUL");
        test_stack_op (OP_MUL, {2, 2}, {4}, "OP_MUL");

        test_stack_op_error (OP_DIV, {1, 0}, "OP_DIV");
        test_stack_op_error (OP_MOD, {1, 0}, "OP_MOD");

        test_stack_op (OP_DIV, {1, 1}, {1}, "OP_DIV");
        test_stack_op (OP_MOD, {1, 1}, {0}, "OP_MOD");

        test_stack_op (OP_DIV, {19, 5}, {3}, "OP_DIV");
        test_stack_op (OP_MOD, {19, 5}, {4}, "OP_MOD");

    }

    TEST (Script, OP_VER) {
        test_data_op (OP_VER, {}, {{0x01, 0x00, 0x00, 0x00}});

        EXPECT_EQ (Error::OK, (evaluate (list<bytes> {bytes {OP_VER, OP_PUSHSIZE4, 0x02, 0x00, 0x00, 0x00, OP_EQUAL}},
            script_config {2, epoch::chronicle}))) << "OP_VER 1";

        EXPECT_EQ (Error::OK, (evaluate ({bytes {OP_VER, OP_PUSHSIZE4, 0x03, 0x00, 0x00, 0x00, OP_EQUAL}},
            script_config {3, epoch::chronicle}))) << "OP_VER 2";
    }

    TEST (Script, MinimalIf) {
        EXPECT_EQ (Error::OK, (evaluate (bytes {
            OP_2, OP_IF,
            OP_1,
            OP_ENDIF
        }, bytes {}, flag {}))) << "non-minimal IF allowed";

        error (evaluate (bytes {
            OP_2, OP_IF,
            OP_1,
            OP_ENDIF
        }, bytes {}, flag::VERIFY_MINIMALIF), "non-minimal IF condition");

        EXPECT_EQ (Error::OK, (evaluate (bytes {
            OP_PUSHSIZE1, 0x00, OP_NOTIF,
            OP_1,
            OP_ENDIF
        }, bytes {}, flag {}))) << "non-minimal NOTIF allowed";

        error (evaluate (bytes {
            OP_PUSHSIZE1, 0x00, OP_NOTIF,
            OP_1,
            OP_ENDIF
        }, bytes {}, flag::VERIFY_MINIMALIF), "non-minimal NOTIF condition");
    }

    TEST (Script, If) {

        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL, (evaluate (bytes {OP_IF}, bytes {}, {2}))) << "OP_IF";
        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL, (evaluate (bytes {OP_NOTIF}, bytes {}, {2}))) << "OP_NOTIF";
        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL, (evaluate (bytes {OP_VERIF}, bytes {}, {2}))) << "OP_VERIF";
        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL, (evaluate (bytes {OP_VERNOTIF}, bytes {}, {2}))) << "OP_VERNOTIF";
        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL, (evaluate (bytes {OP_ELSE}, bytes {}, {2}))) << "OP_ELSE";
        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL, (evaluate (bytes {OP_ENDIF}, bytes {}, {2}))) << "OP_ENDIF";

        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL, (evaluate (bytes {OP_TRUE, OP_IF}, bytes {}, {2}))) << "OP_IF";
        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL, (evaluate (bytes {OP_TRUE, OP_NOTIF}, bytes {}, {2}))) << "OP_NOTIF";
        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL, (evaluate (bytes {OP_TRUE, OP_VERIF}, bytes {}, {2}))) << "OP_VERIF";
        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL, (evaluate (bytes {OP_TRUE, OP_VERNOTIF}, bytes {}, {2}))) << "OP_VERNOTIF";

        // these fail because the stack is empty at the end of the computation, not because the conditional is ill-formed.
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_TRUE, OP_IF, OP_ENDIF}, bytes {}, {2}))) << "OP_IF";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_TRUE, OP_NOTIF, OP_ENDIF}, bytes {}, {2}))) << "OP_IF";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_TRUE, OP_VERIF, OP_ENDIF}, bytes {}, {2}))) << "OP_IF";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_TRUE, OP_VERNOTIF, OP_ENDIF}, bytes {}, {2}))) << "OP_IF";

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_TRUE, OP_IF, OP_ELSE, OP_ENDIF}, bytes {}, {2}))) << "OP_IF";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_TRUE, OP_NOTIF, OP_ELSE, OP_ENDIF}, bytes {}, {2}))) << "OP_IF";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_TRUE, OP_VERIF, OP_ELSE, OP_ENDIF}, bytes {}, {2}))) << "OP_IF";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_TRUE, OP_VERNOTIF, OP_ELSE, OP_ENDIF}, bytes {}, {2}))) << "OP_IF";

        // two elses in a row not allowed.
        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL,
            (evaluate (bytes {OP_TRUE, OP_IF, OP_ELSE, OP_ELSE, OP_ENDIF}, bytes {}, {2}))) << "OP_IF";
        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL,
            (evaluate (bytes {OP_TRUE, OP_NOTIF, OP_ELSE, OP_ELSE, OP_ENDIF}, bytes {}, {2}))) << "OP_IF";
        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL,
            (evaluate (bytes {OP_TRUE, OP_VERIF, OP_ELSE, OP_ELSE, OP_ENDIF}, bytes {}, {2}))) << "OP_IF";
        EXPECT_EQ (Error::UNBALANCED_CONDITIONAL,
            (evaluate (bytes {OP_TRUE, OP_VERNOTIF, OP_ELSE, OP_ELSE, OP_ENDIF}, bytes {}, {2}))) << "OP_IF";

        EXPECT_EQ (Error::OK, (evaluate (bytes {
            OP_1, OP_IF,
            OP_1,
            OP_ELSE,
            OP_0,
            OP_ENDIF
        }, bytes {}, flag {}))) << "OP_IF: true branch";

        EXPECT_EQ (Error::OK, (evaluate (bytes {
            OP_10, OP_VERIF,
            OP_1,
            OP_ELSE,
            OP_0,
            OP_ENDIF
        }, bytes {}, flag {}))) << "OP_VERIF: true branch";

        EXPECT_EQ (Error::FAIL, (evaluate (bytes {
            OP_0, OP_IF,
            OP_1,
            OP_ELSE,
            OP_0,
            OP_ENDIF
        }, bytes {}, flag {}))) << "OP_IF: false branch";

        EXPECT_EQ (Error::FAIL, (evaluate (bytes {
            OP_0, OP_VERIF,
            OP_1,
            OP_ELSE,
            OP_0,
            OP_ENDIF
        }, bytes {}, flag {}))) << "OP_IF: false branch";

        EXPECT_EQ (Error::FAIL, (evaluate (bytes {
            OP_1, OP_NOTIF,
            OP_1,
            OP_ELSE,
            OP_0,
            OP_ENDIF
        }, bytes {}, flag {}))) << "OP_NOTIF: true branch";

        EXPECT_EQ (Error::FAIL, (evaluate (bytes {
            OP_10, OP_VERNOTIF,
            OP_1,
            OP_ELSE,
            OP_0,
            OP_ENDIF
        }, bytes {}, flag {}))) << "OP_NOTIF: true branch";

        EXPECT_EQ (Error::OK, (evaluate (bytes {
            OP_0, OP_NOTIF,
            OP_1,
            OP_ELSE,
            OP_0,
            OP_ENDIF
        }, bytes {}, flag {}))) << "OP_NOTIF: false branch";

        EXPECT_EQ (Error::OK, (evaluate (bytes {
            OP_0, OP_VERNOTIF,
            OP_1,
            OP_ELSE,
            OP_0,
            OP_ENDIF
        }, bytes {}, flag {}))) << "OP_NOTIF: false branch";

        EXPECT_EQ (Error::OK, (evaluate (bytes {
            OP_1,
            OP_0, OP_IF,
            OP_0,
            OP_ENDIF
        }, bytes {}, flag {}))) << "OP_IF: not executed";

        EXPECT_EQ (Error::OK, (evaluate (bytes {
            OP_1,
            OP_1, OP_NOTIF,
            OP_0,
            OP_ENDIF
        }, bytes {}, flag {}))) << "OP_NOTIF: not executed";

        // Unmatched inside non-executed branch
        error (evaluate (bytes {
            OP_0, OP_IF,
            OP_IF,   // never executed, but still must match
            OP_ENDIF
        }, bytes {}, script_config {}), "unmatched OP_IF in dead branch");

        // Unmatched inside non-executed branch
        error (evaluate (bytes {
            OP_1, OP_NOTIF,
            OP_IF,   // never executed, but still must match
            OP_ENDIF
        }, bytes {}, script_config {}), "unmatched OP_IF in dead branch");

        // test that invalid op codes cannot appear in unevaluated branches.
        error (evaluate (bytes {
            OP_1, OP_IF,
            OP_1,
            OP_ELSE,
            FIRST_UNDEFINED_OP_VALUE,
            OP_ENDIF
        }, bytes {}, flag {}), "invalid op codes cannot appear in unevaluated branches");

    }

    TEST (Script, OP_RETURN) {

        EXPECT_EQ (Error::INVALID_STACK_OPERATION,
                                (evaluate (bytes {}, bytes {OP_RETURN}, {}))) << "OP_RETURN error";
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_TRUE}, bytes {OP_RETURN}, {}))) << "OP_RETURN true";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_FALSE}, bytes {OP_RETURN}, {}))) << "OP_RETURN false";

        // here we show that instructions after OP_RETURN don't get evaluated.
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_TRUE}, bytes {OP_RETURN, OP_FALSE}, {2}))) << "OP_RETURN true";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_FALSE}, bytes {OP_RETURN, OP_TRUE}, {2}))) << "OP_RETURN false";

        // Here we show that OP_RETURN jumps to the unlock script.
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_TRUE, OP_RETURN}, bytes {OP_TRUE}, {2}))) << "OP_RETURN true";
        EXPECT_EQ (Error::FAIL, (evaluate (bytes {OP_TRUE, OP_RETURN}, bytes {OP_FALSE}, {2}))) << "OP_RETURN true";

        // here we show that the if/else stacks are eliminated on OP_RETURN.
        EXPECT_EQ (Error::OK,   (evaluate (bytes {OP_TRUE, OP_TRUE, OP_IF}, bytes {OP_RETURN}, {2}))) << "OP_RETURN true";

    }

/*
    TEST (Script, TestCodeSeparator) {

    }
*/
    
}
