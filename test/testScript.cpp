// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/script/pattern/pay_to_address.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/script/interpreter.hpp>
#include <data/crypto/NIST_DRBG.hpp>
#include <data/encoding/hex.hpp>
#include "gtest/gtest.h"
#include <iostream>

namespace Gigamonkey::Bitcoin {

    sighash::document inline add_script_code (const redemption_document &doc, bytes script_code) {
        return sighash::document {doc.Transaction, doc.InputIndex, doc.RedeemedValue, decompile (script_code)};
    }

    void test_program (const bytes &b, bool expected, string explanation = "") {
        if (expected) {
            program p;
            EXPECT_NO_THROW (p = decompile (b)) << explanation;
            EXPECT_EQ (compile (p), b);
        } else {
            EXPECT_THROW (decompile (b), invalid_program) << explanation;
        }
    }

    TEST (ScriptTest, TestProgram) {
        // empty program
        test_program (bytes {}, true);

        // list of ops
        test_program (bytes {OP_FALSE, OP_1NEGATE, OP_1, OP_NOP, OP_TOALTSTACK, OP_DROP,
            OP_EQUALVERIFY, OP_1ADD, OP_CHECKMULTISIGVERIFY, OP_NOP10}, true);

        // invalid op codes
        test_program (bytes {OP_RESERVED}, false, "OP_RESERVED is an invalid op code");
        test_program (bytes {OP_RESERVED1}, false, "OP_RESERVED1 is an invalid op code");
        test_program (bytes {OP_RESERVED2}, false, "OP_RESERVED2 is an invalid op code");
        test_program (bytes {FIRST_UNDEFINED_OP_VALUE}, false, "FIRST_UNDEFINED_OP_VALUE is an invalid op code");
        test_program (bytes {OP_INVALIDOPCODE}, false, "OP_INVALIDOPCODE is an invalid op code");

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

    void success (result r, string explanation = "") {
        EXPECT_TRUE (bool (r)) << explanation;
    }

    void failure (result r, string explanation = "") {
        EXPECT_FALSE (bool (r)) << explanation;
        EXPECT_TRUE (r.valid ()) << explanation << "; " << r.Error;
    }

    void error (result r, string explanation = "") {
        EXPECT_FALSE (bool (r)) << explanation;
        EXPECT_FALSE (r.valid ()) << explanation << "; " << r;
    }

    // There's an option having to do with malleability which says that the
    // stack has to have one element at the end or else it's an error.
    TEST (ScriptTest, TestCleanStack) {
        success (evaluate (bytes {}, bytes {OP_1}, SCRIPT_VERIFY_CLEANSTACK), "Clean stack 1");
        success (evaluate (bytes {}, bytes {OP_2}, SCRIPT_VERIFY_CLEANSTACK), "Clean stack 2");
        success (evaluate (bytes {}, bytes {OP_3}, SCRIPT_VERIFY_CLEANSTACK), "Clean stack 3");

        success (evaluate (bytes {OP_0}, bytes {OP_1}, 0), "Clean stack 1");
        success (evaluate (bytes {OP_0}, bytes {OP_2}, 0), "Clean stack 2");
        success (evaluate (bytes {OP_0}, bytes {OP_3}, 0), "Clean stack 3");

        error (evaluate (bytes {}, bytes {}, SCRIPT_VERIFY_CLEANSTACK), "Clean stack 0");
        error (evaluate (bytes {OP_0}, bytes {OP_1}, SCRIPT_VERIFY_CLEANSTACK), "Clean stack 1");
        error (evaluate (bytes {OP_0}, bytes {OP_2}, SCRIPT_VERIFY_CLEANSTACK), "Clean stack 2");
        error (evaluate (bytes {OP_0}, bytes {OP_3}, SCRIPT_VERIFY_CLEANSTACK), "Clean stack 3");

    }

    TEST (ScriptTest, TestMinimalPush) {

        failure (evaluate (bytes {OP_FALSE}, bytes {}, SCRIPT_VERIFY_MINIMALDATA), "OP_FALSE require minimal");
        failure (evaluate (bytes {OP_FALSE}, bytes {}, 0), "OP_FALSE");

        // other ways of pushing an empty string to the stack.
        error (evaluate (bytes {OP_PUSHDATA1, 0x00}, bytes {}, SCRIPT_VERIFY_MINIMALDATA), "empty push 2");
        error (evaluate (bytes {OP_PUSHDATA2, 0x00, 0x00}, bytes {}, SCRIPT_VERIFY_MINIMALDATA), "empty push 3");
        error (evaluate (bytes {OP_PUSHDATA4, 0x00, 0x00, 0x00, 0x00}, bytes {}, SCRIPT_VERIFY_MINIMALDATA), "empty push 4");

        // but they are all ok when we stop worrying about minimal data.
        failure (evaluate (bytes {OP_PUSHDATA1, 0x00}, bytes {}, 0), "empty push 2");
        failure (evaluate (bytes {OP_PUSHDATA2, 0x00, 0x00}, bytes {}, 0), "empty push 3");
        failure (evaluate (bytes {OP_PUSHDATA4, 0x00, 0x00, 0x00, 0x00}, bytes {}, 0), "empty push 4");

        success (evaluate (bytes {OP_1NEGATE}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        success (evaluate (bytes {OP_1}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        success (evaluate (bytes {OP_16}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));

        success (evaluate (bytes {OP_1NEGATE}, bytes {}, 0));
        success (evaluate (bytes {OP_1}, bytes {}, 0));
        success (evaluate (bytes {OP_16}, bytes {}, 0));

        // Non-minimal ways of pushing -1, 1, and 16
        error (evaluate (bytes {OP_PUSHSIZE1, 0x81}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        error (evaluate (bytes {OP_PUSHSIZE1, 0x01}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        error (evaluate (bytes {OP_PUSHSIZE1, 0x10}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));

        error (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x81}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        error (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x01}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        error (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x10}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));

        error (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x81}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        error (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x01}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        error (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x10}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));

        error (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x81}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        error (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x01}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        error (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x10}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));

        success (evaluate (bytes {OP_PUSHSIZE1, 0x81}, bytes {}, 0));
        success (evaluate (bytes {OP_PUSHSIZE1, 0x01}, bytes {}, 0));
        success (evaluate (bytes {OP_PUSHSIZE1, 0x10}, bytes {}, 0));

        success (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x81}, bytes {}, 0));
        success (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x01}, bytes {}, 0));
        success (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x10}, bytes {}, 0));

        success (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x81}, bytes {}, 0));
        success (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x01}, bytes {}, 0));
        success (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x10}, bytes {}, 0));

        success (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x81}, bytes {}, 0));
        success (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x01}, bytes {}, 0));
        success (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x10}, bytes {}, 0));

        success (evaluate (bytes {OP_PUSHSIZE1, 0x20}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        success (evaluate (bytes {OP_PUSHSIZE1, 0x20}, bytes {}, 0));

        error (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x20}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        success (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x20}, bytes {}, 0));

        error (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x20}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        success (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x20}, bytes {}, 0));

        error (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x20}, bytes {}, SCRIPT_VERIFY_MINIMALDATA));
        success (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x20}, bytes {}, 0));

        // we could have a lot more here but we don't.

    }

    TEST (ScriptTest, TestPush) {
        error (evaluate (bytes {}, bytes {}), "empty script");

        success (evaluate (bytes {OP_TRUE}, bytes {}, 0), "OP_TRUE");
        success (evaluate (bytes {OP_7}, bytes {}, 0), "OP_7");

        success (evaluate (bytes {OP_PUSHSIZE1, 0x01}, bytes {}, 0), "40");
        failure (evaluate (bytes {OP_PUSHSIZE1, 0x00}, bytes {}, 0), "50");
        failure (evaluate (bytes {OP_PUSHSIZE1, 0x80}, bytes {}, 0), "60");
        success (evaluate (bytes {OP_PUSHSIZE2, 0x01, 0x00}, bytes {}, 0), "70");
        success (evaluate (bytes {OP_PUSHSIZE3, 0x01, 0x00, 0x00}, bytes {}, 0), "80");
        failure (evaluate (bytes {OP_PUSHSIZE1, 0x00}, bytes {}, 0), "90");
        failure (evaluate (bytes {OP_PUSHSIZE2, 0x00, 0x00}, bytes {}, 0), "100");
        failure (evaluate (bytes {OP_PUSHSIZE3, 0x00, 0x00, 0x00}, bytes {}), "110");

        error (evaluate (bytes {OP_PUSHSIZE1}, bytes {}, 0), "invalid PUSHSIZE1");
        error (evaluate (bytes {OP_PUSHSIZE2, 0x01}, bytes {}, 0), "invalid PUSHSIZE2");
        error (evaluate (bytes {OP_PUSHSIZE3, 0x01, 0x00}, bytes {}, 0), "invalid PUSHSIZE3");

        failure (evaluate (bytes {OP_PUSHDATA1, 0x00}, bytes {}, 0), "PUSHDATA1 empty push");
        success (evaluate (bytes {OP_PUSHDATA1, 0x01, 0x01}, bytes {}, 0), "160");
        success (evaluate (bytes {OP_PUSHDATA1, 0x02, 0x00, 0x01}, bytes {}, 0), "170");
        success (evaluate (bytes {OP_PUSHDATA1, 0x03, 0x00, 0x00, 0x01}, bytes {}, 0), "180");
        error (evaluate (bytes {OP_PUSHDATA1, 0x01}, bytes {}, 0), "PUSHDATA1 invalid push 1");
        error (evaluate (bytes {OP_PUSHDATA1, 0x02, 0x01}, bytes {}, 0), "PUSHDATA1 invalid push 2");
        error (evaluate (bytes {OP_PUSHDATA1, 0x03, 0x00, 0x01}, bytes {}, 0), "PUSHDATA1 invalid push 3");

        failure (evaluate (bytes {OP_PUSHDATA2, 0x00, 0x00}, bytes {}, 0), "PUSHDATA2 empty push");
        success (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00, 0x01}, bytes {}, 0), "210");
        success (evaluate (bytes {OP_PUSHDATA2, 0x02, 0x00, 0x00, 0x01}, bytes {}, 0), "220");
        success (evaluate (bytes {OP_PUSHDATA2, 0x03, 0x00, 0x00, 0x00, 0x01}, bytes {}, 0), "230");
        error (evaluate (bytes {OP_PUSHDATA2, 0x01, 0x00}, bytes {}, 0), "PUSHDATA2 invalid push");

        failure (evaluate (bytes {OP_PUSHDATA4, 0x00, 0x00, 0x00, 0x00}, bytes {}, 0), "PUSHDATA4 empty push");
        success (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00, 0x01}, bytes {}, 0), "PUSHDATA4 size 1");
        success (evaluate (bytes {OP_PUSHDATA4, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00}, bytes {}, 0), "PUSHDATA4 size 2");
        success (evaluate (bytes {OP_PUSHDATA4, 0x03, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00}, bytes {}, 0), "PUSHDATA4 size 3");

        error (evaluate (bytes {OP_PUSHDATA4, 0x01, 0x00, 0x00, 0x00}, bytes {}, 0), "PUSHDATA4 invalid push");
    }

    TEST (ScriptTest, TestUnlockPushOnly) {

    }

    TEST (ScriptTest, TestInvalidStack) {

        // ops requiring at least one argument.
        error (evaluate (bytes {OP_IF}, bytes {}, 0), "OP_IF");
        error (evaluate (bytes {OP_NOTIF}, bytes {}, 0), "OP_NOTIF");
        error (evaluate (bytes {OP_VERIF}, bytes {}, 0), "OP_VERIF");
        error (evaluate (bytes {OP_VER}, bytes {}, 0), "OP_VER");
        error (evaluate (bytes {OP_VERNOTIF}, bytes {}, 0), "OP_VERNOTIF");
        error (evaluate (bytes {OP_ELSE}, bytes {}, 0), "OP_ELSE");
        error (evaluate (bytes {OP_ENDIF}, bytes {}, 0), "OP_ENDIF");

        error (evaluate (bytes {OP_TOALTSTACK}, bytes {}, 0), "OP_TOALTSTACK");
        error (evaluate (bytes {OP_FROMALTSTACK}, bytes {}, 0), "OP_FROMALTSTACK");

        error (evaluate (bytes {OP_VERIFY}, bytes {}, 0), "OP_VERIFY");

        error (evaluate (bytes {OP_IFDUP}, bytes {}, 0), "OP_IFDUP");

        error (evaluate (bytes {OP_DROP}, bytes {}, 0), "OP_DROP");
        error (evaluate (bytes {OP_DUP}, bytes {}, 0), "OP_DUP");
        error (evaluate (bytes {OP_NIP}, bytes {}, 0), "OP_NIP");
        error (evaluate (bytes {OP_OVER}, bytes {}, 0));
        error (evaluate (bytes {OP_PICK}, bytes {}, 0));
        error (evaluate (bytes {OP_ROLL}, bytes {}, 0));
        error (evaluate (bytes {OP_ROT}, bytes {}, 0));
        error (evaluate (bytes {OP_SWAP}, bytes {}, 0));
        error (evaluate (bytes {OP_TUCK}, bytes {}, 0));

        error (evaluate (bytes {OP_2DROP}, bytes {}, 0));
        error (evaluate (bytes {OP_2DUP}, bytes {}, 0));
        error (evaluate (bytes {OP_3DUP}, bytes {}, 0));
        error (evaluate (bytes {OP_2OVER}, bytes {}, 0));
        error (evaluate (bytes {OP_2ROT}, bytes {}, 0));
        error (evaluate (bytes {OP_2SWAP}, bytes {}, 0));

        error (evaluate (bytes {OP_CAT}, bytes {}, 0));
        error (evaluate (bytes {OP_SPLIT}, bytes {}, 0), "OP_SPLIT");
        error (evaluate (bytes {OP_NUM2BIN}, bytes {}, 0));
        error (evaluate (bytes {OP_BIN2NUM}, bytes {}, 0));
        error (evaluate (bytes {OP_SIZE}, bytes {}, 0));

        error (evaluate (bytes {OP_INVERT}, bytes {}, 0), "OP_INVERT");
        error (evaluate (bytes {OP_AND}, bytes {}, 0));
        error (evaluate (bytes {OP_OR}, bytes {}, 0), "OP_OR");
        error (evaluate (bytes {OP_XOR}, bytes {}, 0));
        error (evaluate (bytes {OP_EQUAL}, bytes {}, 0));
        error (evaluate (bytes {OP_EQUALVERIFY}, bytes {}, 0));
        error (evaluate (bytes {OP_1ADD}, bytes {}, 0));
        error (evaluate (bytes {OP_1SUB}, bytes {}, 0));
        error (evaluate (bytes {OP_2MUL}, bytes {}, 0));
        error (evaluate (bytes {OP_2DIV}, bytes {}, 0));
        error (evaluate (bytes {OP_NEGATE}, bytes {}, 0));
        error (evaluate (bytes {OP_ABS}, bytes {}, 0));
        error (evaluate (bytes {OP_NOT}, bytes {}, 0));
        error (evaluate (bytes {OP_0NOTEQUAL}, bytes {}, 0));
        error (evaluate (bytes {OP_ADD}, bytes {}, 0));
        error (evaluate (bytes {OP_SUB}, bytes {}, 0));
        error (evaluate (bytes {OP_MUL}, bytes {}, 0));
        error (evaluate (bytes {OP_DIV}, bytes {}, 0));
        error (evaluate (bytes {OP_MOD}, bytes {}, 0));
        error (evaluate (bytes {OP_LSHIFT}, bytes {}, 0));
        error (evaluate (bytes {OP_RSHIFT}, bytes {}, 0));

        error (evaluate (bytes {OP_BOOLAND}, bytes {}, 0));
        error (evaluate (bytes {OP_BOOLOR}, bytes {}, 0), "OP_BOOLOR");
        error (evaluate (bytes {OP_NUMEQUAL}, bytes {}, 0));
        error (evaluate (bytes {OP_NUMEQUALVERIFY}, bytes {}, 0));
        error (evaluate (bytes {OP_NUMNOTEQUAL}, bytes {}, 0));
        error (evaluate (bytes {OP_LESSTHAN}, bytes {}, 0));
        error (evaluate (bytes {OP_GREATERTHAN}, bytes {}, 0));
        error (evaluate (bytes {OP_LESSTHANOREQUAL}, bytes {}, 0));
        error (evaluate (bytes {OP_GREATERTHANOREQUAL}, bytes {}, 0));
        error (evaluate (bytes {OP_MIN}, bytes {}, 0));
        error (evaluate (bytes {OP_MAX}, bytes {}, 0));

        error (evaluate (bytes {OP_WITHIN}, bytes {}, 0));

        error (evaluate (bytes {OP_SHA1}, bytes {}, 0));
        error (evaluate (bytes {OP_RIPEMD160}, bytes {}, 0));
        error (evaluate (bytes {OP_SHA256}, bytes {}, 0));
        error (evaluate (bytes {OP_HASH160}, bytes {}, 0));
        error (evaluate (bytes {OP_HASH256}, bytes {}, 0));

        error (evaluate (bytes {OP_CHECKSIG}, bytes {}, 0), "OP_CHECKSIG");
        error (evaluate (bytes {OP_CHECKSIGVERIFY}, bytes {}, 0));
        error (evaluate (bytes {OP_CHECKMULTISIG}, bytes {}, 0));
        error (evaluate (bytes {OP_CHECKMULTISIGVERIFY}, bytes {}, 0));

        //error (evaluate (bytes {OP_SUBSTR}, bytes {}, 0));
        //error (evaluate (bytes {OP_LEFT}, bytes {}, 0));
        //error (evaluate (bytes {OP_RIGHT}, bytes {}, 0));

        // ops requiring at least 2 arguments.

        error (evaluate (bytes {OP_6}, bytes {OP_NIP}, 0));
        error (evaluate (bytes {OP_7}, bytes {OP_OVER}, 0));
        error (evaluate (bytes {OP_10}, bytes {OP_ROT}, 0));
        error (evaluate (bytes {OP_11}, bytes {OP_SWAP}, 0));
        error (evaluate (bytes {OP_12}, bytes {OP_TUCK}, 0));

        error (evaluate (bytes {OP_0}, bytes {OP_2DROP}, 0));
        error (evaluate (bytes {OP_1}, bytes {OP_2DUP}, 0));
        error (evaluate (bytes {OP_2}, bytes {OP_3DUP}, 0));
        error (evaluate (bytes {OP_3}, bytes {OP_2OVER}, 0));
        error (evaluate (bytes {OP_4}, bytes {OP_2ROT}, 0));
        error (evaluate (bytes {OP_5}, bytes {OP_2SWAP}, 0));

        error (evaluate (bytes {OP_8}, bytes {OP_CAT}, 0));
        error (evaluate (bytes {OP_9}, bytes {OP_SPLIT}, 0));

        //error (evaluate (bytes {OP_3}, bytes {OP_SUBSTR}, 0), "OP_SUBSTR 2");
        //error (evaluate (bytes {OP_4}, bytes {OP_LEFT}, 0));
        //error (evaluate (bytes {OP_5}, bytes {OP_RIGHT}, 0));

        error (evaluate (bytes {OP_13}, bytes {OP_AND}, 0));
        error (evaluate (bytes {OP_14}, bytes {OP_OR}, 0));
        error (evaluate (bytes {OP_15}, bytes {OP_XOR}, 0));
        error (evaluate (bytes {OP_16}, bytes {OP_EQUAL}, 0));
        error (evaluate (bytes {OP_0}, bytes {OP_EQUALVERIFY}, 0));
        error (evaluate (bytes {OP_1}, bytes {OP_ADD}, 0));
        error (evaluate (bytes {OP_2}, bytes {OP_SUB}, 0), "OP_SUB 2");

        error (evaluate (bytes {OP_3}, bytes {OP_MUL}, 0));
        error (evaluate (bytes {OP_4}, bytes {OP_DIV}, 0));
        error (evaluate (bytes {OP_5}, bytes {OP_MOD}, 0));
        error (evaluate (bytes {OP_6}, bytes {OP_LSHIFT}, 0));
        error (evaluate (bytes {OP_7}, bytes {OP_RSHIFT}, 0));

        error (evaluate (bytes {OP_8}, bytes {OP_BOOLAND}, 0));
        error (evaluate (bytes {OP_9}, bytes {OP_BOOLOR}, 0));
        error (evaluate (bytes {OP_10}, bytes {OP_NUMEQUAL}, 0));
        error (evaluate (bytes {OP_11}, bytes {OP_NUMEQUALVERIFY}, 0));
        error (evaluate (bytes {OP_12}, bytes {OP_NUMNOTEQUAL}, 0));
        error (evaluate (bytes {OP_13}, bytes {OP_LESSTHAN}, 0));
        error (evaluate (bytes {OP_14}, bytes {OP_GREATERTHAN}, 0));
        error (evaluate (bytes {OP_15}, bytes {OP_LESSTHANOREQUAL}, 0));
        error (evaluate (bytes {OP_16}, bytes {OP_GREATERTHANOREQUAL}, 0));
        error (evaluate (bytes {OP_0}, bytes {OP_MIN}, 0));
        error (evaluate (bytes {OP_1}, bytes {OP_MAX}, 0), "OP_MAX 2");

        error (evaluate (bytes {OP_2}, bytes {OP_WITHIN}, 0));

        error (evaluate (bytes {OP_6}, bytes {OP_CHECKSIG}, 0));
        error (evaluate (bytes {OP_7}, bytes {OP_CHECKSIGVERIFY}, 0));
        error (evaluate (bytes {OP_8}, bytes {OP_CHECKMULTISIG}, 0));
        error (evaluate (bytes {OP_9}, bytes {OP_CHECKMULTISIGVERIFY}, 0));

        // taking at least 3 arguments.
        error (evaluate (bytes {OP_10, OP_11}, bytes {OP_ROT}, 0));
        error (evaluate (bytes {OP_12, OP_13}, bytes {OP_3DUP}, 0));
        error (evaluate (bytes {OP_14, OP_15}, bytes {OP_2OVER}, 0));
        error (evaluate (bytes {OP_16, OP_0}, bytes {OP_2ROT}, 0));
        error (evaluate (bytes {OP_1, OP_2}, bytes {OP_2SWAP}, 0));
        error (evaluate (bytes {OP_3, OP_4}, bytes {OP_WITHIN}, 0), "OP_WITHIN 3");

        // at least 4
        error (evaluate (bytes {OP_5, OP_6, OP_7}, bytes {OP_2OVER}, 0));
        error (evaluate (bytes {OP_8, OP_9, OP_10}, bytes {OP_2ROT}, 0));
        error (evaluate (bytes {OP_11, OP_12, OP_13}, bytes {OP_2SWAP}, 0));

        // at least 6
        error (evaluate (bytes {OP_14, OP_15, OP_16, OP_0}, bytes {OP_2ROT}, 0));
        error (evaluate (bytes {OP_1, OP_2, OP_3, OP_4, OP_5}, bytes {OP_2ROT}, 0));
    }

    TEST (ScriptTest, TestOpcodes) {

        failure (evaluate (bytes {OP_NOP}, bytes {}, 0), "OP_NOP 1");
        success (evaluate (bytes {OP_1, OP_NOP}, bytes {}, 0), "OP_NOP 2");
        failure (evaluate (bytes {OP_0, OP_NOP}, bytes {}, 0), "OP_NOP 3");

        error (evaluate (bytes {OP_FALSE}, bytes {OP_VERIFY}, 0), "OP_VERIFY 1");
        failure (evaluate (bytes {OP_TRUE}, bytes {OP_VERIFY}, 0), "OP_VERIFY 2");

        failure (evaluate (bytes {}, bytes {OP_DEPTH}, 0), "OP DEPTH 1");
        success (evaluate (bytes {OP_FALSE}, bytes {OP_DEPTH}, 0), "OP DEPTH 2");

        // OP_EQUAL
        // OP_EQUALVERIFY

        success (evaluate (bytes {OP_0, OP_SIZE}, bytes {OP_0, OP_EQUAL}, 0));
        success (evaluate (bytes {OP_1, OP_SIZE}, bytes {OP_1, OP_EQUAL}, 0));
        success (evaluate (bytes {OP_16, OP_SIZE}, bytes {OP_1, OP_EQUAL}, 0));
        success (evaluate (bytes {OP_PUSHSIZE3, 0x11, 0x12, 0x13, OP_SIZE}, bytes {OP_3, OP_EQUAL}, 0));
    }
/*
    TEST (ScriptTest, TestAltStack) {
        OP_TOALTSTACK
        OP_FROMALTSTACK
    }*/

    program stack_equal (list<int> stack) {
        list<instruction> test_program;
        for (const int &b : reverse (stack)) {
            test_program <<= push_data (b);
            test_program <<= OP_EQUALVERIFY;
        }

        test_program <<= OP_DEPTH;
        test_program <<= OP_0;
        test_program <<= OP_EQUAL;

        return test_program;
    }

    // if the redemption document is not provided, all signature operations will succeed.
    result inline evaluate_step (const script &unlock, const script &lock, const script_config &conf) {
        interpreter i (unlock, lock, conf);
        step_through (i);
        return false;
    }

    program stack_initialize (list<int> stack) {
        list<instruction> test_program;
        for (const int &b : stack) test_program <<= push_data (b);
        return test_program;
    }

    void test_pick_roll_error (list<int> start, string explanation) {
        error (evaluate (compile (stack_initialize (start)), bytes {OP_PICK}, 0), explanation);
        error (evaluate (compile (stack_initialize (start)), bytes {OP_ROLL}, 0), explanation);
    }

    void test_pick_roll (list<int> start, list<int> expected_roll, list<int> expected_pick, string explanation) {
        success (evaluate (compile (stack_initialize (start) << OP_PICK), compile (stack_equal (expected_pick)), 0), explanation);
        success (evaluate (compile (stack_initialize (start) << OP_ROLL), compile (stack_equal (expected_roll)), 0), explanation);
    }

    TEST (ScriptTest, TestPickRoll) {

        test_pick_roll_error ({0}, "error 0");
        test_pick_roll_error ({9, 1}, "error 1");
        test_pick_roll_error ({12, 9, 2}, "error 2");
        test_pick_roll_error ({34, 12, 9, 3}, "error 3");

        test_pick_roll ({12, 0}, {12}, {12, 12}, "success 0");
        test_pick_roll ({34, 12, 1}, {12, 34}, {34, 12, 34}, "success 1");
        test_pick_roll ({17, 34, 12, 2}, {34, 12, 17}, {17, 34, 12, 17}, "success 2");

    }
/*
    TEST (ScriptTest, TestStackOps) {

        OP_DROP
        OP_DUP
        OP_NIP
        OP_OVER
        OP_ROT
        OP_SWAP
        OP_TUCK

        OP_2DROP
        OP_2DUP
        OP_3DUP
        OP_2OVER
        OP_2ROT
        OP_2SWAP

    }

    TEST (ScriptTest, TestStringOps) {

        OP_CAT
        OP_SPLIT
        OP_SUBSTR
        OP_LEFT
        OP_RIGHT

    }

    TEST (ScriptTest, TestBitOps) {

        OP_INVERT
        OP_AND
        OP_OR
        OP_XOR
    }

    TEST (ScriptTest, TestBoolOps) {

        OP_NOT
        OP_BOOLAND
        OP_BOOLOR
    }

    TEST (ScriptTest, TestHashOps) {

        OP_RIPEMD160
        OP_SHA1
        OP_SHA256
        OP_HASH160
        OP_HASH256
    }

    TEST (ScriptTest, TestNumberOps) {

        OP_1ADD = 0x8b,
        OP_1SUB = 0x8c,
        OP_2MUL = 0x8d,
        OP_2DIV = 0x8e,
        OP_NEGATE = 0x8f,
        OP_ABS = 0x90,
        OP_0NOTEQUAL = 0x92,

        OP_ADD = 0x93,
        OP_SUB = 0x94,
        OP_MUL
        OP_DIV = 0x96,
        OP_MOD = 0x97,

        OP_NUMEQUAL = 0x9c,
        OP_NUMEQUALVERIFY = 0x9d,
        OP_NUMNOTEQUAL
        OP_LESSTHAN = 0x9f,
        OP_GREATERTHAN = 0xa0,
        OP_LESSTHANOREQUAL = 0xa1,
        OP_GREATERTHANOREQUAL = 0xa2,
        OP_MIN = 0xa3,
        OP_MAX

        OP_WITHIN = 0xa5,
    }

    TEST (ScriptTest, TestBitShift) {
        OP_LSHIFT
        OP_RSHIFT
    }

    TEST (ScriptTest, TestBin2Num2Bin) {
        OP_NUM2BIN = 0x80, // after monolith upgrade (May 2018)
        OP_BIN2NUM = 0x81, // after monolith upgrade (May 2018)
    }

    TEST (ScriptTest, TestOP_VER) {

    }

    TEST (ScriptTest, TestChecksig) {

    }

    TEST (ScriptTest, TestCodeSeparator) {

    }

    TEST (ScriptTest, TestReturn) {
        OP_RETURN
    }

    TEST (ScriptTest, TestControlOps) {
        OP_VER
        OP_IF
        OP_NOTIF
        OP_VERIF
        OP_VERNOTIF
        OP_ELSE
        OP_ENDIF
        OP_IFDUP
    }*/
    
    bytes multisig_script (
        const redemption_document &doc,
        list<secp256k1::secret> s,
        list<secp256k1::pubkey> p,
        const instruction &null_push) {
        program mp;
        mp <<= push_data (s.size ());
        for (const secp256k1::pubkey &pk : p) mp <<= push_data (pk);
        mp <<= push_data (p.size ());
        mp <<= OP_CHECKMULTISIGVERIFY;
        
        sighash::document sd = add_script_code (doc, compile (mp));
        
        program ms;
        ms <<= null_push;
        for (const secp256k1::secret &sk : s) ms <<= push_data (signature::sign (sk, sighash::all, sd));
        ms <<= OP_CODESEPARATOR;
        return compile (ms + mp);
    }
    
    bytes multisig_script (const redemption_document &doc, list<secp256k1::secret> s, list<secp256k1::pubkey> p) {
        return multisig_script (doc, s, p, OP_0);
    }
    
    TEST (SignatureTest, TestMultisig) {
        incomplete::transaction tx {
            {incomplete::input {
                outpoint {
                    digest256 {uint256 {"0xaa00000000000000000000000000000000000000000000555555550707070707"}}, 0xcdcdcdcd},
                    0xfedcba09}}, {
                output {1, pay_to_address::script (digest160 {uint160 {"0xbb00000000000000000000000000006565656575"}})},
                output {2, pay_to_address::script (digest160 {uint160 {"0xcc00000000000000000000000000002929292985"}})}},
            5};

        redemption_document doc {tx, 0, satoshi {0xfeee}};
        
        auto k1 = secp256k1::secret (uint256 {123456});
        auto k2 = secp256k1::secret (uint256 {789012});
        auto k3 = secp256k1::secret (uint256 {345678});
        
        auto p1 = k1.to_public ();
        auto p2 = k2.to_public ();
        auto p3 = k3.to_public ();
        
        struct multisig_test {
            int Number;
            bool Expected;
            redemption_document Doc;
            bytes Test;
            
            result run () {
                return evaluate ({}, Test, Doc, 0);
            }
            
            void test () {
                result r = run ();
                EXPECT_EQ (bool (r), Expected) << Number << ": script " << decompile (Test) << " expect " << Expected << "; results in " << r;
            }
            
            multisig_test (int num, bool ex, const redemption_document &doc, list<secp256k1::secret> s, list<secp256k1::pubkey> p) :
                Number {num}, Expected {ex}, Doc {doc}, Test {multisig_script (doc, s, p)} {}
        };
        
        multisig_test {10,  true,  doc, {},           {}          }.test ();
        multisig_test {20,  false, doc, {k1},         {}          }.test ();
        multisig_test {30,  true,  doc, {},           {p1}        }.test ();
        multisig_test {40,  true,  doc, {k1},         {p1}        }.test ();
        multisig_test {50,  false, doc, {k2},         {p1}        }.test ();
        multisig_test {60,  true,  doc, {},           {p1, p2}    }.test ();
        multisig_test {70,  true,  doc, {k1},         {p1, p2}    }.test ();
        multisig_test {80,  false, doc, {k3},         {p1, p2}    }.test ();
        multisig_test {90,  true,  doc, {k1, k2},     {p1, p2}    }.test ();
        multisig_test {100, false, doc, {k2, k1},     {p1, p2}    }.test ();
        multisig_test {110, false, doc, {k1, k3},     {p1, p2}    }.test ();
        multisig_test {120, false, doc, {k2, k3},     {p1, p2}    }.test ();
        multisig_test {130, true,  doc, {},           {p1, p2, p3}}.test ();
        multisig_test {140, true,  doc, {k1},         {p1, p2, p3}}.test ();
        multisig_test {150, true,  doc, {k2},         {p1, p2, p3}}.test ();
        multisig_test {160, true,  doc, {k3},         {p1, p2, p3}}.test ();
        multisig_test {170, true,  doc, {k1, k3},     {p1, p2, p3}}.test ();
        multisig_test {180, false, doc, {k3, k1},     {p1, p2, p3}}.test ();
        multisig_test {190, true,  doc, {k1, k2, k3}, {p1, p2, p3}}.test ();
        multisig_test {200, false, doc, {k3, k2, k1}, {p1, p2, p3}}.test ();
        multisig_test {210, false, doc, {k2, k3, k1}, {p1, p2, p3}}.test ();
        
        // TODO test that not adding the prefix fails
        // TODO test that adding a different prefix fails for the right flags. 
        // TODO test that signatures that fail should be null for certain flags. 
        
    }
    
}
