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

        success (evaluate (bytes {}, bytes {OP_TRUE}, 0));
        success (evaluate (bytes {}, bytes {OP_TRUE}, SCRIPT_VERIFY_SIGPUSHONLY));

        success (evaluate (bytes {OP_TRUE}, bytes {}, 0));
        success (evaluate (bytes {OP_TRUE}, bytes {}, SCRIPT_VERIFY_SIGPUSHONLY));

        success (evaluate (bytes {OP_0, OP_0, OP_EQUAL}, bytes {}, 0));
        error (evaluate (bytes {OP_0, OP_0, OP_EQUAL}, bytes {}, SCRIPT_VERIFY_SIGPUSHONLY));

        success (evaluate (bytes {OP_0, OP_0}, bytes {OP_EQUAL}, 0));
        success (evaluate (bytes {OP_0, OP_0}, bytes {OP_EQUAL}, SCRIPT_VERIFY_SIGPUSHONLY));

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
        error (evaluate (bytes {OP_8}, bytes {OP_NUM2BIN}, 0));

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
        //error (evaluate (bytes {OP_6, OP_7}, bytes {OP_SUBSTR}, 0), "OP_SUBSTR 3");

        // at least 4
        error (evaluate (bytes {OP_5, OP_6, OP_7}, bytes {OP_2OVER}, 0));
        error (evaluate (bytes {OP_8, OP_9, OP_10}, bytes {OP_2ROT}, 0));
        error (evaluate (bytes {OP_11, OP_12, OP_13}, bytes {OP_2SWAP}, 0));

        // at least 6
        error (evaluate (bytes {OP_14, OP_15, OP_16, OP_0}, bytes {OP_2ROT}, 0));
        error (evaluate (bytes {OP_1, OP_2, OP_3, OP_4, OP_5}, bytes {OP_2ROT}, 0));

    }

    TEST (ScriptTest, TestOpcodes) {

        // OP_NOP
        failure (evaluate (bytes {OP_NOP}, bytes {}, 0), "OP_NOP 1");
        success (evaluate (bytes {OP_1, OP_NOP}, bytes {}, 0), "OP_NOP 2");
        failure (evaluate (bytes {OP_0, OP_NOP}, bytes {}, 0), "OP_NOP 3");

        // OP_VERIFY
        error (evaluate (bytes {OP_FALSE}, bytes {OP_VERIFY}, 0), "OP_VERIFY 1");
        failure (evaluate (bytes {OP_TRUE}, bytes {OP_VERIFY}, 0), "OP_VERIFY 2");

        // OP_DEPTH
        failure (evaluate (bytes {}, bytes {OP_DEPTH}, 0), "OP DEPTH 1");
        success (evaluate (bytes {OP_FALSE}, bytes {OP_DEPTH}, 0), "OP DEPTH 2");

        // OP_EQUAL
        success (evaluate (bytes {OP_FALSE, OP_FALSE}, bytes {OP_EQUAL}), "EQUAL 1");
        failure (evaluate (bytes {OP_FALSE, OP_PUSHSIZE1, 0x00}, bytes {OP_EQUAL}, 0), "EQUAL 2");

        // OP_EQUALVERIFY
        failure (evaluate (bytes {OP_FALSE, OP_FALSE}, bytes {OP_EQUALVERIFY}, 0), "EQUALVERIFY 1");
        error (evaluate (bytes {OP_FALSE, OP_TRUE}, bytes {OP_EQUALVERIFY}, 0), "EQUALVERIFY 2");
        success (evaluate (bytes {OP_FALSE, OP_FALSE}, bytes {OP_EQUALVERIFY, OP_1}, SCRIPT_VERIFY_CLEANSTACK), "EQUALVERIFY 3");

        // OP_SIZE
        success (evaluate (bytes {OP_0, OP_SIZE}, bytes {OP_0, OP_EQUAL}, 0));
        success (evaluate (bytes {OP_1, OP_SIZE}, bytes {OP_1, OP_EQUAL}, 0));
        success (evaluate (bytes {OP_16, OP_SIZE}, bytes {OP_1, OP_EQUAL}, 0));
        success (evaluate (bytes {OP_PUSHSIZE3, 0x11, 0x12, 0x13, OP_SIZE}, bytes {OP_3, OP_EQUAL}, 0));

    }

    TEST (ScriptTest, TestAltStack) {
        // OP_TOALTSTACK
        failure (evaluate (bytes {OP_1}, bytes {OP_TOALTSTACK}, 0), "alt stack 1");
        // OP_FROMALTSTACK
        success (evaluate (bytes {OP_1}, bytes {OP_TOALTSTACK, OP_FROMALTSTACK}, 0), "alt stack 2");
    }

    template <typename X>
    program stack_equal (list<X> stack) {
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
    program stack_initialize (list<X> stack) {
        list<instruction> test_program;
        for (const X &b : stack) test_program <<= push_data (b);
        return test_program;
    }

    template <typename X>
    void test_op_error (op Op, list<X> start, string explanation) {
        error (evaluate (compile (stack_initialize<X> (start)), bytes {Op}, 0), explanation);
    }

    template <typename X>
    void test_op (op Op, list<X> start, list<X> expected, string explanation = "") {
        success (evaluate (compile (stack_initialize<X> (start) << Op), compile (stack_equal<X> (expected)), 0), explanation);
    }

    void test_pick_roll_error (list<int> start, string explanation) {
        test_op_error<int> (OP_PICK, start, explanation);
        test_op_error<int> (OP_ROLL, start, explanation);
    }

    void test_pick_roll (list<int> start, list<int> expected_roll, list<int> expected_pick, string explanation) {
        test_op<int> (OP_PICK, start, expected_pick, explanation);
        test_op<int> (OP_ROLL, start, expected_roll, explanation);
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

    auto test_stack_op_error = &test_op<int>;

    auto test_stack_op = &test_op<int>;

    TEST (ScriptTest, TestStackOps) {

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

    void test_hash_op (op Op, bytes_view input, bytes_view result, bool expected = true) {
        if (expected) success (evaluate (compile (push_data (input)), compile (program {Op, push_data (result), OP_EQUAL}), 0));
        else failure (evaluate (compile (push_data (input)), compile (program {Op, push_data (result), OP_EQUAL}), 0));
    }

    TEST (ScriptTest, TestHashOps) {

        test_hash_op (OP_SHA1, bytes {}, *encoding::hex::read ("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        test_hash_op (OP_SHA256, bytes {}, *encoding::hex::read ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));

        test_hash_op (OP_RIPEMD160, bytes {}, *encoding::hex::read ("9c1185a5c5e9fc54612808977ee8f548b2258d31"));

        test_hash_op (OP_HASH160, bytes {}, crypto::RIPEMD_160 (crypto::SHA2_256 (bytes {})));
        test_hash_op (OP_HASH256, bytes {}, crypto::SHA2_256 (crypto::SHA2_256 (bytes {})));

    }

    void test_data_op_error (op Op, list<bytes> start, string explanation = "") {
        test_op_error (Op, start, explanation);
    }

    void test_data_op (op Op, list<bytes> start, list<bytes> expected, string explanation = "") {
        test_op (Op, start, expected, explanation);
    }

    TEST (ScriptTest, TestBoolOps) {

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

    TEST (ScriptTest, TestBitOps) {

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

    TEST (ScriptTest, TestStringOps) {

        test_data_op (OP_CAT, {{}, {}}, {{}});
        test_data_op (OP_CAT, {{0x78}, {}}, {{0x78}});
        test_data_op (OP_CAT, {{}, {0x78}}, {{0x78}});
        test_data_op (OP_CAT, {{0xab}, {0xcd}}, {{0xab, 0xcd}});

        test_data_op_error (OP_SPLIT, {{0xab, 0xcd}, {0x81}});
        test_data_op (OP_SPLIT, {{0xab, 0xcd}, {}}, {{}, {0xab, 0xcd}});
        test_data_op (OP_SPLIT, {{0xab, 0xcd}, {0x01}}, {{0xab}, {0xcd}});
        test_data_op (OP_SPLIT, {{0xab, 0xcd}, {0x02}}, {{0xab, 0xcd}, {}});
        test_data_op_error (OP_SPLIT, {{0xab, 0xcd}, {0x03}});
/*
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

        // TODO
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
        */

    }

    TEST (ScriptTest, TestBitShift) {

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

        // TODO

    }

    TEST (ScriptTest, TestBin2Num2Bin) {

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
/*
    TEST (ScriptTest, TestNumberEqual) {

        test_data_op (OP_NUMEQUAL);
        test_data_op (OP_NUMEQUALVERIFY);
        test_data_op (OP_NUMNOTEQUAL);

    }

    TEST (ScriptTest, TestNumberCompare) {

        test_data_op (OP_NUMEQUAL);
        test_data_op (OP_NUMEQUALVERIFY);
        test_data_op (OP_NUMNOTEQUAL);

    }

    TEST (ScriptTest, TestNumberOps) {

        test_data_op (OP_1ADD);
        test_data_op (OP_1SUB);
        test_data_op (OP_2MUL);
        test_data_op (OP_2DIV);
        test_data_op (OP_NEGATE);
        test_data_op (OP_ABS);
        test_data_op (OP_0NOTEQUAL);

        test_data_op (OP_ADD);
        test_data_op (OP_SUB);
        test_data_op (OP_MUL);
        test_data_op (OP_DIV);
        test_data_op (OP_MOD);

        test_data_op (OP_LESSTHAN);
        test_data_op (OP_GREATERTHAN);
        test_data_op (OP_LESSTHANOREQUAL);
        test_data_op (OP_GREATERTHANOREQUAL);
        test_data_op (OP_MIN);
        test_data_op (OP_MAX);

        test_data_op (OP_WITHIN);

    }*/
/*
    TEST (ScriptTest, TestSignatureNULLFAIL) {
        // TODO
    }

    TEST (ScriptTest, TestSignatureCompressedPubkey) {
        // TODO
    }

    // TODO

    TEST (ScriptTest, TestChecksig) {

    }

    TEST (ScriptTest, TestCodeSeparator) {

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
/*
    TEST (ScriptTest, TestOP_VER) {
        OP_VER
    }

    TEST (ScriptTest, TestReturn) {
        OP_RETURN
    }

    TEST (ScriptTest, TestControlOps) {

        OP_IF
        OP_NOTIF
        OP_VERIF
        OP_VERNOTIF
        OP_ELSE
        OP_ENDIF

    }*/
    
}
