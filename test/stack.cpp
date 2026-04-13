// Copyright (c) 2019-2026 Daniel Krawisz
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <gigamonkey/hash.hpp>
#include <gigamonkey/script/pattern/pay_to_address.hpp>
#include <gigamonkey/script/pattern/pay_to_pubkey.hpp>
#include <gigamonkey/script/pattern/multisig.hpp>
#include <gigamonkey/script/interpreter.hpp>
#include <gigamonkey/address.hpp>
#include <gigamonkey/wif.hpp>
#include <data/encoding/hex.hpp>
#include "gtest/gtest.h"
#include <iostream>

namespace Gigamonkey::Bitcoin {

    // There's an option having to do with malleability which says that the
    // stack has to have one element at the end or else it's an error.
    TEST (Stack, Clean) {

        EXPECT_EQ (Error::OK, (evaluate (bytes {}, bytes {OP_1}, flag::VERIFY_CLEANSTACK))) << "Clean stack A1";
        EXPECT_EQ (Error::OK, (evaluate (bytes {}, bytes {OP_2}, flag::VERIFY_CLEANSTACK))) << "Clean stack A2";
        EXPECT_EQ (Error::OK, (evaluate (bytes {}, bytes {OP_3}, flag::VERIFY_CLEANSTACK))) << "Clean stack A3";

        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_0}, bytes {OP_1}, flag {}))) << "Clean stack B1";
        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_0}, bytes {OP_2}, flag {}))) << "Clean stack B2";
        EXPECT_EQ (Error::OK, (evaluate (bytes {OP_0}, bytes {OP_3}, flag {}))) << "Clean stack B3";

        EXPECT_EQ (Error::CLEANSTACK, (evaluate (bytes {}, bytes {}, flag::VERIFY_CLEANSTACK))) << "Clean stack C0";
        EXPECT_EQ (Error::CLEANSTACK, (evaluate (bytes {OP_0}, bytes {OP_1}, flag::VERIFY_CLEANSTACK))) << "Clean stack C1";
        EXPECT_EQ (Error::CLEANSTACK, (evaluate (bytes {OP_0}, bytes {OP_2}, flag::VERIFY_CLEANSTACK))) << "Clean stack C2";
        EXPECT_EQ (Error::CLEANSTACK, (evaluate (bytes {OP_0}, bytes {OP_3}, flag::VERIFY_CLEANSTACK))) << "Clean stack C3";

    }

    TEST (Stack, Invalid) {

        // ops requiring at least one argument.

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_VERIFY}, bytes {}, flag {}))) << "OP_VERIFY";

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_IFDUP}, bytes {}, flag {}))) << "OP_IFDUP";

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_DROP}, bytes {}, flag {}))) << "OP_DROP";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_DUP}, bytes {}, flag {}))) << "OP_DUP";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_NIP}, bytes {}, flag {}))) << "OP_NIP";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_OVER}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_PICK}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_ROLL}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_ROT}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_SWAP}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_TUCK}, bytes {}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_2DROP}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_2DUP}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_3DUP}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_2OVER}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_2ROT}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_2SWAP}, bytes {}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_CAT}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_SPLIT}, bytes {}, flag {}))) << "OP_SPLIT";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_NUM2BIN}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_BIN2NUM}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_SIZE}, bytes {}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_INVERT}, bytes {}, flag {}))) << "OP_INVERT";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_AND}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_OR}, bytes {}, flag {}))) << "OP_OR";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_XOR}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_EQUAL}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_EQUALVERIFY}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_1ADD}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_1SUB}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_2MUL}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_2DIV}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_NEGATE}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_ABS}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_NOT}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_0NOTEQUAL}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_ADD}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_SUB}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_MUL}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_DIV}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_MOD}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_LSHIFT}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_RSHIFT}, bytes {}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_BOOLAND}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_BOOLOR}, bytes {}, flag {}))) << "OP_BOOLOR";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_NUMEQUAL}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_NUMEQUALVERIFY}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_NUMNOTEQUAL}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_LESSTHAN}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_GREATERTHAN}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_LESSTHANOREQUAL}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_GREATERTHANOREQUAL}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_MIN}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_MAX}, bytes {}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_WITHIN}, bytes {}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_SHA1}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_RIPEMD160}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_SHA256}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_HASH160}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_HASH256}, bytes {}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_CHECKSIG}, bytes {}, flag {}))) << "OP_CHECKSIG";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_CHECKSIGVERIFY}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_CHECKMULTISIG}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_CHECKMULTISIGVERIFY}, bytes {}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_SUBSTR}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_LEFT}, bytes {}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_RIGHT}, bytes {}, flag {})));

        // ops requiring at least 2 arguments.

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_6}, bytes {OP_NIP}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_7}, bytes {OP_OVER}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_10}, bytes {OP_ROT}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_11}, bytes {OP_SWAP}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_12}, bytes {OP_TUCK}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_0}, bytes {OP_2DROP}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_1}, bytes {OP_2DUP}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_2}, bytes {OP_3DUP}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_3}, bytes {OP_2OVER}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_4}, bytes {OP_2ROT}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_5}, bytes {OP_2SWAP}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_8}, bytes {OP_CAT}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_9}, bytes {OP_SPLIT}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_3}, bytes {OP_SUBSTR}, flag {}))) << "OP_SUBSTR 2";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_4}, bytes {OP_LEFT}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_5}, bytes {OP_RIGHT}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_13}, bytes {OP_AND}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_14}, bytes {OP_OR}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_15}, bytes {OP_XOR}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_16}, bytes {OP_EQUAL}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_0}, bytes {OP_EQUALVERIFY}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_1}, bytes {OP_ADD}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_2}, bytes {OP_SUB}, flag {}))) << "OP_SUB 2";

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_3}, bytes {OP_MUL}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_4}, bytes {OP_DIV}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_5}, bytes {OP_MOD}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_6}, bytes {OP_LSHIFT}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_7}, bytes {OP_RSHIFT}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_8}, bytes {OP_BOOLAND}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_9}, bytes {OP_BOOLOR}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_10}, bytes {OP_NUMEQUAL}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_11}, bytes {OP_NUMEQUALVERIFY}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_12}, bytes {OP_NUMNOTEQUAL}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_13}, bytes {OP_LESSTHAN}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_14}, bytes {OP_GREATERTHAN}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_15}, bytes {OP_LESSTHANOREQUAL}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_16}, bytes {OP_GREATERTHANOREQUAL}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_0}, bytes {OP_MIN}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_1}, bytes {OP_MAX}, flag {}))) << "OP_MAX 2";

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_2}, bytes {OP_WITHIN}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_8}, bytes {OP_NUM2BIN}, flag {})));

        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_6}, bytes {OP_CHECKSIG}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_7}, bytes {OP_CHECKSIGVERIFY}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_8}, bytes {OP_CHECKMULTISIG}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_9}, bytes {OP_CHECKMULTISIGVERIFY}, flag {})));

        // taking at least 3 arguments.
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_10, OP_11}, bytes {OP_ROT}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_12, OP_13}, bytes {OP_3DUP}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_14, OP_15}, bytes {OP_2OVER}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_16, OP_0}, bytes {OP_2ROT}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_1, OP_2}, bytes {OP_2SWAP}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_3, OP_4}, bytes {OP_WITHIN}, flag {}))) << "OP_WITHIN 3";
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_6, OP_7}, bytes {OP_SUBSTR}, flag {}))) << "OP_SUBSTR 3";

        // at least 4
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_5, OP_6, OP_7}, bytes {OP_2OVER}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_8, OP_9, OP_10}, bytes {OP_2ROT}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_11, OP_12, OP_13}, bytes {OP_2SWAP}, flag {})));

        // at least 6
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_14, OP_15, OP_16, OP_0}, bytes {OP_2ROT}, flag {})));
        EXPECT_EQ (Error::INVALID_STACK_OPERATION, (evaluate (bytes {OP_1, OP_2, OP_3, OP_4, OP_5}, bytes {OP_2ROT}, flag {})));

    }

}
