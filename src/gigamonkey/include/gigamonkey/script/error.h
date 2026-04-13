// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019 Bitcoin Association
// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_SCRIPT_SCRIPT_ERROR_H
#define BITCOIN_SCRIPT_SCRIPT_ERROR_H

#include <iosfwd>
#include <data/io/exception.hpp>

// errors that can be returned in script execution or signature verification.
enum class Error {
    OK = 0,
    UNKNOWN_ERROR,
    FAIL,
    OP_RETURN,

    /* Max sizes */
    SCRIPT_SIZE,
    PUSH_SIZE,
    OP_COUNT,
    STACK_SIZE,
    SIG_COUNT,
    PUBKEY_COUNT,

    /* Operands checks */
    INVALID_OPERAND_SIZE,
    INVALID_NUMBER_RANGE,
    IMPOSSIBLE_ENCODING,
    INVALID_SPLIT_RANGE,
    SCRIPTNUM_OVERFLOW,
    SCRIPTNUM_MINENCODE,

    /* Failed verify operations */
    VERIFY,
    EQUALVERIFY,
    CHECKMULTISIGVERIFY,
    CHECKSIGVERIFY,
    NUMEQUALVERIFY,

    /* Logical/Format/Canonical errors */
    BAD_OPCODE,
    DISABLED_OPCODE,
    INVALID_STACK_OPERATION,
    INVALID_ALTSTACK_OPERATION,
    UNBALANCED_CONDITIONAL,

    /* Divisor errors */
    DIV_BY_ZERO,
    MOD_BY_ZERO,

    /* CHECKLOCKTIMEVERIFY and CHECKSEQUENCEVERIFY */
    NEGATIVE_LOCKTIME,
    UNSATISFIED_LOCKTIME,

    /* Malleability */
    SIG_HASHTYPE,
    SIG_DER,
    MINIMALDATA,
    SIG_PUSHONLY,
    SIG_HIGH_S,
    SIG_NULLDUMMY,
    PUBKEYTYPE,
    CLEANSTACK,
    MINIMALIF,
    SIG_NULLFAIL,

    /* softfork safeness */
    DISCOURAGE_UPGRADABLE_NOPS,

    /* misc */
    NONCOMPRESSED_PUBKEY,

    /* anti replay */
    ILLEGAL_FORKID,
    MUST_USE_FORKID,

    BIG_INT,

    // Returned when the script code has binary data
    // that doesn't decompile to a valid script.
    INVALID_SCRIPT_CODE,

    COUNT
};

#define SCRIPT_ERR_LAST SCRIPT_ERR_ERROR_COUNT

const char *ScriptErrorString (const Error error);

std::ostream &operator << (std::ostream &, const Error);

namespace Gigamonkey::Bitcoin {
    struct invalid_program : data::exception {
        ::Error Error;
        invalid_program (::Error err): Error {err} {
            *this << "program is invalid: " << err;
        }
    };
};

#endif // BITCOIN_SCRIPT_SCRIPT_ERROR_H
