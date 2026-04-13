// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019 Bitcoin Association
// Copyright (d) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/error.h>
#include <iostream>

const char *ScriptErrorString (const Error serror) {
    switch (serror) {
        case Error::OK:
            return "No error";
        case Error::FAIL:
            return "Script evaluated without error but finished with a "
                   "false/empty top stack element";
        case Error::VERIFY:
            return "Script failed an OP_VERIFY operation";
        case Error::EQUALVERIFY:
            return "Script failed an OP_EQUALVERIFY operation";
        case Error::CHECKMULTISIGVERIFY:
            return "Script failed an OP_CHECKMULTISIGVERIFY operation";
        case Error::CHECKSIGVERIFY:
            return "Script failed an OP_CHECKSIGVERIFY operation";
        case Error::NUMEQUALVERIFY:
            return "Script failed an OP_NUMEQUALVERIFY operation";
        case Error::SCRIPT_SIZE:
            return "Script is too big";
        case Error::PUSH_SIZE:
            return "Push value size limit exceeded";
        case Error::OP_COUNT:
            return "Operation limit exceeded";
        case Error::STACK_SIZE:
            return "Stack size limit exceeded";
        case Error::SIG_COUNT:
            return "Signature count negative or greater than pubkey count";
        case Error::PUBKEY_COUNT:
            return "Pubkey count negative or limit exceeded";
        case Error::INVALID_OPERAND_SIZE:
            return "Invalid operand size";
        case Error::INVALID_NUMBER_RANGE:
            return "Given operand is not a number within the valid range "
                   "[-2^31...2^31]";
        case Error::IMPOSSIBLE_ENCODING:
            return "The requested encoding is impossible to satisfy";
        case Error::INVALID_SPLIT_RANGE:
            return "Invalid OP_SPLIT range";
        case Error::SCRIPTNUM_OVERFLOW:
            return "Script number overflow";
        case Error::SCRIPTNUM_MINENCODE:
            return "Non-minimally encoded script number";
        case Error::BAD_OPCODE:
            return "Opcode missing or not understood";
        case Error::DISABLED_OPCODE:
            return "Attempted to use a disabled opcode";
        case Error::INVALID_STACK_OPERATION:
            return "Operation not valid with the current stack size";
        case Error::INVALID_ALTSTACK_OPERATION:
            return "Operation not valid with the current altstack size";
        case Error::OP_RETURN:
            return "OP_RETURN was encountered";
        case Error::UNBALANCED_CONDITIONAL:
            return "Invalid OP_IF construction";
        case Error::DIV_BY_ZERO:
            return "Division by zero error";
        case Error::MOD_BY_ZERO:
            return "Modulo by zero error";
        case Error::NEGATIVE_LOCKTIME:
            return "Negative locktime";
        case Error::UNSATISFIED_LOCKTIME:
            return "Locktime requirement not satisfied";
        case Error::SIG_HASHTYPE:
            return "Signature hash type missing or not understood";
        case Error::SIG_DER:
            return "Non-canonical DER signature";
        case Error::MINIMALDATA:
            return "Data push larger than necessary";
        case Error::SIG_PUSHONLY:
            return "Only non-push operators allowed in signatures";
        case Error::SIG_HIGH_S:
            return "Non-canonical signature: S value is unnecessarily high";
        case Error::SIG_NULLDUMMY:
            return "Dummy CHECKMULTISIG argument must be zero";
        case Error::MINIMALIF:
            return "OP_IF/NOTIF argument must be minimal";
        case Error::SIG_NULLFAIL:
            return "Signature must be zero for failed CHECK(MULTI)SIG "
                   "operation";
        case Error::DISCOURAGE_UPGRADABLE_NOPS:
            return "NOPx reserved for soft-fork upgrades";
        case Error::PUBKEYTYPE:
            return "Public key is neither compressed or uncompressed";
        case Error::CLEANSTACK:
            return "Script did not clean its stack";
        case Error::NONCOMPRESSED_PUBKEY:
            return "Using non-compressed public key";
        case Error::ILLEGAL_FORKID:
            return "Illegal use of SIGHASH_FORKID";
        case Error::MUST_USE_FORKID:
            return "Signature must use SIGHASH_FORKID";
        case Error::BIG_INT:
            return "Big integer OpenSSL error";
        case Error::UNKNOWN_ERROR:
        case Error::COUNT:
        default:
            break;
    }
    return "unknown error";
}

std::ostream &operator << (std::ostream &os, const Error e) {
    os << ScriptErrorString (e);
    return os;
}

