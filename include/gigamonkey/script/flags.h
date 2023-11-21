// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2018 The Bitcoin developers
// Copyright (c) 2018-2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_SCRIPT_SCRIPTFLAGS_H
#define BITCOIN_SCRIPT_SCRIPTFLAGS_H

#include <cstdint>

/** Script verification flags */
enum {
    SCRIPT_VERIFY_NONE = 0,

    // Evaluate P2SH subscripts (softfork safe, BIP16).
    SCRIPT_VERIFY_P2SH = (1U << 0),

    // Passing a non-strict-DER signature or one with undefined hashtype to a
    // checksig operation causes script failure. Evaluating a pubkey that is not
    // (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) by checksig causes script
    // failure.
    SCRIPT_VERIFY_STRICTENC = (1U << 1),

    // Passing a non-strict-DER signature to a checksig operation causes script
    // failure (softfork safe, BIP62 rule 1)
    SCRIPT_VERIFY_DERSIG = (1U << 2),

    // Passing a non-strict-DER signature or one with S > order/2 to a checksig
    // operation causes script failure
    // (softfork safe, BIP62 rule 5).
    SCRIPT_VERIFY_LOW_S = (1U << 3),

    // verify dummy stack item consumed by CHECKMULTISIG is of zero-length
    // (softfork safe, BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY = (1U << 4),

    // Using a non-push operator in the scriptSig causes script failure
    // (softfork safe, BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY = (1U << 5),

    // Require minimal encodings for all push operations (OP_0... OP_16,
    // OP_1NEGATE where possible, direct pushes up to 75 bytes, OP_PUSHDATA up
    // to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating any other
    // push causes the script to fail (BIP62 rule 3). In addition, whenever a
    // stack element is interpreted as a number, it must be of minimal length
    // (BIP62 rule 4).
    // (softfork safe)
    SCRIPT_VERIFY_MINIMALDATA = (1U << 6),

    // Discourage use of NOPs reserved for upgrades (NOP1-10)
    //
    // Provided so that nodes can avoid accepting or mining transactions
    // containing executed NOP's whose meaning may change after a soft-fork,
    // thus rendering the script invalid; with this flag set executing
    // discouraged NOPs fails the script. This verification flag will never be a
    // mandatory flag applied to scripts in a block. NOPs that are not executed,
    // e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = (1U << 7),

    // Require that only a single stack element remains after evaluation. This
    // changes the success criterion from "At least one stack element must
    // remain, and when interpreted as a boolean, it must be true" to "Exactly
    // one stack element must remain, and when interpreted as a boolean, it must
    // be true".
    // (softfork safe, BIP62 rule 6)
    // Note: CLEANSTACK should never be used without P2SH or WITNESS.
    SCRIPT_VERIFY_CLEANSTACK = (1U << 8),

    // Verify CHECKLOCKTIMEVERIFY
    //
    // See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = (1U << 9),

    // support CHECKSEQUENCEVERIFY opcode
    //
    // See BIP112 for details
    SCRIPT_VERIFY_CHECKSEQUENCEVERIFY = (1U << 10),

    // Require the argument of OP_IF/NOTIF to be exactly 0x01 or empty vector
    //
    SCRIPT_VERIFY_MINIMALIF = (1U << 13),

    // Signature(s) must be empty vector if an CHECK(MULTI)SIG operation failed
    //
    SCRIPT_VERIFY_NULLFAIL = (1U << 14),

    // Public keys in scripts must be compressed
    //
    SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE = (1U << 15),

    // Do we accept signature using SIGHASH_FORKID
    //
    SCRIPT_ENABLE_SIGHASH_FORKID = (1U << 16),


    // Is Genesis enabled - transcations that is being executed is part of block that uses Geneisis rules.
    //
    SCRIPT_GENESIS = (1U << 18),

    // UTXO being used in this script was created *after* Genesis upgrade
    // has been activated. This activates new rules (such as original meaning of OP_RETURN)
    // This is per (input!) UTXO flag
    SCRIPT_UTXO_AFTER_GENESIS = (1U << 19),

    // Not actual flag. Used for marking largest flag value.
    SCRIPT_FLAG_LAST = (1U << 20)
};

/**
 * Mandatory script verification flags that all new blocks must comply with for
 * them to be valid. (but old blocks may not comply with) Currently just P2SH,
 * but in the future other flags may be added, such as a soft-fork to enforce
 * strict DER encoding.
 *
 * Failing one of these tests may trigger a DoS ban - see CheckInputs() for
 * details.
 */
static const uint32_t MANDATORY_SCRIPT_VERIFY_FLAGS =
    SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC |
    SCRIPT_ENABLE_SIGHASH_FORKID | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_NULLFAIL;

/**
 * Standard script verification flags that standard transactions will comply
 * with. However scripts violating these flags may still be present in valid
 * blocks and we must accept those blocks.
 */
static const unsigned int STANDARD_SCRIPT_VERIFY_FLAGS =
    MANDATORY_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DERSIG |
    SCRIPT_VERIFY_MINIMALDATA | SCRIPT_VERIFY_NULLDUMMY |
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS | SCRIPT_VERIFY_CLEANSTACK |
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;

/** For convenience, standard but not mandatory verify flags. */
static const unsigned int STANDARD_NOT_MANDATORY_VERIFY_FLAGS =
    STANDARD_SCRIPT_VERIFY_FLAGS & ~MANDATORY_SCRIPT_VERIFY_FLAGS;

/** returns flags for "standard" script*/
unsigned int inline StandardScriptVerifyFlags (bool genesisEnabled, bool utxoAfterGenesis) {
    unsigned int scriptFlags = STANDARD_SCRIPT_VERIFY_FLAGS;
    if (utxoAfterGenesis) scriptFlags |= SCRIPT_UTXO_AFTER_GENESIS;

    if (genesisEnabled) {
        scriptFlags |= SCRIPT_GENESIS;
        scriptFlags |= SCRIPT_VERIFY_SIGPUSHONLY;
    }

    return scriptFlags;
}

/** Flags for nSequence and nLockTime locks */
enum {
    /* Interpret sequence numbers as relative lock-time constraints. */
    LOCKTIME_VERIFY_SEQUENCE = (1U << 0),

    /* Use GetMedianTimePast() instead of nTime for end point timestamp. */
    LOCKTIME_MEDIAN_TIME_PAST = (1U << 1),
};

/** Get the flags to use for non-final transaction checks */
unsigned int inline StandardNonFinalVerifyFlags (bool genesisEnabled) {
    unsigned int flags { LOCKTIME_MEDIAN_TIME_PAST };

    if (!genesisEnabled) flags |= LOCKTIME_VERIFY_SEQUENCE;
    return flags;
}

#endif // BITCOIN_SCRIPT_SCRIPTFLAGS_H
