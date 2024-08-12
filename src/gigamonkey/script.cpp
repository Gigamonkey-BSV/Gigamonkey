// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018-2019 Bitcoin Association
// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script.hpp>
#include <gigamonkey/script/bitcoin_core.hpp>
#include <gigamonkey/script/counter.hpp>
#include <gigamonkey/script/stack.hpp>

namespace Gigamonkey::Bitcoin {

    result verify_signature (bytes_view sig, bytes_view pub, const sighash::document &doc, uint32 flags) {

        if (flags & SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE && !secp256k1::pubkey::compressed (pub))
            return SCRIPT_ERR_NONCOMPRESSED_PUBKEY;

        else if (flags & SCRIPT_VERIFY_STRICTENC && !secp256k1::pubkey::valid (pub))
            return SCRIPT_ERR_PUBKEYTYPE;

        auto d = signature::directive (sig);
        auto raw = signature::raw (sig);

        if (!sighash::valid (d)) return SCRIPT_ERR_SIG_HASHTYPE;

        if (sighash::has_fork_id (d) && !(flags & SCRIPT_ENABLE_SIGHASH_FORKID))
            return SCRIPT_ERR_ILLEGAL_FORKID;

        if (!sighash::has_fork_id (d) && (flags & SCRIPT_ENABLE_SIGHASH_FORKID))
            return SCRIPT_ERR_MUST_USE_FORKID;

        if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) && !signature::DER (sig))
            return SCRIPT_ERR_SIG_DER;

        if ((flags & SCRIPT_VERIFY_LOW_S) && !secp256k1::signature::normalized (raw))
            return SCRIPT_ERR_SIG_HIGH_S;

        if (signature::verify (sig, pub, doc)) return true;

        if (flags & SCRIPT_VERIFY_NULLFAIL && sig.size () != 0)
            return SCRIPT_ERR_SIG_NULLFAIL;

        return false;
    }

    bytes_view remove_until_last_code_separator (bytes_view b) {
        program_counter counter {b};
        while (counter.Next.size () > 0) counter = counter.next ();
        return counter.script_code ();
    }
    
    bool redemption_document::check_locktime (const uint32_little &nLockTime) const {
        // There are two kinds of nLockTime: lock-by-blockheight and
        // lock-by-blocktime, distinguished by whether nLockTime <
        // LOCKTIME_THRESHOLD.
        //
        // We want to compare apples to apples, so fail the script unless the type
        // of nLockTime being tested is the same as the nLockTime in the
        // transaction.
        if (!((Transaction.LockTime < LOCKTIME_THRESHOLD &&
            nLockTime < LOCKTIME_THRESHOLD) ||
            (Transaction.LockTime >= LOCKTIME_THRESHOLD &&
            nLockTime >= LOCKTIME_THRESHOLD))) return false;

        // Now that we know we're comparing apples-to-apples, the comparison is a
        // simple numeric one.
        if (nLockTime > int64_t (Transaction.LockTime)) return false;

        // Finally the nLockTime feature can be disabled and thus
        // CHECKLOCKTIMEVERIFY bypassed if every txin has been finalized by setting
        // nSequence to maxint. The transaction would be allowed into the
        // blockchain, making the opcode ineffective.
        //
        // Testing if this vin is not final is sufficient to prevent this condition.
        // Alternatively we could test all inputs, but testing just this input
        // minimizes the data required to prove correct CHECKLOCKTIMEVERIFY
        // execution.
        if (CTxIn::SEQUENCE_FINAL == Transaction.Inputs[InputIndex].Sequence) return false;

        return true;
    }

    bool redemption_document::check_sequence (const uint32_little &nSequence) const {
        // Relative lock times are supported by comparing the passed in operand to
        // the sequence number of the input.
        const int64_t txToSequence = int64_t (Transaction.Inputs[InputIndex].Sequence);

        // Fail if the transaction's version number is not set high enough to
        // trigger BIP 68 rules.
        if (static_cast<uint32_t> (Transaction.Version) < 2) return false;

        // Sequence numbers with their most significant bit set are not consensus
        // constrained. Testing that the transaction's sequence number do not have
        // this bit set prevents using this property to get around a
        // CHECKSEQUENCEVERIFY check.
        if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) return false;

        // Mask off any bits that do not have consensus-enforced meaning before
        // doing the integer comparisons
        const uint32 nLockTimeMask =
            CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
        const int64 txToSequenceMasked = txToSequence & nLockTimeMask;
        const uint32 nSequenceMasked = uint32 (nSequence) & nLockTimeMask;

        // There are two kinds of nSequence: lock-by-blockheight and
        // lock-by-blocktime, distinguished by whether nSequenceMasked <
        // CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
        //
        // We want to compare apples to apples, so fail the script unless the type
        // of nSequenceMasked being tested is the same as the nSequenceMasked in the
        // transaction.
        if (!((txToSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG &&
            nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) ||
            (txToSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG &&
            nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG))) return false;

        // Now that we know we're comparing apples-to-apples, the comparison is a
        // simple numeric one.
        if (nSequenceMasked > txToSequenceMasked) return false;

        return true;
    }
}
