// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018-2019 Bitcoin Association
// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/pattern.hpp>
#include <data/math/number/bytes/N.hpp>
#include <sv/script/script.h>
#include <gigamonkey/script/bitcoin_core.hpp>

namespace Gigamonkey::Bitcoin::interpreter {
    
    bool provably_prunable_recurse(program p) {
        if (p.size() < 2) return false;
        if (p.size() == 2) return p.first().Op == OP_FALSE && p.rest().first() == OP_RETURN;
        return provably_prunable_recurse(p);
    }
    
    bool provably_prunable(program p) {
        if (!p.valid()) return false;
        return provably_prunable_recurse(p);
    }
    
    bool push::match(const instruction& i) const {
        switch (Type) {
            case any : 
                return is_push(i.Op);
            case value : 
                return is_push(i.Op) && Value == Z{bytes_view(i.data())};
            case data : 
                return is_push(i.Op) && Data == i.data();
            case read : 
                if (!is_push(i.Op)) return false;
                Read = i.data();
                return true;
            default: 
                return false;
        }
    }
    
    bool push_size::match(const instruction& i) const {
        bytes Data = i.data();
        if (Data.size() != Size) return false;
        if (Reader) Read = Data;
        return true;
    }
    
    bytes_view pattern::sequence::scan(bytes_view p) const {
        list<ptr<pattern>> patt = Patterns;
        while (!data::empty(patt)) {
            p = patt.first()->scan(p);
            patt = patt.rest();
        }
        return p;
    }
        
    bytes_view optional::scan(bytes_view p) const {
        try {
            return pattern::Pattern->scan(p);
        } catch (fail) {
            return p;
        }
    }
    
    bytes_view repeated::scan(bytes_view p) const {
        ptr<pattern> patt = pattern::Pattern;
        uint32 min = Second == -1 && Directive == or_less ? 0 : First;
        int64 max = Second != -1 ? Second : Directive == or_more ? -1 : First;
        uint32 matches = 0;
        while (true) {
            try {
                p = patt->scan(p);
                matches++;
                if (matches == max) return p;
            } catch (fail) {
                if (matches < min) throw fail{};
                return p;
            }
        }
    }
    
    bytes_view alternatives::scan(bytes_view b) const {
        list<ptr<pattern>> patt = Patterns;
        while (!data::empty(patt)) {
            try {
                return patt.first()->scan(b);
            } catch (fail) {
                patt = patt.rest();
            }
        }
        throw fail{};
    };

}

namespace Gigamonkey::Bitcoin {
    
    bool redemption_document::check_locktime(const CScriptNum &nLockTime) const {
        // There are two kinds of nLockTime: lock-by-blockheight and
        // lock-by-blocktime, distinguished by whether nLockTime <
        // LOCKTIME_THRESHOLD.
        //
        // We want to compare apples to apples, so fail the script unless the type
        // of nLockTime being tested is the same as the nLockTime in the
        // transaction.
        if (!((Transaction.Locktime < LOCKTIME_THRESHOLD &&
            nLockTime < LOCKTIME_THRESHOLD) ||
            (Transaction.Locktime >= LOCKTIME_THRESHOLD &&
            nLockTime >= LOCKTIME_THRESHOLD))) {
            return false;
        }

        // Now that we know we're comparing apples-to-apples, the comparison is a
        // simple numeric one.
        if (nLockTime > int64_t(Transaction.Locktime)) {
            return false;
        }

        // Finally the nLockTime feature can be disabled and thus
        // CHECKLOCKTIMEVERIFY bypassed if every txin has been finalized by setting
        // nSequence to maxint. The transaction would be allowed into the
        // blockchain, making the opcode ineffective.
        //
        // Testing if this vin is not final is sufficient to prevent this condition.
        // Alternatively we could test all inputs, but testing just this input
        // minimizes the data required to prove correct CHECKLOCKTIMEVERIFY
        // execution.
        if (CTxIn::SEQUENCE_FINAL == Transaction.Inputs[InputIndex].Sequence) {
            return false;
        }

        return true;
    }

    bool redemption_document::check_sequence(const CScriptNum &nSequence) const {
        // Relative lock times are supported by comparing the passed in operand to
        // the sequence number of the input.
        const int64_t txToSequence = int64_t(Transaction.Inputs[InputIndex].Sequence);

        // Fail if the transaction's version number is not set high enough to
        // trigger BIP 68 rules.
        if (static_cast<uint32_t>(Transaction.Version) < 2) {
            return false;
        }

        // Sequence numbers with their most significant bit set are not consensus
        // constrained. Testing that the transaction's sequence number do not have
        // this bit set prevents using this property to get around a
        // CHECKSEQUENCEVERIFY check.
        if (txToSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            return false;
        }

        // Mask off any bits that do not have consensus-enforced meaning before
        // doing the integer comparisons
        const uint32_t nLockTimeMask =
            CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG | CTxIn::SEQUENCE_LOCKTIME_MASK;
        const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;
        const CScriptNum nSequenceMasked = nSequence & nLockTimeMask;

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
            nSequenceMasked >= CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG))) {
            return false;
        }

        // Now that we know we're comparing apples-to-apples, the comparison is a
        // simple numeric one.
        if (nSequenceMasked > txToSequenceMasked) {
            return false;
        }

        return true;
    }
}
