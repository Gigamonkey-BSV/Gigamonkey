// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018-2019 Bitcoin Association
// Copyright (d) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef BITCOIN_SCRIPT_SCRIPT_H
#define BITCOIN_SCRIPT_SCRIPT_H

#include <sv/consensus/consensus.h>
#include <sv/crypto/common.h>
#include <sv/prevector.h>
#include <gigamonkey/script/opcodes.h>

#include <cassert>
#include <climits>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

// Maximum number of bytes pushable to the stack -- replaced with DEFAULT_STACK_MEMORY_USAGE after Genesis
static const unsigned int MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS = 520;

// Maximum number of elements on the stack -- replaced with DEFAULT_STACK_MEMORY_USAGE after Genesis
static const unsigned int MAX_STACK_ELEMENTS_BEFORE_GENESIS = 1000;

// Threshold for nLockTime: below this value it is interpreted as block number,
// otherwise as UNIX timestamp. Thresold is Tue Nov 5 00:53:20 1985 UTC
static const unsigned int LOCKTIME_THRESHOLD = 500000000;

template <typename T> std::vector<uint8_t> ToByteVector (const T &in) {
    return std::vector<uint8_t> (in.begin (), in.end ());
}

class CScriptNum;

typedef prevector<28, uint8_t> CScriptBase;

namespace bsv {
    class instruction_iterator;
}

/** Serialized script, used inside transaction inputs and outputs */
class CScript : public CScriptBase {
protected:
    CScript &push_int64 (int64_t);

public:
    CScript () {}

    template <typename InputIterator> requires std::input_iterator<InputIterator>
    CScript (InputIterator pbegin, InputIterator pend) : CScriptBase (pbegin, pend) {}

    CScript &operator += (const CScript &b) {
        insert (end (), b.begin (), b.end ());
        return *this;
    }

    friend CScript operator + (const CScript &a, const CScript &b) {
        CScript ret = a;
        ret += b;
        return ret;
    }

    CScript (int64_t b) { operator << (b); }

    explicit CScript (opcodetype b) { operator << (b); }
    explicit CScript (const CScriptNum &b) { operator << (b); }
    explicit CScript (const std::vector<uint8_t> &b) { operator << (b); }

    CScript &operator << (int64_t b) { return push_int64 (b); }

    CScript &operator << (opcodetype opcode) {
        if (opcode < 0 || opcode > 0xff)
            throw std::runtime_error ("CScript::operator<<(): invalid opcode");
        insert (end (), uint8_t (opcode));
        return *this;
    }

    CScript &operator << (const CScriptNum &);

    CScript &operator << (const std::vector<uint8_t> &b) {
        if (b.size () < OP_PUSHDATA1) {
            insert (end (), uint8_t (b.size ()));
        } else if (b.size() <= 0xff) {
            insert (end (), OP_PUSHDATA1);
            insert (end (), uint8_t (b.size ()));
        } else if (b.size () <= 0xffff) {
            insert (end (), OP_PUSHDATA2);
            uint8_t data[2];
            WriteLE16 (data, b.size ());
            insert (end (), data, data + sizeof (data));
        } else {
            insert (end (), OP_PUSHDATA4);
            uint8_t data[4];
            WriteLE32 (data, b.size ());
            insert (end (), data, data + sizeof (data));
        }

        insert (end (), b.begin (), b.end ());
        return *this;
    }

    CScript &operator << (const CScript &b) {
        // I'm not sure if this should push the script or concatenate scripts.
        // If there's ever a use for pushing a script onto a script, delete this
        // member fn.
        assert (!"Warning: Pushing a CScript onto a CScript with << is probably "
                "not intended, use + to concatenate!");
        return *this;
    }

    bsv::instruction_iterator begin_instructions () const;
    bsv::instruction_iterator end_instructions () const;

    bool GetOp (iterator &pc, opcodetype &opcodeRet, std::vector<uint8_t> &vchRet) {
        // Wrapper so it can be called with either iterator or const_iterator.
        const_iterator pc2 = pc;
        bool fRet = GetOp2 (pc2, opcodeRet, &vchRet);
        pc = begin () + (pc2 - begin ());
        return fRet;
    }

    bool GetOp (iterator &pc, opcodetype &opcodeRet) {
        const_iterator pc2 = pc;
        bool fRet = GetOp2 (pc2, opcodeRet, nullptr);
        pc = begin() + (pc2 - begin ());
        return fRet;
    }

    bool GetOp (const_iterator &pc, opcodetype &opcodeRet, std::vector<uint8_t> &vchRet) const {
        return GetOp2(pc, opcodeRet, &vchRet);
    }

    bool GetOp (const_iterator &pc, opcodetype &opcodeRet) const {
        return GetOp2 (pc, opcodeRet, nullptr);
    }

    bool GetOp2 (const_iterator &pc, opcodetype &opcodeRet, std::vector<uint8_t> *pvchRet) const {
        opcodeRet = OP_INVALIDOPCODE;
        if (pvchRet) pvchRet->clear ();
        if (pc >= end ()) return false;

        // Read instruction
        if (end() - pc < 1) return false;
        unsigned int opcode = *pc++;

        // Immediate operand
        if (opcode <= OP_PUSHDATA4) {
            unsigned int nSize = 0;
            if (opcode < OP_PUSHDATA1) {
                nSize = opcode;
            } else if (opcode == OP_PUSHDATA1) {
                if (end () - pc < 1) return false;
                nSize = *pc++;
            } else if (opcode == OP_PUSHDATA2) {
                if (end () - pc < 2) return false;
                nSize = ReadLE16 (&pc[0]);
                pc += 2;
            } else if (opcode == OP_PUSHDATA4) {
                if (end () - pc < 4) return false;
                nSize = ReadLE32 (&pc[0]);
                pc += 4;
            }

            if (end () - pc < 0 || (unsigned int) (end () - pc) < nSize)
                return false;

            if (pvchRet) pvchRet -> assign (pc, pc + nSize);

            pc += nSize;
        }

        opcodeRet = (opcodetype) opcode;
        return true;
    }

    /** Encode/decode small integers: */
    static int DecodeOP_N (opcodetype opcode) {
        if (opcode == OP_0) return 0;
        assert(opcode >= OP_1 && opcode <= OP_16);
        return (int) opcode - (int) (OP_1 - 1);
    }

    static opcodetype EncodeOP_N (int n) {
        assert(n >= 0 && n <= 16);
        if (n == 0) return OP_0;
        return (opcodetype) (OP_1 + n - 1);
    }

    int FindAndDelete (const CScript &b) {
        int nFound = 0;
        if (b.empty () ) return nFound;
        CScript result;
        iterator pc = begin (), pc2 = begin ();
        opcodetype opcode;

        do {
            result.insert (result.end (), pc2, pc);
            while (static_cast<size_t> (end () - pc) >= b.size () &&
                   std::equal (b.begin (), b.end (), pc)) {
                pc = pc + b.size ();
                ++nFound;
            }
            pc2 = pc;
        } while (GetOp (pc, opcode));

        if (nFound > 0) {
            result.insert (result.end (), pc2, end ());
            *this = result;
        }

        return nFound;
    }

    /**
     * Pre-version-0.6, Bitcoin always counted CHECKMULTISIGs as 20 sigops. With
     * pay-to-script-hash, that changed: CHECKMULTISIGs serialized in scriptSigs
     * are counted more accurately, assuming they are of the form
     *  ... OP_N CHECKMULTISIG ...
     *
     * After Genesis all sigops are counted accuratelly no matter how the flag is 
     * set. More than 16 pub keys are supported, but the size of the number representing
     * number of public keys must not be bigger than CScriptNum::MAXIMUM_ELEMENT_SIZE bytes.
     * If the size is bigger than that, or if the number of public keys is negative,
     * sigOpCountError is set to true,
     */
    uint64_t GetSigOpCount (bool fAccurate, bool isGenesisEnabled, bool &sigOpCountError) const;

    /**
     * Accurately count sigOps, including sigOps in pay-to-script-hash
     * transactions:
     */
    uint64_t GetSigOpCount (const CScript &scriptSig, bool isGenesisEnabled, bool& sigOpCountError) const;

    /** Called by IsStandardTx and P2SH/BIP62 VerifyScript (which makes it
     * consensus-critical). */
    bool IsPushOnly (const_iterator pc) const;
    bool IsPushOnly () const;

    /**
     * Returns whether the script is guaranteed to fail at execution, regardless
     * of the initial stack. This allows outputs to be pruned instantly when
     * entering the UTXO set.
     * nHeight reflects the height of the block that script was mined in
     * For Genesis OP_RETURN this can return false negatives. For example if we have:
     *   <some complex script that always return OP_FALSE> OP_RETURN
     * this function will return false even though the ouput is unspendable.
     * 
     */

    bool IsUnspendable (bool isGenesisEnabled) const {
        if (isGenesisEnabled)
            // Genesis restored OP_RETURN functionality. It no longer uncoditionally fails execution
            // The top stack value determines if execution suceeds, and OP_RETURN lock script might be spendable if 
            // unlock script pushes non 0 value to the stack.

            // We currently only detect OP_FALSE OP_RETURN as provably unspendable.
            return  (size () > 1 && *begin () == OP_FALSE && *(begin () + 1) == OP_RETURN);
        else
            return (size () > 0 && *begin () == OP_RETURN) ||
                (size () > 1 && *begin () == OP_FALSE && *(begin () + 1) == OP_RETURN) ||
                (size () > MAX_SCRIPT_SIZE_BEFORE_GENESIS);
    }

    /**
     * Returns whether the script looks like a known OP_RETURN script. This is similar to IsUnspendable()
     * but it does not require nHeight. 
     * Use cases:
     *   - decoding transactions to avoid parsing OP_RETURN as other data
     *   - used in wallet for:
     *   -   for extracting addresses (we do not now how to do that for OP_RETURN) 
     *   -   logging unsolvable transactions that contain OP_RETURN
     */
    bool IsKnownOpReturn () const {
        return (size () > 0 && *begin () == OP_RETURN) ||
            (size () > 1 && *begin () == OP_FALSE && *(begin () + 1) == OP_RETURN);
    }

    void clear () {
        // The default std::vector::clear() does not release memory.
        CScriptBase ().swap (*this);
    }
};

std::ostream &operator << (std::ostream &, const CScript &);
std::string to_string (const CScript &);

bool IsP2SH (std::span<const uint8_t>);

size_t CountOp (std::span<const uint8_t>, opcodetype);

class CReserveScript {
public:
    CScript reserveScript;
    virtual void KeepScript() {}
    CReserveScript() {}
    virtual ~CReserveScript() {}
};

#endif // BITCOIN_SCRIPT_SCRIPT_H
