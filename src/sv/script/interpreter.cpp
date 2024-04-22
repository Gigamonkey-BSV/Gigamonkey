// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2018-2019 Bitcoin Association
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <sv/script/interpreter.h>
#include <gigamonkey/script/flags.h>
#include <gigamonkey/signature.hpp>
#include <gigamonkey/script/config.hpp>
#include <sv/script/script.h>
#include <sv/script/script_num.h>
#include <sv/uint256.h>
#include <sv/consensus/consensus.h>

namespace Satoshi {

namespace {

bool inline set_success (ScriptError *ret) {
    if (ret) *ret = SCRIPT_ERR_OK;
    return true;
}

bool inline set_error (ScriptError *ret, const ScriptError serror) {
    if (ret) *ret = serror;
    return false;
}

constexpr auto bits_per_byte {8};

} // namespace

bool CastToBool (const valtype &vch) {
    for (size_t i = 0; i < vch.size (); i++) {
        if (vch[i] != 0) {
            // Can be negative zero
            if (i == vch.size () - 1 && vch[i] == 0x80) {
                return false;
            }
            return true;
        }
    }
    return false;
}

static bool IsInvalidBranchingOpcode (opcodetype opcode) {
    return opcode == OP_VERNOTIF || opcode == OP_VERIF;
}

data::maybe<bool> EvalScript (
    const script_config &config,
    bool consensus,
    LimitedStack &stack,
    const CScript &script,
    uint32_t flags,
    LimitedStack &altstack,
    long &ipc,
    data::cross<bool> &vfExec,
    data::cross<bool> &vfElse,
    ScriptError *serror) {

    static const CScriptNum bnZero (0);
    static const CScriptNum bnOne (1);
    static const valtype vchFalse (0);
    static const valtype vchTrue ({1});
    
    CScript::const_iterator pc = script.begin ();
    CScript::const_iterator pend = script.end ();
    CScript::const_iterator pbegincodehash = script.begin ();
    opcodetype opcode;
    valtype vchPushValue;
    
    set_error (serror, SCRIPT_ERR_UNKNOWN_ERROR);
    
    const bool utxo_after_genesis {(flags & SCRIPT_UTXO_AFTER_GENESIS) != 0};
    const uint64_t maxScriptNumLength = config.GetMaxScriptNumLength (utxo_after_genesis, consensus);
    
    if(script.size () > config.GetMaxScriptSize (utxo_after_genesis, consensus))
        return set_error (serror, SCRIPT_ERR_SCRIPT_SIZE);
    
    const bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;
    
    // if OP_RETURN is found in executed branches after genesis is activated,
    // we still have to check if the rest of the script is valid
    bool nonTopLevelReturnAfterGenesis = false;
    
        while (pc < pend) {

            //
            // Read instruction
            //
            if (!script.GetOp (pc, opcode, vchPushValue)) return set_error (serror, SCRIPT_ERR_BAD_OPCODE);
            ipc = pc - script.begin ();

            // Do not execute instructions if Genesis OP_RETURN was found in executed branches.
            bool fExec = !count (vfExec.begin (), vfExec.end (), false) && (!nonTopLevelReturnAfterGenesis || opcode == OP_RETURN);

            if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF)) {
                switch (opcode) {
                    //
                    // Push value
                    //
                    case OP_1NEGATE:
                    case OP_1:
                    case OP_2:
                    case OP_3:
                    case OP_4:
                    case OP_5:
                    case OP_6:
                    case OP_7:
                    case OP_8:
                    case OP_9:
                    case OP_10:
                    case OP_11:
                    case OP_12:
                    case OP_13:
                    case OP_14:
                    case OP_15:
                    case OP_16: 
                    case OP_NOP:
                    case OP_NOP1:
                    case OP_CHECKLOCKTIMEVERIFY: 
                    case OP_CHECKSEQUENCEVERIFY: 
                    case OP_NOP4:
                    case OP_NOP5:
                    case OP_NOP6:
                    case OP_NOP7:
                    case OP_NOP8:
                    case OP_NOP9:
                    case OP_NOP10: throw std::logic_error {"should not evaluate this"};

                    case OP_IF:
                    case OP_NOTIF: {
                        // <expression> if [statements] [else [statements]]
                        // endif
                        bool fValue = false;
                        if (fExec) {
                            if (stack.size () < 1)
                                return set_error (serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);

                            LimitedVector &vch = stack.stacktop (-1);
                            if (flags & SCRIPT_VERIFY_MINIMALIF) {
                                if (vch.size () > 1)
                                    return set_error (serror, SCRIPT_ERR_MINIMALIF);

                                if (vch.size () == 1 && vch[0] != 1)
                                    return set_error (serror, SCRIPT_ERR_MINIMALIF);
                            }

                            fValue = CastToBool (vch.GetElement ());
                            if (opcode == OP_NOTIF)
                                fValue = !fValue;

                            stack.pop_back ();
                        }

                        vfExec.push_back (fValue);
                        vfElse.push_back (false);
                    } break;

                    case OP_ELSE: {
                        // Only one ELSE is allowed in IF after genesis.
                        if (vfExec.empty () || (vfElse.back() && utxo_after_genesis))
                            return set_error (serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);

                        vfExec.back () = !vfExec.back ();
                        vfElse.back () = true;
                    } break;

                    case OP_ENDIF: {
                        if (vfExec.empty ()) return set_error (serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        vfExec.pop_back ();
                        vfElse.pop_back ();
                    } break;

                    case OP_VERIFY: 
                    case OP_RETURN: 
                    case OP_TOALTSTACK: 
                    case OP_FROMALTSTACK:
                    case OP_2DROP: 
                    case OP_2DUP:
                    case OP_3DUP: 
                    case OP_2OVER: 
                    case OP_2ROT: 
                    case OP_2SWAP: 
                    case OP_IFDUP:
                    case OP_DEPTH:
                    case OP_DROP: 
                    case OP_DUP: 
                    case OP_NIP: 
                    case OP_OVER: 
                    case OP_PICK:
                    case OP_ROLL: 
                    case OP_ROT: 
                    case OP_SWAP: 
                    case OP_TUCK: 
                    case OP_SIZE: 

                    //
                    // Bitwise logic
                    //
                    case OP_AND:
                    case OP_OR:
                    case OP_XOR: 
                    case OP_INVERT:
                    case OP_LSHIFT:
                    case OP_RSHIFT:
                    case OP_EQUAL:
                    case OP_EQUALVERIFY: 

                    //
                    // Numeric
                    //
                    case OP_1ADD:
                    case OP_1SUB:
                    case OP_NEGATE:
                    case OP_ABS:
                    case OP_NOT:
                    case OP_0NOTEQUAL: 
                    case OP_ADD:
                    case OP_SUB:
                    case OP_MUL:
                    case OP_DIV:
                    case OP_MOD:
                    case OP_BOOLAND:
                    case OP_BOOLOR:
                    case OP_NUMEQUAL:
                    case OP_NUMEQUALVERIFY:
                    case OP_NUMNOTEQUAL:
                    case OP_LESSTHAN:
                    case OP_GREATERTHAN:
                    case OP_LESSTHANOREQUAL:
                    case OP_GREATERTHANOREQUAL:
                    case OP_MIN:
                    case OP_MAX: 
                    case OP_WITHIN: 

                    //
                    // Crypto
                    //
                    case OP_RIPEMD160:
                    case OP_SHA1:
                    case OP_SHA256:
                    case OP_HASH160:
                    case OP_HASH256: 
                    case OP_CODESEPARATOR:
                    case OP_CHECKSIG:
                    case OP_CHECKSIGVERIFY: 
                    case OP_CHECKMULTISIG:
                    case OP_CHECKMULTISIGVERIFY:

                    //
                    // Byte string operations
                    //
                    case OP_CAT:
                    case OP_SPLIT:

                    //
                    // Conversion operations
                    //
                    case OP_NUM2BIN:
                    case OP_BIN2NUM: throw std::logic_error {"should not reach this point"};

                    default: {
                        if (IsInvalidBranchingOpcode (opcode) && utxo_after_genesis && !fExec)
                            break;

                        return set_error (serror, SCRIPT_ERR_BAD_OPCODE);
                    }
                }
            }
        }

    return set_success (serror);
}

data::maybe<bool> EvalScript (
    const script_config &config,
    bool consensus,
    LimitedStack &stack,
    const CScript &script,
    uint32_t flags,
    ScriptError *serror) {
    LimitedStack altstack {stack.makeChildStack ()};
    long ipc {0};
    data::cross<bool> vfExec, vfElse;
    return EvalScript (config, consensus, stack, script, flags, altstack, ipc, vfExec, vfElse, serror);
}

}
