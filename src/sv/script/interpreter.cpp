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

namespace {

inline bool set_success(ScriptError *ret) {
    if (ret) {
        *ret = SCRIPT_ERR_OK;
    }
    return true;
}

inline bool set_error(ScriptError *ret, const ScriptError serror) {
    if (ret) {
        *ret = serror;
    }
    return false;
}

constexpr auto bits_per_byte{8};

} // namespace

inline uint8_t make_rshift_mask(size_t n) {
    static uint8_t mask[] = {0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80}; 
    return mask[n]; 
} 

inline uint8_t make_lshift_mask(size_t n) {
    static uint8_t mask[] = {0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01}; 
    return mask[n]; 
} 

// shift x right by n bits, implements OP_RSHIFT
static valtype RShift(const valtype &x, int n) {
    valtype::size_type bit_shift = n % 8;
    valtype::size_type byte_shift = n / 8;
 
    uint8_t mask = make_rshift_mask(bit_shift); 
    uint8_t overflow_mask = ~mask; 
 
    valtype result(x.size(), 0x00); 
    for (valtype::size_type i = 0; i < x.size(); i++) {
        valtype::size_type k = i + byte_shift;
        if (k < x.size()) {
            uint8_t val = (x[i] & mask); 
            val >>= bit_shift;
            result[k] |= val; 
        } 

        if (k + 1 < x.size()) {
            uint8_t carryval = (x[i] & overflow_mask); 
            carryval <<= 8 - bit_shift; 
            result[k + 1] |= carryval;
        } 
    } 
    return result; 
} 

// shift x left by n bits, implements OP_LSHIFT
static valtype LShift(const valtype &x, int n) {
    valtype::size_type bit_shift = n % 8;
    valtype::size_type byte_shift = n / 8;

    uint8_t mask = make_lshift_mask(bit_shift); 
    uint8_t overflow_mask = ~mask; 

    valtype result(x.size(), 0x00); 
    for (valtype::size_type index = x.size(); index > 0; index--) {
        valtype::size_type i = index - 1;
        // make sure that k is always >= 0
        if (byte_shift <= i)
        {
            valtype::size_type k = i - byte_shift;
            uint8_t val = (x[i] & mask);
            val <<= bit_shift;
            result[k] |= val;

            if (k >= 1) {
                uint8_t carryval = (x[i] & overflow_mask);
                carryval >>= 8 - bit_shift;
                result[k - 1] |= carryval;
            }
        }
    }
    return result; 
} 

bool CastToBool(const valtype &vch) {
    for (size_t i = 0; i < vch.size(); i++) {
        if (vch[i] != 0) {
            // Can be negative zero
            if (i == vch.size() - 1 && vch[i] == 0x80) {
                return false;
            }
            return true;
        }
    }
    return false;
}

static bool IsInvalidBranchingOpcode(opcodetype opcode) {
    return opcode == OP_VERNOTIF || opcode == OP_VERIF;
}

std::optional<bool> EvalScript(
    const CScriptConfig& config,
    bool consensus,
    LimitedStack& stack,
    const CScript& script,
    uint32_t flags,
    LimitedStack& altstack,
    long& ipc,
    std::vector<bool>& vfExec,
    std::vector<bool>& vfElse,
    ScriptError* serror)
{
    static const CScriptNum bnZero(0);
    static const CScriptNum bnOne(1);
    static const valtype vchFalse(0);
    static const valtype vchTrue(1, 1);
    
    CScript::const_iterator pc = script.begin();
    CScript::const_iterator pend = script.end();
    CScript::const_iterator pbegincodehash = script.begin();
    opcodetype opcode;
    valtype vchPushValue;
    
    set_error(serror, SCRIPT_ERR_UNKNOWN_ERROR);
    
    const bool utxo_after_genesis{(flags & SCRIPT_UTXO_AFTER_GENESIS) != 0};
    const uint64_t maxScriptNumLength = config.GetMaxScriptNumLength(utxo_after_genesis, consensus);
    
    if(script.size() > config.GetMaxScriptSize(utxo_after_genesis, consensus))
    {
        return set_error(serror, SCRIPT_ERR_SCRIPT_SIZE);
    }
    
    const bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;
    
    // if OP_RETURN is found in executed branches after genesis is activated,
    // we still have to check if the rest of the script is valid
    bool nonTopLevelReturnAfterGenesis = false;
    
        while (pc < pend) {

            //
            // Read instruction
            //
            if (!script.GetOp(pc, opcode, vchPushValue)) {
                return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
            }
            ipc = pc - script.begin();

            // Do not execute instructions if Genesis OP_RETURN was found in executed branches.
            bool fExec = !count(vfExec.begin(), vfExec.end(), false) && (!nonTopLevelReturnAfterGenesis || opcode == OP_RETURN);

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
                    case OP_NOP10: throw std::logic_error{"should not evaluate this"};

                    case OP_IF:
                    case OP_NOTIF: {
                        // <expression> if [statements] [else [statements]]
                        // endif
                        bool fValue = false;
                        if (fExec) {
                            if (stack.size() < 1) {
                                return set_error(
                                    serror, SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                            }
                            LimitedVector &vch = stack.stacktop(-1);
                            if (flags & SCRIPT_VERIFY_MINIMALIF) {
                                if (vch.size() > 1) {
                                    return set_error(serror,
                                                     SCRIPT_ERR_MINIMALIF);
                                }
                                if (vch.size() == 1 && vch[0] != 1) {
                                    return set_error(serror,
                                                     SCRIPT_ERR_MINIMALIF);
                                }
                            }
                            fValue = CastToBool(vch.GetElement());
                            if (opcode == OP_NOTIF) {
                                fValue = !fValue;
                            }
                            stack.pop_back();
                        }
                        vfExec.push_back(fValue);
                        vfElse.push_back(false);
                    } break;

                    case OP_ELSE: {
                        // Only one ELSE is allowed in IF after genesis.
                        if (vfExec.empty() || (vfElse.back() && utxo_after_genesis)) {
                            return set_error(serror,
                                             SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        }
                        vfExec.back() = !vfExec.back();
                        vfElse.back() = true;
                    } break;

                    case OP_ENDIF: {
                        if (vfExec.empty()) {
                            return set_error(serror,
                                             SCRIPT_ERR_UNBALANCED_CONDITIONAL);
                        }
                        vfExec.pop_back();
                        vfElse.pop_back();
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
                    case OP_INVERT: throw std::logic_error{"should not evaluate this"};

                    case OP_LSHIFT:
                    {
                        // (x n -- out)
                        if(stack.size() < 2)
                        {
                            return set_error(
                                serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }

                        const LimitedVector vch1 = stack.stacktop(-2);
                        const auto& top{stack.stacktop(-1).GetElement()};
                        CScriptNum n{top, fRequireMinimal, maxScriptNumLength,
                                     utxo_after_genesis};
                        if(n < 0)
                        {
                            return set_error(serror,
                                             SCRIPT_ERR_INVALID_NUMBER_RANGE);
                        }

                        stack.pop_back();
                        stack.pop_back();
                        auto values{vch1.GetElement()};

                        if(n >= values.size() * bits_per_byte)
                            fill(begin(values), end(values), 0);
                        else
                        {
                            do
                            {
                                values = LShift(values, n.getint());
                                n -= utxo_after_genesis
                                         ? CScriptNum{bsv::bint{INT32_MAX}}
                                         : CScriptNum{INT32_MAX};
                            } while(n > 0);
                        }
                        stack.push_back(values);
                    }
                    break;

                    case OP_RSHIFT:
                    {
                        // (x n -- out)
                        if(stack.size() < 2)
                        {
                            return set_error(
                                serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }

                        const LimitedVector vch1 = stack.stacktop(-2);
                        const auto& top{stack.stacktop(-1).GetElement()};
                        CScriptNum n{top, fRequireMinimal, maxScriptNumLength,
                                     utxo_after_genesis};
                        if(n < 0)
                        {
                            return set_error(serror,
                                             SCRIPT_ERR_INVALID_NUMBER_RANGE);
                        }

                        stack.pop_back();
                        stack.pop_back();
                        auto values{vch1.GetElement()};

                        if(n >= values.size() * bits_per_byte)
                            fill(begin(values), end(values), 0);
                        else
                        {
                            do
                            {
                                values = RShift(values, n.getint());
                                n -= utxo_after_genesis
                                         ? CScriptNum{bsv::bint{INT32_MAX}}
                                         : CScriptNum{INT32_MAX};
                            } while(n > 0);
                        }
                        stack.push_back(values);
                    }
                    break;

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
                    case OP_CHECKMULTISIGVERIFY: throw std::logic_error{"should not reach this point"}; 

                    //
                    // Byte string operations
                    //
                    case OP_CAT: {
                        // (x1 x2 -- out)
                        if (stack.size() < 2) {
                            return set_error(
                                serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }

                        LimitedVector &vch1 = stack.stacktop(-2);
                        // We make copy of last element on stack (vch2) so we can pop the last
                        // element before appending it to the previous element.
                        // If appending would be first, we could exceed stack size in the process
                        // even though OP_CAT actually reduces total stack size.
                        LimitedVector vch2 = stack.stacktop(-1);

                        if (!utxo_after_genesis &&
                            (vch1.size() + vch2.size() > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS))
                        {
                            return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                        }

                        stack.pop_back();
                        vch1.append(vch2);
                    } break;

                    case OP_SPLIT: {
                        // (in position -- x1 x2)
                        if(stack.size() < 2)
                            return set_error(
                                serror, SCRIPT_ERR_INVALID_STACK_OPERATION);

                        const LimitedVector& data = stack.stacktop(-2);

                        // Make sure the split point is apropriate.
                        const auto& top{stack.stacktop(-1).GetElement()};
                        const CScriptNum n{
                            top, fRequireMinimal,
                            maxScriptNumLength,
                            utxo_after_genesis};
                        if(n < 0 || n > data.size())
                            return set_error(serror,
                                             SCRIPT_ERR_INVALID_SPLIT_RANGE);

                        const auto position{n.to_size_t_limited()};

                        // Prepare the results in their own buffer as `data`
                        // will be invalidated.
                        valtype n1(data.begin(), data.begin() + position);
                        valtype n2(data.begin() + position, data.end());
                        
                        stack.pop_back();
                        stack.pop_back();

                        // Replace existing stack values by the new values.
                        stack.push_back(n1);
                        stack.push_back(n2);
                    } break;

                    //
                    // Conversion operations
                    //
                    case OP_NUM2BIN: {
                        // (in size -- out)
                        if (stack.size() < 2) {
                            return set_error(
                                serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }

                        const auto& arg_1 = stack.stacktop(-1).GetElement();
                        const CScriptNum n{
                            arg_1, fRequireMinimal,
                            maxScriptNumLength,
                            utxo_after_genesis};
                        if(n < 0 || n > std::numeric_limits<int32_t>::max())
                            return set_error(serror, SCRIPT_ERR_PUSH_SIZE);

                        const auto size{n.to_size_t_limited()};
                        if(!utxo_after_genesis && (size > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS))
                        {
                            return set_error(serror, SCRIPT_ERR_PUSH_SIZE);
                        }

                        stack.pop_back();
                        LimitedVector &rawnum = stack.stacktop(-1);

                        // Try to see if we can fit that number in the number of
                        // byte requested.
                        rawnum.MinimallyEncode();
                        if (rawnum.size() > size) {
                            // We definitively cannot.
                            return set_error(serror,
                                             SCRIPT_ERR_IMPOSSIBLE_ENCODING);
                        }

                        // We already have an element of the right size, we
                        // don't need to do anything.
                        if (rawnum.size() == size) {
                            break;
                        }

                        uint8_t signbit = 0x00;
                        if (rawnum.size() > 0) {
                            signbit = rawnum.GetElement().back() & 0x80;
                            rawnum[rawnum.size() - 1] &= 0x7f;
                        }

                        rawnum.padRight(size, signbit);
                    } break;

                    case OP_BIN2NUM: {
                        // (in -- out)
                        if (stack.size() < 1) {
                            return set_error(
                                serror, SCRIPT_ERR_INVALID_STACK_OPERATION);
                        }

                        LimitedVector &n = stack.stacktop(-1);
                        n.MinimallyEncode();

                        // The resulting number must be a valid number.
                        if (!n.IsMinimallyEncoded(maxScriptNumLength))
                        {
                            return set_error(serror,
                                             SCRIPT_ERR_INVALID_NUMBER_RANGE);
                        }
                    } break;

                    default: {
                        if (IsInvalidBranchingOpcode(opcode) && utxo_after_genesis && !fExec)
                        {
                            break;
                        }

                        return set_error(serror, SCRIPT_ERR_BAD_OPCODE);
                    }
                }
            }
        }

    return set_success(serror);
}

std::optional<bool> EvalScript(
    const CScriptConfig& config,
    bool consensus,
    LimitedStack& stack,
    const CScript& script,
    uint32_t flags,
    ScriptError* serror)
{
    LimitedStack altstack {stack.makeChildStack()};
    long ipc{0};
    std::vector<bool> vfExec, vfElse;
    return EvalScript(config, consensus, stack, script, flags, altstack, ipc, vfExec, vfElse, serror);
}
