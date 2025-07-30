// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/machine.hpp>
#include <gigamonkey/script/bitcoin_core.hpp>
#include <sv/policy/policy.h>

// not in use but required by config.h dependency
bool fRequireStandard = true;

namespace Gigamonkey::Bitcoin {

    machine::machine (ptr<two_stack> stack, maybe<redemption_document> doc, const script_config &conf):
        Halt {false}, Result {false}, Config {conf},
        UtxoAfterGenesis {bool (static_cast<uint32> (Config.Flags & flag::ENABLE_GENESIS_OPCODES))},
        RequireMinimal {Config.verify_minimal_push ()},
        Document {doc}, Stack {stack}, Exec {}, Else {}, OpCount {0} {}

    bool inline IsValidMaxOpsPerScript (uint64_t nOpCount, const script_config &config) {
        return (nOpCount <= config.MaxOpsPerScript);
    }

    bool inline machine::increment_operation () {
        return IsValidMaxOpsPerScript (++OpCount, Config);
    }
    
    program inline cleanup_script_code (program script_code, slice<const byte> sig) {
        return sighash::has_fork_id (signature::directive (sig)) ? script_code :
            find_and_delete (script_code, instruction::push (sig));
    }
    
    sighash::document inline *add_script_code (redemption_document &doc, program script_code) {
        return new sighash::document {doc.Transaction, doc.InputIndex, doc.RedeemedValue, script_code};
    }

    constexpr auto bits_per_byte {8};
    
    slice<const byte> get_push_data (slice<const byte> instruction) {
        if (instruction.size () < 1) return {};
        
        op Op = op (instruction[0]);
        
        if (!is_push_data (Op)) return {};
        
        if (Op <= OP_PUSHSIZE75) return instruction.drop (1);
        
        if (Op == OP_PUSHDATA1) return instruction.drop (2);
        
        if (Op == OP_PUSHDATA2) return instruction.drop (3);
        
        return instruction.drop (5);
    }

    bool inline IsInvalidBranchingOpcode (op opcode) {
        return opcode == OP_VERNOTIF || opcode == OP_VERIF;
    }

    // just take the first four bites.
    // must know that it's not negative or too big.
    uint32_little inline read_as_uint32_little (const integer &n) {
        uint32_little ul {0};
        std::copy (n.begin (), n.begin () + (n.size () >= 4 ? 4 : n.size ()), ul.begin ());
        return ul;
    }
    
    maybe<result> machine::step (const program_counter &Counter) {
        
        if (Counter.Next == slice<const byte> {}) {
            if (Config.verify_clean_stack () && (Stack->size () != 1)) return SCRIPT_ERR_CLEANSTACK;
            if (Stack->size () == 0) return false;
            return nonzero (Stack->top ());
        }
        
        op Op = op (Counter.Next[0]);
        
        // Check opcode limits.
        //
        // Push values are not taken into consideration.
        // Note how OP_RESERVED does not count towards the opcode limit.
        if ((Op > OP_16) && !increment_operation ()) return SCRIPT_ERR_OP_COUNT;
        
        // whether this op code will be executed. 
        // need to take into account OP_RETURN
        bool executed = !count (Exec.begin (), Exec.end (), false);
        if (!executed) return {};

        // Some opcodes are disabled.
        if (Config.disabled (Op) && executed) return SCRIPT_ERR_DISABLED_OPCODE;
        
        if (executed && 0 <= Op && Op <= OP_PUSHDATA4) Stack->push_back (get_push_data (Counter.Next));
        else switch (Op) {
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
            case OP_16: {
                // ( -- value)
                Stack->push_back (integer {((int) Op - (int) (OP_1 - 1))});
                // The result of these opcodes should always be the
                // minimal way to push the data they push, so no need
                // for a CheckMinimalPush here.
            } break;

            //
            // Control
            //
            case OP_NOP:
                break;
            
            case OP_CHECKLOCKTIMEVERIFY: {
                if (Config.check_locktime ()) {
                    // not enabled; treat as a NOP2
                    if (verify_discourage_upgradable_NOPs (Config.Flags))
                        return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;

                    break;
                }

                if (Stack->size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                // Note that elsewhere numeric opcodes are limited to
                // operands in the range -2**31+1 to 2**31-1, however it
                // is legal for opcodes to produce results exceeding
                // that range. This limitation is implemented by
                // CScriptNum's default 4-byte limit.
                //
                // If we kept to that limit we'd have a year 2038
                // problem, even though the nLockTime field in
                // transactions themselves is uint32 which only becomes
                // meaningless after the year 2106.
                //
                // Thus as a special case we tell CScriptNum to accept
                // up to 5-byte bignums, which are good until 2**39-1,
                // well beyond the 2**32-1 limit of the nLockTime field
                // itself.
                const integer nLockTime = read_integer (Stack->top (), RequireMinimal, 5);

                // In the rare event that the argument may be < 0 due to
                // some arithmetic being done first, you can always use
                // 0 MAX CHECKLOCKTIMEVERIFY.
                if (is_negative (nLockTime)) return SCRIPT_ERR_NEGATIVE_LOCKTIME;

                // Actually compare the specified lock time with the
                // transaction.
                if (bool (Document) && !Document->check_locktime (read_as_uint32_little (nLockTime)))
                    return SCRIPT_ERR_UNSATISFIED_LOCKTIME;

            } break;

            case OP_CHECKSEQUENCEVERIFY: {
                if (Config.check_sequence ()) {
                    // not enabled; treat as a NOP3
                    if (verify_discourage_upgradable_NOPs (Config.Flags))
                        return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;

                    break;
                }

                if (Stack->size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                // nSequence, like nLockTime, is a 32-bit unsigned
                // integer field. See the comment in CHECKLOCKTIMEVERIFY
                // regarding 5-byte numeric operands.
                const integer nSequence = read_integer (Stack->top (), RequireMinimal, 5);

                // In the rare event that the argument may be < 0 due to
                // some arithmetic being done first, you can always use
                // 0 MAX CHECKSEQUENCEVERIFY.
                if (nSequence < 0) return SCRIPT_ERR_NEGATIVE_LOCKTIME;
                auto nx = read_as_uint32_little (nSequence);

                // To provide for future soft-fork extensibility, if the
                // operand has the disabled lock-time flag set,
                // CHECKSEQUENCEVERIFY behaves as a NOP.
                if (uint32 (nx) & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) return SCRIPT_ERR_OK;

                // Compare the specified sequence number with the input.
                if (bool (Document) && !Document->check_sequence (nx))
                    return SCRIPT_ERR_UNSATISFIED_LOCKTIME;

            } break;
            
            case OP_NOP1:
            case OP_NOP7:
            case OP_NOP8:
            case OP_NOP9:
            case OP_NOP10: {
                if (verify_discourage_upgradable_NOPs (Config.Flags))
                    return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;
            } break;

            case OP_IF:
            case OP_NOTIF: {
                // <expression> if [statements] [else [statements]]
                // endif
                bool fValue = false;
                if (executed) {
                    if (Stack->size () < 1) return SCRIPT_ERR_UNBALANCED_CONDITIONAL;

                    auto &vch = Stack->top ();
                    if (verify_minimal_if (Config.Flags))
                        if (vch.size () > 1 || vch.size () == 1 && vch[0] != 1)
                            return SCRIPT_ERR_MINIMALIF;

                    fValue = nonzero (vch);
                    if (Op == OP_NOTIF)
                        fValue = !fValue;

                    Stack->pop_back ();
                }

                Exec.push_back (fValue);
                Else.push_back (false);
            } break;

            case OP_ELSE: {
                // Only one ELSE is allowed in IF after genesis.
                if (Exec.empty () || (Else.back () && UtxoAfterGenesis))
                    return SCRIPT_ERR_UNBALANCED_CONDITIONAL;

                Exec.back () = !Exec.back ();
                Else.back () = true;
            } break;

            case OP_ENDIF: {
                if (Exec.empty ()) return SCRIPT_ERR_UNBALANCED_CONDITIONAL;
                Exec.pop_back ();
                Else.pop_back ();
            } break;

            case OP_VERIFY: {
                // (true -- ) or
                // (false -- false) and return
                if (Stack->size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                if (nonzero (Stack->top ())) Stack->pop_back ();
                else return SCRIPT_ERR_VERIFY;
                
            } break;
            
            case OP_RETURN: {
                if (UtxoAfterGenesis) {
                    if (Exec.empty ()) return true;
                    // Pre-Genesis OP_RETURN marks script as invalid
                } else return SCRIPT_ERR_OP_RETURN;
            } break;
                    
            //
            // Stack ops
            //
            case OP_TOALTSTACK: {
                if (Stack->size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                Stack->to_alt ();
            } break;

            case OP_FROMALTSTACK: {
                if (Stack->alt_size () < 1) return SCRIPT_ERR_INVALID_ALTSTACK_OPERATION;
                Stack->from_alt ();
            } break;

            case OP_2DROP: {
                // (x1 x2 -- )
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                    
                Stack->pop_back ();
                Stack->pop_back ();
                
            } break;

            case OP_2DUP: {
                // (x1 x2 -- x1 x2 x1 x2)
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                auto vch1 = Stack->top (-2);
                auto vch2 = Stack->top ();
                
                Stack->push_back (vch1);
                Stack->push_back (vch2);
                
            } break;

            case OP_3DUP: {
                // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                if (Stack->size () < 3) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                auto vch1 = Stack->top (-3);
                auto vch2 = Stack->top (-2);
                auto vch3 = Stack->top ();
                
                Stack->push_back (vch1);
                Stack->push_back (vch2);
                Stack->push_back (vch3);
                
            } break;

            case OP_2OVER: {
                // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                if (Stack->size () < 4) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                auto vch1 = Stack->top (-4);
                auto vch2 = Stack->top (-3);
                Stack->push_back (vch1);
                Stack->push_back (vch2);
            } break;

            case OP_2ROT: {
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                if (Stack->size () < 6) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                auto vch1 = Stack->top (-6);
                auto vch2 = Stack->top (-5);
                
                Stack->erase (-6, -4);
                Stack->push_back (vch1);
                Stack->push_back (vch2);
                
            } break;

            case OP_2SWAP: {
                
                // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                if (Stack->size () < 4) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                Stack->swap (Stack->size () - 4, Stack->size () - 2);
                Stack->swap (Stack->size () - 3, Stack->size () - 1);
                
            } break;
            
            case OP_IFDUP: {
                // (x - 0 | x x)
                if (Stack->size () < 1)
                    return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                auto vch = Stack->top ();

                if (nonzero (vch)) Stack->push_back (vch);
                
            } break;

            case OP_DEPTH: {
                // -- stacksize
                Stack->push_back (integer {Stack->size ()});
                
            } break;

            case OP_DROP: {
                // (x -- )
                if (Stack->size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                Stack->pop_back ();
                
            } break;

            case OP_DUP: {
                // (x -- x x)
                if (Stack->size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                auto vch = Stack->top ();
                Stack->push_back (vch);
            } break;

            case OP_NIP: {
                // (x1 x2 -- x2)
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                Stack->erase (-2);
                
            } break;

            case OP_OVER: {
                // (x1 x2 -- x1 x2 x1)
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                auto vch = Stack->top (-2);
                Stack->push_back (vch);
                
            } break;

            case OP_PICK:
            case OP_ROLL: {
                // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                const auto sn = read_integer (Stack->top (), RequireMinimal, Config.MaxScriptNumLength);
                Stack->pop_back ();
                if (sn < 0 || sn >= Stack->size ())
                    return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                const uint32 n = uint32 (read_as_uint32_little (sn));
                auto vch = Stack->top (-n - 1);

                if (Op == OP_ROLL) Stack->erase (-n - 1);

                Stack->push_back (vch);
                
            } break;

            case OP_ROT: {
                // (x1 x2 x3 -- x2 x3 x1)
                //  x2 x1 x3  after first swap
                //  x2 x3 x1  after second swap
                if (Stack->size () < 3)
                    return SCRIPT_ERR_INVALID_STACK_OPERATION;

                Stack->swap (Stack->size () - 3, Stack->size () - 2);
                Stack->swap (Stack->size () - 2, Stack->size () - 1);
                
            } break;

            case OP_SWAP: {
                // (x1 x2 -- x2 x1)
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                Stack->swap (Stack->size () - 2, Stack->size () - 1);
                
            } break;

            case OP_TUCK: {
                // (x1 x2 -- x2 x1 x2)
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                auto vch = Stack->top ();
                Stack->insert (-2, vch);
                
            } break;

            case OP_SIZE: {
                // (in -- in size)
                if (Stack->size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                Stack->push_back (integer {Stack->top ().size ()});
                
            } break;

            //
            // Bitwise logic
            //
            case OP_AND:
            case OP_OR:
            case OP_XOR: {
                // (x1 x2 - out)
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                auto &vch1 = Stack->top (-2);
                auto &vch2 = Stack->top ();

                // Inputs must be the same size
                if (vch1.size () != vch2.size ()) return SCRIPT_ERR_INVALID_OPERAND_SIZE;

                // To avoid allocating, we modify vch1 in place.
                switch (Op) {
                    case OP_AND: for (size_t i = 0; i < vch1.size (); ++i) vch1[i] &= vch2[i];
                        break;
                        
                    case OP_OR: for (size_t i = 0; i < vch1.size (); ++i) vch1[i] |= vch2[i];
                        break;
                        
                    case OP_XOR: for (size_t i = 0; i < vch1.size (); ++i) vch1[i] ^= vch2[i];
                        break;
                        
                    default:
                        break;
                }

                // And pop vch2.
                Stack->pop_back ();
            } break;

            case OP_INVERT: {
                // (x -- out)
                if (Stack->size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                auto &vch1 = Stack->top ();
                // To avoid allocating, we modify vch1 in place
                for (size_t i = 0; i < vch1.size (); i++) vch1[i] = ~vch1[i];
                
            } break;

            case OP_LSHIFT: {
                // (x n -- out)
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                integer n = read_integer (Stack->top (), RequireMinimal, Config.MaxScriptNumLength);
                if (n < 0) return SCRIPT_ERR_INVALID_NUMBER_RANGE;

                Stack->pop_back ();

                Stack->modify_top ([&n] (bytes &values) {
                    if (n >= values.size () * bits_per_byte) fill (begin (values), end (values), 0);
                    else {
                        integer max = integer {INT32_MAX};
                        while (n > max) {
                            values = left_shift (values, INT32_MAX);
                            n -= max;
                        }
                        values = left_shift (values, static_cast<int32> (uint32 (read_as_uint32_little (n))));
                    }
                });
            } break;

            case OP_RSHIFT: {
                // (x n -- out)
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                integer n = read_integer (Stack->top (), RequireMinimal, Config.MaxScriptNumLength);
                if (n < 0) return SCRIPT_ERR_INVALID_NUMBER_RANGE;

                Stack->pop_back ();

                Stack->modify_top ([&n] (bytes &values) {
                    if (n >= values.size () * bits_per_byte) fill (begin (values), end (values), 0);
                    else {
                        integer max = integer {INT32_MAX};
                        while (n > max) {
                            values = right_shift (values, INT32_MAX);
                            n -= max;
                        }
                        values = right_shift (values, static_cast<int32> (uint32 (read_as_uint32_little (n))));
                    }
                });
            } break;

            case OP_EQUAL:
            case OP_EQUALVERIFY: {
                // (x1 x2 - bool)
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                auto &vch1 = Stack->top (-2);
                auto &vch2 = Stack->top ();

                bool fEqual = (vch1 == vch2);
                // OP_NOTEQUAL is disabled because it would be too
                // easy to say something like n != 1 and have some
                // wiseguy pass in 1 with extra zero bytes after it
                // (numerically, 0x01 == 0x0001 == 0x000001)
                // if (opcode == OP_NOTEQUAL)
                //    fEqual = !fEqual;
                Stack->pop_back ();
                Stack->pop_back ();
                Stack->push_back (integer (fEqual));
                
                if (Op == OP_EQUALVERIFY) {
                    if (fEqual) Stack->pop_back ();
                    else return SCRIPT_ERR_EQUALVERIFY;
                }
                
            } break;

            //
            // Numeric
            //
            case OP_1ADD:
            case OP_1SUB:
            case OP_2MUL:
            case OP_2DIV:
            case OP_NEGATE:
            case OP_ABS:
            case OP_NOT:
            case OP_0NOTEQUAL: {
                // (in -- out)
                if (Stack->size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                integer bn = read_integer (Stack->top (), RequireMinimal, Config.MaxScriptNumLength);
                
                switch (Op) {
                    case OP_1ADD:
                        bn++;
                        break;
                    case OP_1SUB:
                        bn--;
                        break;
                    case OP_2MUL:
                        bn <<= 1;
                        break;
                    case OP_2DIV:
                        if (is_negative (bn)) bn++;
                        bn >>= 1;
                        break;
                    case OP_NEGATE:
                        bn = -bn;
                        break;
                    case OP_ABS:
                        if (is_negative (bn)) bn = -bn;
                        break;
                    case OP_NOT:
                        bn = integer {!bool (bn)};
                        break;
                    case OP_0NOTEQUAL:
                        bn = integer {bool (bn)};
                        break;
                    default:
                        assert (!"invalid opcode");
                        break;
                }
                
                Stack->pop_back ();
                Stack->push_back (bn);
            } break;

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
            case OP_MAX: {
                // (x1 x2 -- out)
                if (Stack->size () < 2) SCRIPT_ERR_INVALID_STACK_OPERATION;

                const auto& bn1 = read_integer (Stack->top (-2), RequireMinimal, Config.MaxScriptNumLength);
                const auto& bn2 = read_integer (Stack->top (), RequireMinimal, Config.MaxScriptNumLength);

                integer bn {};
                switch (Op) {
                    case OP_ADD:
                        bn = bn1 + bn2;
                        break;

                    case OP_SUB:
                        bn = bn1 - bn2;
                        break;

                    case OP_MUL:
                        bn = bn1 * bn2;
                        break;

                    case OP_DIV:
                        // denominator must not be 0
                        if (is_zero (bn2)) return SCRIPT_ERR_DIV_BY_ZERO;
                        bn = bn1 / bn2;
                        break;

                    case OP_MOD:
                        // divisor must not be 0
                        if (is_zero (bn2)) return SCRIPT_ERR_MOD_BY_ZERO;
                        bn = bn1 % bn2;
                        break;

                    case OP_BOOLAND:
                        bn = integer {bool (bn1) && bool (bn2)};
                        break;
                    case OP_BOOLOR:
                        bn = integer {bool (bn1) || bool (bn2)};
                        break;
                    case OP_NUMEQUAL:
                        bn = (bn1 == bn2);
                        break;
                    case OP_NUMEQUALVERIFY:
                        bn = (bn1 == bn2);
                        break;
                    case OP_NUMNOTEQUAL:
                        bn = (bn1 != bn2);
                        break;
                    case OP_LESSTHAN:
                        bn = (bn1 < bn2);
                        break;
                    case OP_GREATERTHAN:
                        bn = (bn1 > bn2);
                        break;
                    case OP_LESSTHANOREQUAL:
                        bn = (bn1 <= bn2);
                        break;
                    case OP_GREATERTHANOREQUAL:
                        bn = (bn1 >= bn2);
                        break;
                    case OP_MIN:
                        bn = (bn1 < bn2 ? bn1 : bn2);
                        break;
                    case OP_MAX:
                        bn = (bn1 > bn2 ? bn1 : bn2);
                        break;
                    default:
                        assert (!"invalid opcode");
                        break;
                }
                
                Stack->pop_back ();
                Stack->pop_back ();
                Stack->push_back (bn);

                if (Op == OP_NUMEQUALVERIFY) {
                    if (nonzero (Stack->top ())) Stack->pop_back ();
                    else return SCRIPT_ERR_NUMEQUALVERIFY;
                }
            } break;

            case OP_WITHIN: {
                // (x min max -- out)
                if (Stack->size () < 3) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                const auto& bn1 = read_integer (Stack->top (-3), RequireMinimal, Config.MaxScriptNumLength);
                const auto& bn2 = read_integer (Stack->top (-2), RequireMinimal, Config.MaxScriptNumLength);
                const auto& bn3 = read_integer (Stack->top (-1), RequireMinimal, Config.MaxScriptNumLength);
                    
                const bool fValue = (bn2 <= bn1 && bn1 < bn3);
                Stack->pop_back ();
                Stack->pop_back ();
                Stack->pop_back ();

                Stack->push_back (integer (fValue));
            } break;
            //
            // Crypto
            //
            case OP_RIPEMD160:
            case OP_SHA1:
            case OP_SHA256:
            case OP_HASH160:
            case OP_HASH256: {
                // (in -- hash)
                if (Stack->size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                if (Op == OP_RIPEMD160) Stack->replace_back (RIPEMD_160 (Stack->top ()));
                else if (Op == OP_SHA1) Stack->replace_back (SHA1 (Stack->top ()));
                else if (Op == OP_SHA256) Stack->replace_back (SHA2_256 (Stack->top ()));
                else if (Op == OP_HASH160) Stack->replace_back (Hash160 (Stack->top ()));
                else if (Op == OP_HASH256) Stack->replace_back (Hash256 (Stack->top ()));
            } break;
            
            // we take care of this elsewhere. 
            case OP_CODESEPARATOR: break;
            
            case OP_CHECKSIG: 
            case OP_CHECKSIGVERIFY: {
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                const bytes &sig = Stack->top (-2);
                const bytes &pub = Stack->top ();
                
                result r;
                if (bool (Document)) {
                    auto doc = add_script_code (*Document, cleanup_script_code (Counter.to_last_code_separator (), sig));
                    r = result {verify_signature (sig, pub, *doc, Config.Flags)};
                    delete doc;
                } else r = result {true};
                
                if (r.Error) return r.Error;
                
                Stack->pop_back ();
                Stack->pop_back ();
                Stack->push_back (integer (r.Success));
                
                if (Op == OP_CHECKSIGVERIFY) {
                    if (r.Success) {
                        Stack->pop_back ();
                        return true;
                    } else return SCRIPT_ERR_CHECKSIGVERIFY;
                }
                
            } break;
            
            case OP_CHECKMULTISIG:
            case OP_CHECKMULTISIGVERIFY: {
                
                // ([sig ...] num_of_signatures [pubkey ...]
                // num_of_pubkeys -- bool)
                    
                uint64_t i = 1;
                if (Stack->size () < i) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                // initialize to max size of CScriptNum::MAXIMUM_ELEMENT_SIZE (4 bytes) 
                // because only 4 byte integers are supported by  OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY
                auto nKeysCountZ = read_integer (Stack->top (-i), RequireMinimal, MAXIMUM_ELEMENT_SIZE);
                if (nKeysCountZ < 0) return SCRIPT_ERR_PUBKEY_COUNT;
                
                int64 nKeysCount = static_cast<int64> (nKeysCountZ);
                if (nKeysCount > Config.MaxPubKeysPerMultiSig)
                    return SCRIPT_ERR_PUBKEY_COUNT;
                
                OpCount += nKeysCount;
                if (!IsValidMaxOpsPerScript (OpCount, Config))
                    return SCRIPT_ERR_OP_COUNT;
                
                uint64_t ikey = ++i;
                // ikey2 is the position of last non-signature item in
                // the stack. Top stack item = 1. With
                // SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if
                // operation fails.
                uint64_t ikey2 = nKeysCount + 2;
                i += nKeysCount;
                if (Stack->size () < i) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                auto nSigsCountZ = read_integer (Stack->top (-i), RequireMinimal, MAXIMUM_ELEMENT_SIZE);
                    
                if (nSigsCountZ < 0) return SCRIPT_ERR_SIG_COUNT;
                
                int64 nSigsCount = static_cast<int64> (nSigsCountZ);
                if (nSigsCount > nKeysCount) return SCRIPT_ERR_SIG_COUNT;
                
                uint64_t isig = ++i;
                i += nSigsCount;
                if (Stack->size () < i) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                sighash::document *doc = nullptr;
                if (bool (Document)) {
                    program script_code = Counter.to_last_code_separator ();
                    
                    // Remove signature for pre-fork scripts
                    for (auto it = Stack->begin () + 1; it != Stack->begin () + 1 + nSigsCount; it++)
                        script_code = cleanup_script_code (script_code, *it);
                    
                    doc = add_script_code (*Document, script_code);
                }
                
                bool fSuccess = true;
                while (fSuccess && nSigsCount > 0) {

                    const bytes &sig = Stack->top (-isig);
                    const bytes &pub = Stack->top (-ikey);
                    
                    // Note how this makes the exact order of
                    // pubkey/signature evaluation distinguishable by
                    // CHECKMULTISIG NOT if the STRICTENC flag is set.
                    // See the script_(in)valid tests for details.
                    // Check signature
                    
                    result r = (doc == nullptr) ? result {true} : result {verify_signature (sig, pub, *doc, Config.Flags)};
                    
                    if (r.Error) return r.Error;
                    
                    if (r.Success) {
                        isig++;
                        nSigsCount--;
                    }
                    
                    ikey++;
                    nKeysCount--;
                    
                    // If there are more signatures left than keys left,
                    // then too many signatures have failed. Exit early,
                    // without checking any further signatures.
                    if (nSigsCount > nKeysCount) fSuccess = false;
                    
                }
                
                delete doc;
                
                // Clean up stack of actual arguments
                while (i-- > 1) {
                    // If the operation failed, we require that all
                    // signatures must be empty vector
                    if (!fSuccess && (verify_null_fail (Config.Flags)) &&
                        !ikey2 && Stack->top ().size ()) {
                        return SCRIPT_ERR_SIG_NULLFAIL;
                    }
                    
                    if (ikey2 > 0) ikey2--;
                    
                    Stack->pop_back ();
                }
                
                // A bug causes CHECKMULTISIG to consume one extra
                // argument whose contents were not checked in any way.
                //
                // Unfortunately this is a potential source of
                // mutability, so optionally verify it is exactly equal
                // to zero prior to removing it from the stack.
                if (Stack->size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                if ((verify_null_dummy (Config.Flags)) &&
                    Stack->top ().size ()) return SCRIPT_ERR_SIG_NULLDUMMY;
                
                Stack->pop_back ();
                
                Stack->push_back (integer (fSuccess));
                
                if (Op == OP_CHECKMULTISIGVERIFY) {
                    if (fSuccess) {
                        Stack->pop_back ();
                        return true;
                    } else return SCRIPT_ERR_CHECKMULTISIGVERIFY;
                }
                
            } break;

            //
            // Byte string operations
            //
            case OP_CAT: {
                // (x1 x2 -- out)
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                // We make copy of last element on stack (vch2) so we can pop the last
                // element before appending it to the previous element.
                // If appending would be first, we could exceed stack size in the process
                // even though OP_CAT actually reduces total stack size.
                bytes vch = Stack->top ();

                Stack->pop_back ();
                Stack->modify_top ([&vch] (bytes &val) {
                    val.insert (val.end (), vch.begin (), vch.end ());
                });
            } break;

            case OP_SPLIT: {
                // (in position -- x1 x2)
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                const auto &data = Stack->top (-2);

                // Make sure the split point is apropriate.
                const integer n = read_integer (Stack->top (), RequireMinimal, Config.MaxScriptNumLength);

                if (n < 0 || n > data.size ()) return SCRIPT_ERR_INVALID_SPLIT_RANGE;

                const uint32 position = uint32 (read_as_uint32_little (n));

                // Prepare the results in their own buffer as `data`
                // will be invalidated.
                integer n1;
                integer n2;

                n1.resize (position);
                n2.resize (data.size () - position);

                std::copy (data.begin (), data.begin () + position, n1.begin ());
                std::copy (data.begin () + position, data.end (), n2.begin ());

                Stack->pop_back ();
                Stack->pop_back ();

                // Replace existing stack values by the new values.
                Stack->push_back (n1);
                Stack->push_back (n2);
            } break;

            // Extend a number to a certain size.
            // (shrinking numbers is not allowed, even if they
            // are not minimally encoded -- use OP_BIN2NUM first)
            case OP_NUM2BIN: {
                // (in size -- out)
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                const integer n = read_integer (Stack->top (), RequireMinimal, Config.MaxScriptNumLength);

                if (n < 0 || n > std::numeric_limits<int32_t>::max ())
                    return SCRIPT_ERR_PUSH_SIZE;

                const uint32 size = read_as_uint32_little (n);
                if (!UtxoAfterGenesis && (size > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS))
                    return SCRIPT_ERR_PUSH_SIZE;

                Stack->pop_back ();

                Stack->modify_top ([size] (bytes &rawnum) {
                    if (rawnum.size () > size) throw script_exception {SCRIPT_ERR_IMPOSSIBLE_ENCODING};
                    extend_number (rawnum, size);
                });

            } break;

            // trim a number to its minimal representation.
            case OP_BIN2NUM: {

                // (in -- out)
                if (Stack->size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                Stack->modify_top ([this] (bytes &n) {
                    trim_number (n);
                    if (n.size () > this->Config.MaxScriptNumLength) throw script_exception {SCRIPT_ERR_INVALID_NUMBER_RANGE};
                });

            } break;

            case OP_SUBSTR: {
                if (Stack->size () < 3) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                const auto &data = Stack->top (-3);
                const integer len = read_integer (Stack->top (), RequireMinimal, Config.MaxScriptNumLength);
                const integer pos = read_integer (Stack->top (-2), RequireMinimal, Config.MaxScriptNumLength);
                if (pos < 0 || pos > data.size ()) return SCRIPT_ERR_INVALID_SPLIT_RANGE;
                if (len < 0 || pos + len > data.size ()) return SCRIPT_ERR_INVALID_SPLIT_RANGE;

                const uint32 position = uint32 (read_as_uint32_little (pos));
                const uint32 length = uint32 (read_as_uint32_little (len));

                integer n1;

                n1.resize (length);

                std::copy (data.begin () + position, data.begin () + position + length, n1.begin ());

                Stack->pop_back ();
                Stack->pop_back ();
                Stack->pop_back ();

                Stack->push_back (n1);

            } break;

            case OP_LEFT: {
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                const auto &data = Stack->top (-2);
                const integer n = read_integer (Stack->top (), RequireMinimal, Config.MaxScriptNumLength);
                if (n < 0 || n > data.size ()) return SCRIPT_ERR_INVALID_SPLIT_RANGE;

                const uint32 position = uint32 (read_as_uint32_little (n));

                // Prepare the results in their own buffer as `data`
                // will be invalidated.
                integer n1;

                n1.resize (position);

                std::copy (data.begin (), data.begin () + position, n1.begin ());

                Stack->pop_back ();
                Stack->pop_back ();

                Stack->push_back (n1);

            } break;

            case OP_RIGHT: {
                if (Stack->size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                const auto &data = Stack->top (-2);
                const integer n = read_integer (Stack->top (), RequireMinimal, Config.MaxScriptNumLength);
                if (n < 0 || n > data.size ()) return SCRIPT_ERR_INVALID_SPLIT_RANGE;

                const uint32 position = uint32 (read_as_uint32_little (n));

                // Prepare the results in their own buffer as `data`
                // will be invalidated.
                integer n1;

                n1.resize (position);

                std::copy (data.begin () + data.size () - position, data.end (), n1.begin ());

                Stack->pop_back ();
                Stack->pop_back ();

                Stack->push_back (n1);

            } break;
            
            default: {
                if (IsInvalidBranchingOpcode (Op) && UtxoAfterGenesis && !executed) break;

                return SCRIPT_ERR_BAD_OPCODE;
            }
        }
        
        return {};
        
    }
    
}
