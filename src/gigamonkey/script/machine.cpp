// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/machine.hpp>
#include <gigamonkey/script/bitcoin_core.hpp>
#include <sv/script/interpreter.h>
#include <sv/script/script.h>
#include <sv/script/script_num.h>
#include <sv/policy/policy.h>
#include <sv/hash.h>
#include <boost/scoped_ptr.hpp>
#include <data/io/wait_for_enter.hpp>

// not in use but required by config.h dependency
bool fRequireStandard = true;

namespace Gigamonkey::Bitcoin::interpreter { 
    
    result verify_signature (bytes_view sig, bytes_view pub, const sighash::document &doc, uint32 flags) {

        if (flags & SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE && !secp256k1::pubkey::compressed (pub))
            return SCRIPT_ERR_NONCOMPRESSED_PUBKEY;

        else if (flags & SCRIPT_VERIFY_STRICTENC && !secp256k1::pubkey::valid (pub))
            return SCRIPT_ERR_PUBKEYTYPE;

        auto d = signature::directive (sig);
        auto raw = signature::raw (sig);

        if (!sighash::valid (d))
            return SCRIPT_ERR_SIG_HASHTYPE;

        if (sighash::has_fork_id (d) && !(flags & SCRIPT_ENABLE_SIGHASH_FORKID))
            return SCRIPT_ERR_ILLEGAL_FORKID;

        if (!sighash::has_fork_id (d) && (flags & SCRIPT_ENABLE_SIGHASH_FORKID))
            return SCRIPT_ERR_MUST_USE_FORKID;

        if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) && !signature::DER (sig))
            return SCRIPT_ERR_SIG_DER;

        if ((flags & SCRIPT_VERIFY_LOW_S) && !secp256k1::signature::normalized (raw))
            return SCRIPT_ERR_SIG_HIGH_S;

        if (signature::verify (sig, pub, doc))
            return true;

        if (flags & SCRIPT_VERIFY_NULLFAIL && sig.size () != 0)
            return SCRIPT_ERR_SIG_NULLFAIL;

        return false;
    }
    
    list<bool> make_list (const std::vector<bool> &v) {
        list<bool> l;
        for (const bool &b : v) l << b;
        return l;
    }
    
    std::ostream &operator << (std::ostream &o, const machine &i) {
        return o << "machine {\n\tProgram: " << i.State.unread ()
            << ",\n\tHalt: " << (i.Halt ? "true" : "false") 
            << ", Result: " << i.Result << ", Flags: " << i.State.Flags
            << ",\n\tStack: " << i.State.Stack << ",\n\tAltStack: "
            << i.State.AltStack << ", Exec: " << make_list (i.State.Exec)
            << ", Else: " << make_list (i.State.Else) << "}";
    }
    
    result step_through (machine &m) {
        std::cout << "begin program" << std::endl;
        while (true) {
            std::cout << m << std::endl;
            if (m.Halt) break;
            wait_for_enter ();
            m.step ();
        }
        
        std::cout << "Result " << m.Result << std::endl;
        return m.Result;
    }
    
    machine::state::state (uint32 flags, bool consensus, maybe<redemption_document> doc, const bytes &script) :
        Flags {flags}, Consensus {consensus}, Config {}, Document {doc},
        Script {script}, Counter {program_counter {Script}},
        Stack {Config.GetMaxStackMemoryUsage (Flags & SCRIPT_UTXO_AFTER_GENESIS, consensus)},
        AltStack {Stack.makeChildStack ()}, Exec {}, Else {}, OpCount {0} {}
    
    machine::machine (const script &unlock, const script &lock, const redemption_document &doc, uint32 flags) :
        machine {{doc}, decompile (unlock), decompile (lock), flags} {}
    
    machine::machine (const script &unlock, const script &lock, uint32 flags) :
        machine {{}, decompile (unlock), decompile (lock), flags} {}
    
    machine::machine (maybe<redemption_document> doc, const program unlock, const program lock, uint32 flags) :
        Halt {false}, Result {false}, State {flags, false, doc, compile (full (unlock, lock))} {
        if (auto err = pre_check_scripts (unlock, lock, flags); err) {
            Halt = true;
            Result = err;
        }
    }

    machine::machine (const program script, uint32 flags) :
        Halt {false}, Result {false}, State {flags, false, {}, compile (script)} {
    }
    
    result state_step (machine::state &x) {
        return x.step ();
    }
    
    result state_run (machine::state &x) {
        while (true) {
            auto err = x.step ();
            if (err.Error || err.Success) return err;
        }
    }
    
    result catch_all_errors (result (*fn) (machine::state &), machine::state &x) {
        try {
            return fn (x);
        } catch (scriptnum_overflow_error &err) {
            return SCRIPT_ERR_SCRIPTNUM_OVERFLOW;
        } catch (scriptnum_minencode_error &err) {
            return SCRIPT_ERR_SCRIPTNUM_MINENCODE;
        } catch (stack_overflow_error &err) {
            return SCRIPT_ERR_STACK_SIZE;
        } catch (const bsv::big_int_error &) {
            return SCRIPT_ERR_BIG_INT;
        } catch (std::out_of_range &err) {
            return SCRIPT_ERR_INVALID_STACK_OPERATION;
        } catch (...) {
            return SCRIPT_ERR_UNKNOWN_ERROR;
        }
    }
    
    void machine::step () {
        if (Halt) return;
        auto err = catch_all_errors (state_step, State);
        if (err.Error || err.Success) {
            Halt = true;
            Result = err;
        }
    }
    
    result machine::run () {
        Result = catch_all_errors (state_run, State);
        Halt = true;
        return Result;
    }
    
    bool inline IsValidMaxOpsPerScript
        (uint64_t nOpCount, const script_config &config, bool isGenesisEnabled, bool consensus) {
        return (nOpCount <= config.GetMaxOpsPerScript (isGenesisEnabled, consensus));
    }

    static bool IsOpcodeDisabled (opcodetype opcode) {
        switch (opcode) {
            case OP_2MUL:
            case OP_2DIV:
                // Disabled opcodes.
                return true;

            default:
                break;
        }

        return false;
    }
    
    bytes inline cleanup_script_code (bytes_view script_code, bytes_view sig) {
        return sighash::has_fork_id (signature::directive (sig)) ?
            bytes (script_code) :
            find_and_delete (script_code, compile (instruction::push (sig)));
    }
    
    sighash::document *add_script_code (redemption_document &doc, bytes_view script_code) {
        return new sighash::document (doc.RedeemedValue, script_code, doc.Transaction, doc.InputIndex);
    }

    uint8_t inline make_rshift_mask (size_t n) {
        static uint8_t mask[] = {0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80};
        return mask[n];
    }

    uint8_t inline make_lshift_mask (size_t n) {
        static uint8_t mask[] = {0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01};
        return mask[n];
    }

    // shift x right by n bits, implements OP_RSHIFT
    static Z RShift (const Z &x, int n) {
        Z::size_type bit_shift = n % 8;
        Z::size_type byte_shift = n / 8;

        uint8_t mask = make_rshift_mask (bit_shift);
        uint8_t overflow_mask = ~mask;

        Z result = Z::zero (x.size ());
        for (Z::size_type i = 0; i < x.size (); i++) {
            Z::size_type k = i + byte_shift;
            if (k < x.size ()) {
                uint8_t val = (x[i] & mask);
                val >>= bit_shift;
                result[k] |= val;
            }

            if (k + 1 < x.size ()) {
                uint8_t carryval = (x[i] & overflow_mask);
                carryval <<= 8 - bit_shift;
                result[k + 1] |= carryval;
            }
        }

        return result;
    }

    // shift x left by n bits, implements OP_LSHIFT
    static Z LShift (const Z &x, int n) {
        Z::size_type bit_shift = n % 8;
        Z::size_type byte_shift = n / 8;

        uint8_t mask = make_lshift_mask (bit_shift);
        uint8_t overflow_mask = ~mask;

        Z result = Z::zero (x.size ());
        for (Z::size_type index = x.size (); index > 0; index--) {
            Z::size_type i = index - 1;
            // make sure that k is always >= 0
            if (byte_shift <= i)
            {
                Z::size_type k = i - byte_shift;
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

    constexpr auto bits_per_byte {8};
    
    bytes_view get_push_data (bytes_view instruction) {
        if (instruction.size () < 1) return {};
        
        op Op = op (instruction[0]);
        
        if (!is_push_data (Op)) return {};
        
        if (Op <= OP_PUSHSIZE75) return instruction.substr (1);
        
        if (Op == OP_PUSHDATA1) return instruction.substr (2);
        
        if (Op == OP_PUSHDATA2) return instruction.substr (3);
        
        return instruction.substr (5);
    }
    
    result machine::state::step () {
    
        const bool utxo_after_genesis {(Flags & SCRIPT_UTXO_AFTER_GENESIS) != 0};
        const uint64_t maxScriptNumLength = Config.GetMaxScriptNumLength (utxo_after_genesis, Consensus);
        const bool fRequireMinimal = (Flags & SCRIPT_VERIFY_MINIMALDATA) != 0;
        
        // this will always be valid because we've already checked for invalid op codes. 
        //bytes_view next = Counter.next_instruction();
        
        if (Counter.Next == bytes_view {}) {
            if ((Flags & SCRIPT_VERIFY_CLEANSTACK) != 0 && Stack.size () != 1) return SCRIPT_ERR_CLEANSTACK;
            return true;
        }
        
        op Op = op (Counter.Next[0]);
        
        // Check opcode limits.
        //
        // Push values are not taken into consideration.
        // Note how OP_RESERVED does not count towards the opcode limit.
        if ((Op > OP_16) && !IsValidMaxOpsPerScript (++OpCount, Config, utxo_after_genesis, Consensus))
            return SCRIPT_ERR_OP_COUNT;

        if (!utxo_after_genesis && (Counter.Next.size () - 1 > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS))
            return SCRIPT_ERR_PUSH_SIZE;
        
        // whether this op code will be executed. 
        bool executed = !count (Exec.begin (), Exec.end (), false);
        if (!executed) return SCRIPT_ERR_OK;

        // Some opcodes are disabled.
        if (IsOpcodeDisabled (Op) && (!utxo_after_genesis || executed ))
            return SCRIPT_ERR_DISABLED_OPCODE;
        
        if (executed && 0 <= Op && Op <= OP_PUSHDATA4) Stack.push_back (get_push_data (Counter.Next));
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
                CScriptNum bn ((int) Op - (int) (OP_1 - 1));
                Stack.push_back (bn.getvch ());
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
                if (!(Flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) || utxo_after_genesis) {
                    // not enabled; treat as a NOP2
                    if (Flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                        return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;

                    break;
                }

                if (Stack.size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

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
                const CScriptNum nLockTime (Stack.stacktop (-1).GetElement (), fRequireMinimal, 5);

                // In the rare event that the argument may be < 0 due to
                // some arithmetic being done first, you can always use
                // 0 MAX CHECKLOCKTIMEVERIFY.
                if (nLockTime < 0) return SCRIPT_ERR_NEGATIVE_LOCKTIME;

                // Actually compare the specified lock time with the
                // transaction.
                if (bool (Document) && !Document->check_locktime (nLockTime)) return SCRIPT_ERR_UNSATISFIED_LOCKTIME;

            } break;

            case OP_CHECKSEQUENCEVERIFY: {
                if (!(Flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) || utxo_after_genesis) {
                    // not enabled; treat as a NOP3
                    if (Flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;
                    break;
                }

                if (Stack.size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                // nSequence, like nLockTime, is a 32-bit unsigned
                // integer field. See the comment in CHECKLOCKTIMEVERIFY
                // regarding 5-byte numeric operands.
                const CScriptNum nSequence (Stack.stacktop (-1).GetElement (), fRequireMinimal, 5);

                // In the rare event that the argument may be < 0 due to
                // some arithmetic being done first, you can always use
                // 0 MAX CHECKSEQUENCEVERIFY.
                if (nSequence < 0) return SCRIPT_ERR_NEGATIVE_LOCKTIME;

                // To provide for future soft-fork extensibility, if the
                // operand has the disabled lock-time flag set,
                // CHECKSEQUENCEVERIFY behaves as a NOP.
                if ((nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != script_zero ()) return SCRIPT_ERR_OK;

                // Compare the specified sequence number with the input.
                if (bool (Document) && !Document->check_sequence (nSequence))
                    return SCRIPT_ERR_UNSATISFIED_LOCKTIME;

            } break;
            
            case OP_NOP1:
            case OP_NOP4:
            case OP_NOP5:
            case OP_NOP6:
            case OP_NOP7:
            case OP_NOP8:
            case OP_NOP9:
            case OP_NOP10: {
                if (Flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
                    return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;
            } break;

            case OP_VERIFY: {
                // (true -- ) or
                // (false -- false) and return
                if (Stack.size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                if (bool (Stack.stacktop (-1).GetElement ())) Stack.pop_back ();
                else return SCRIPT_ERR_VERIFY;
                
            } break;
            
            case OP_RETURN: {
                if (utxo_after_genesis) {
                    if (Exec.empty ()) return true;
                    // Pre-Genesis OP_RETURN marks script as invalid
                } else return SCRIPT_ERR_OP_RETURN;
            } break;
                    
            //
            // Stack ops
            //
            case OP_TOALTSTACK: {
                if (Stack.size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                AltStack.moveTopToStack (Stack);
            } break;

            case OP_FROMALTSTACK: {
                if (AltStack.size () < 1) return SCRIPT_ERR_INVALID_ALTSTACK_OPERATION;
                Stack.moveTopToStack (AltStack);
            } break;

            case OP_2DROP: {
                // (x1 x2 -- )
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                    
                Stack.pop_back ();
                Stack.pop_back ();
                
            } break;

            case OP_2DUP: {
                // (x1 x2 -- x1 x2 x1 x2)
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                vector vch1 = Stack.stacktop (-2);
                vector vch2 = Stack.stacktop (-1);
                
                Stack.push_back (vch1);
                Stack.push_back (vch2);
                
            } break;

            case OP_3DUP: {
                // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                if (Stack.size () < 3) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                vector vch1 = Stack.stacktop (-3);
                vector vch2 = Stack.stacktop (-2);
                vector vch3 = Stack.stacktop (-1);
                
                Stack.push_back (vch1);
                Stack.push_back (vch2);
                Stack.push_back (vch3);
                
            } break;

            case OP_2OVER: {
                // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                if (Stack.size () < 4) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                vector vch1 = Stack.stacktop (-4);
                vector vch2 = Stack.stacktop (-3);
                Stack.push_back (vch1);
                Stack.push_back (vch2);
            } break;

            case OP_2ROT: {
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                if (Stack.size () < 6) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                vector vch1 = Stack.stacktop (-6);
                vector vch2 = Stack.stacktop (-5);
                
                Stack.erase (- 6, - 4);
                Stack.push_back (vch1);
                Stack.push_back (vch2);
                
            } break;

            case OP_2SWAP: {
                
                // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                if (Stack.size () < 4) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                Stack.swapElements (Stack.size () - 4, Stack.size () - 2);
                Stack.swapElements (Stack.size () - 3, Stack.size () - 1);
                
            } break;
            
            case OP_IFDUP: {
                // (x - 0 | x x)
                if (Stack.size () < 1)
                    return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                vector vch = Stack.stacktop (-1);

                if (bool (vch.GetElement ())) Stack.push_back (vch);
                
            } break;

            case OP_DEPTH: {
                // -- stacksize
                const CScriptNum bn (bsv::bint {Stack.size ()});
                Stack.push_back (bn.getvch ());
                
            } break;

            case OP_DROP: {
                // (x -- )
                if (Stack.size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                Stack.pop_back ();
                
            } break;

            case OP_DUP: {
                // (x -- x x)
                if (Stack.size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                vector vch = Stack.stacktop (-1);
                Stack.push_back (vch);
                
            } break;

            case OP_NIP: {
                // (x1 x2 -- x2)
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                Stack.erase (-2);
                
            } break;

            case OP_OVER: {
                // (x1 x2 -- x1 x2 x1)
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                vector vch = Stack.stacktop (-2);
                Stack.push_back (vch);
                
            } break;

            case OP_PICK:
            case OP_ROLL: {
                // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                const auto &top {Stack.stacktop (-1).GetElement ()};

                const CScriptNum sn {
                    top, fRequireMinimal,
                    maxScriptNumLength,
                    utxo_after_genesis};
                Stack.pop_back ();

                if (sn < 0 || sn >= Stack.size ())
                    return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                const auto n{sn.to_size_t_limited ()};
                vector vch = Stack.stacktop (-n - 1);

                if (Op == OP_ROLL) Stack.erase (- n - 1);

                Stack.push_back (vch);
                
            } break;

            case OP_ROT: {
                // (x1 x2 x3 -- x2 x3 x1)
                //  x2 x1 x3  after first swap
                //  x2 x3 x1  after second swap
                if (Stack.size () < 3)
                    return SCRIPT_ERR_INVALID_STACK_OPERATION;

                Stack.swapElements (Stack.size () - 3, Stack.size () - 2);
                Stack.swapElements (Stack.size () - 2, Stack.size () - 1);
                
            } break;

            case OP_SWAP: {
                // (x1 x2 -- x2 x1)
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                Stack.swapElements (Stack.size () - 2, Stack.size () - 1);
                
            } break;

            case OP_TUCK: {
                // (x1 x2 -- x2 x1 x2)
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                vector vch = Stack.stacktop (-1);
                Stack.insert (-2, vch);
                
            } break;

            case OP_SIZE: {
                // (in -- in size)
                if (Stack.size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                CScriptNum bn (bsv::bint {Stack.stacktop (-1).size ()});
                Stack.push_back (bn.getvch ());
                
            } break;

            //
            // Bitwise logic
            //
            case OP_AND:
            case OP_OR:
            case OP_XOR: {
                // (x1 x2 - out)
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                vector &vch1 = Stack.stacktop (-2);
                vector &vch2 = Stack.stacktop (-1);

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
                Stack.pop_back ();
            } break;

            case OP_INVERT: {
                // (x -- out)
                if (Stack.size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                vector &vch1 = Stack.stacktop (-1);
                // To avoid allocating, we modify vch1 in place
                for (size_t i=0; i<vch1.size (); i++) vch1[i] = ~vch1[i];
                
            } break;

            case OP_LSHIFT: {
                // (x n -- out)
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                const vector vch1 = Stack.stacktop (-2);
                const auto& top {Stack.stacktop (-1).GetElement ()};
                CScriptNum n {top, fRequireMinimal, maxScriptNumLength, utxo_after_genesis};

                if (n < 0) return SCRIPT_ERR_INVALID_NUMBER_RANGE;

                Stack.pop_back ();
                Stack.pop_back ();
                auto values {vch1.GetElement ()};

                if (n >= values.size () * bits_per_byte) fill (begin (values), end (values), 0);
                else {
                    do {
                        values = LShift (values, n.getint ());
                        n -= utxo_after_genesis
                                    ? CScriptNum {bsv::bint {INT32_MAX}}
                                    : CScriptNum {INT32_MAX};
                    } while (n > 0);
                }

                Stack.push_back (values);
            } break;

            case OP_RSHIFT: {
                // (x n -- out)
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                const vector vch1 = Stack.stacktop (-2);
                const auto& top {Stack.stacktop (-1).GetElement ()};
                CScriptNum n {top, fRequireMinimal, maxScriptNumLength, utxo_after_genesis};

                if (n < 0) return SCRIPT_ERR_INVALID_NUMBER_RANGE;

                Stack.pop_back ();
                Stack.pop_back ();
                auto values {vch1.GetElement ()};

                if (n >= values.size () * bits_per_byte) fill (begin (values), end (values), 0);
                else {
                    do {
                        values = RShift (values, n.getint ());
                        n -= utxo_after_genesis
                                    ? CScriptNum {bsv::bint {INT32_MAX}}
                                    : CScriptNum {INT32_MAX};
                    } while (n > 0);
                }
                Stack.push_back (values);
            } break;

            case OP_EQUAL:
            case OP_EQUALVERIFY: {
                // (x1 x2 - bool)
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                vector &vch1 = Stack.stacktop (-2);
                vector &vch2 = Stack.stacktop (-1);

                bool fEqual = (vch1.GetElement () == vch2.GetElement ());
                // OP_NOTEQUAL is disabled because it would be too
                // easy to say something like n != 1 and have some
                // wiseguy pass in 1 with extra zero bytes after it
                // (numerically, 0x01 == 0x0001 == 0x000001)
                // if (opcode == OP_NOTEQUAL)
                //    fEqual = !fEqual;
                Stack.pop_back ();
                Stack.pop_back ();
                Stack.push_back (Z::boolean (fEqual));
                
                if (Op == OP_EQUALVERIFY) {
                    if (fEqual) Stack.pop_back ();
                    else return SCRIPT_ERR_EQUALVERIFY;
                }
                
            } break;

            //
            // Numeric
            //
            case OP_1ADD:
            case OP_1SUB:
            case OP_NEGATE:
            case OP_ABS:
            case OP_NOT:
            case OP_0NOTEQUAL: {
                // (in -- out)
                if (Stack.size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                const auto &top {Stack.stacktop (-1).GetElement ()};
                CScriptNum bn {top, fRequireMinimal, maxScriptNumLength, utxo_after_genesis};
                
                switch (Op) {
                    case OP_1ADD:
                        bn += utxo_after_genesis ? CScriptNum {bsv::bint {1}} : script_one ();
                        break;
                    case OP_1SUB:
                        bn -= utxo_after_genesis ? CScriptNum {bsv::bint {1}} : script_one ();
                        // bn -= bnOne;
                        break;
                    case OP_NEGATE:
                        bn = -bn;
                        break;
                    case OP_ABS:
                        if (bn < script_zero ()) bn = -bn;
                        break;
                    case OP_NOT:
                        bn = (bn == script_zero ());
                        break;
                    case OP_0NOTEQUAL:
                        bn = (bn != script_zero ());
                        break;
                    default:
                        assert (!"invalid opcode");
                        break;
                }
                
                Stack.pop_back ();
                Stack.push_back (bn.getvch ());
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
                if (Stack.size () < 2) SCRIPT_ERR_INVALID_STACK_OPERATION;

                const auto& arg_2 = Stack.stacktop (-2);
                const auto& arg_1 = Stack.stacktop (-1);

                CScriptNum bn1 (arg_2.GetElement (), fRequireMinimal,
                                maxScriptNumLength,
                                utxo_after_genesis);
                
                CScriptNum bn2 (arg_1.GetElement (), fRequireMinimal,
                                maxScriptNumLength,
                                utxo_after_genesis);
                CScriptNum bn;
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
                        if (bn2 == script_zero ()) return SCRIPT_ERR_DIV_BY_ZERO;
                        bn = bn1 / bn2;
                        break;

                    case OP_MOD:
                        // divisor must not be 0
                        if (bn2 == script_zero ()) return SCRIPT_ERR_MOD_BY_ZERO;
                        bn = bn1 % bn2;
                        break;

                    case OP_BOOLAND:
                        bn = (bn1 != script_zero () && bn2 != script_zero());
                        break;
                    case OP_BOOLOR:
                        bn = (bn1 != script_zero () || bn2 != script_zero());
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
                
                Stack.pop_back ();
                Stack.pop_back ();
                Stack.push_back (bn.getvch ());

                if (Op == OP_NUMEQUALVERIFY) {
                    if (bool (Stack.stacktop (-1).GetElement ())) Stack.pop_back ();
                    else return SCRIPT_ERR_NUMEQUALVERIFY;
                }
            } break;

            case OP_WITHIN: {
                // (x min max -- out)
                if (Stack.size () < 3) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                const auto& top_3 {Stack.stacktop (-3).GetElement ()};
                const CScriptNum bn1 {
                    top_3, fRequireMinimal,
                    maxScriptNumLength,
                    utxo_after_genesis};
                    
                const auto& top_2 {Stack.stacktop (-2).GetElement ()};
                const CScriptNum bn2 {
                    top_2, fRequireMinimal,
                    maxScriptNumLength,
                    utxo_after_genesis};
                    
                const auto& top_1 {Stack.stacktop (-1).GetElement ()};
                const CScriptNum bn3 {
                    top_1, fRequireMinimal,
                    maxScriptNumLength,
                    utxo_after_genesis};
                    
                const bool fValue = (bn2 <= bn1 && bn1 < bn3);
                Stack.pop_back ();
                Stack.pop_back ();
                Stack.pop_back ();

                Stack.push_back (Z::boolean (fValue));
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
                if (Stack.size () < 1)
                    return SCRIPT_ERR_INVALID_STACK_OPERATION;

                vector &vch = Stack.stacktop (-1);

                Z vchHash;

                if (Op == OP_RIPEMD160) {
                    auto d = RIPEMD_160 (vch.GetElement ());
                    Stack.pop_back ();
                    Stack.push_back (bytes_view (d));
                } else if (Op == OP_SHA1) {
                    auto d = SHA1 (vch.GetElement ());
                    Stack.pop_back ();
                    Stack.push_back (bytes_view (d));
                } else if (Op == OP_SHA256) {
                    auto d = SHA2_256 (vch.GetElement ());
                    Stack.pop_back ();
                    Stack.push_back (bytes_view (d));
                } else if (Op == OP_HASH160) {
                    auto d = Hash160 (vch.GetElement ());
                    Stack.pop_back ();
                    Stack.push_back (bytes_view (d));
                } else if (Op == OP_HASH256) {
                    auto d = Hash256 (vch.GetElement ());
                    Stack.pop_back ();
                    Stack.push_back (bytes_view (d));
                }
            } break;
            
            // we take care of this elsewhere. 
            case OP_CODESEPARATOR: break;
            
            case OP_CHECKSIG: 
            case OP_CHECKSIGVERIFY: {
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                const Z &sig = Stack.stacktop (-2).GetElement ();
                const Z &pub = Stack.stacktop (-1).GetElement ();
                
                result r = bool (Document) ?
                    result {verify_signature
                        (sig, pub, Document->add_script_code (cleanup_script_code (Counter.script_code (), sig)), Flags)} :
                    result {true};
                
                if (r.Error) return r.Error;
                
                Stack.pop_back ();
                Stack.pop_back ();
                Stack.push_back (Z::boolean (r.Success));
                
                if (Op == OP_CHECKSIGVERIFY) {
                    if (r.Success) {
                        Stack.pop_back ();
                        return true;
                    } else return SCRIPT_ERR_CHECKSIGVERIFY;
                }
                
            } break;
            
            case OP_CHECKMULTISIG:
            case OP_CHECKMULTISIGVERIFY: {
                
                // ([sig ...] num_of_signatures [pubkey ...]
                // num_of_pubkeys -- bool)
                    
                uint64_t i = 1;
                if (Stack.size () < i) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                // initialize to max size of CScriptNum::MAXIMUM_ELEMENT_SIZE (4 bytes) 
                // because only 4 byte integers are supported by  OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY
                int64_t nKeysCountSigned =
                    CScriptNum (Stack.stacktop (-i).GetElement (), fRequireMinimal, CScriptNum::MAXIMUM_ELEMENT_SIZE).getint ();
                if (nKeysCountSigned < 0) return SCRIPT_ERR_PUBKEY_COUNT;
                
                uint64_t nKeysCount = static_cast<uint64_t> (nKeysCountSigned);
                if (nKeysCount > Config.GetMaxPubKeysPerMultiSig (utxo_after_genesis, Consensus))
                    return SCRIPT_ERR_PUBKEY_COUNT;
                
                OpCount += nKeysCount;
                if (!IsValidMaxOpsPerScript (OpCount, Config, utxo_after_genesis, Consensus))
                    return SCRIPT_ERR_OP_COUNT;
                
                uint64_t ikey = ++i;
                // ikey2 is the position of last non-signature item in
                // the stack. Top stack item = 1. With
                // SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if
                // operation fails.
                uint64_t ikey2 = nKeysCount + 2;
                i += nKeysCount;
                if (Stack.size () < i) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                int64_t nSigsCountSigned =
                    CScriptNum (Stack.stacktop (-i).GetElement (), fRequireMinimal, CScriptNum::MAXIMUM_ELEMENT_SIZE).getint ();
                    
                if (nSigsCountSigned < 0) return SCRIPT_ERR_SIG_COUNT;
                
                uint64_t nSigsCount = static_cast<uint64_t> (nSigsCountSigned);
                if (nSigsCount > nKeysCount) return SCRIPT_ERR_SIG_COUNT;
                
                uint64_t isig = ++i;
                i += nSigsCount;
                if (Stack.size () < i) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                sighash::document *doc = nullptr;
                if (bool (Document)) {
                    bytes script_code = Counter.script_code ();
                    
                    // Remove signature for pre-fork scripts
                    for (auto it = Stack.begin () + 1; it != Stack.begin () + 1 + nSigsCount; it++)
                        script_code = cleanup_script_code (script_code, it->GetElement ());
                    
                    doc = add_script_code (*Document, script_code);
                }
                
                bool fSuccess = true;
                while (fSuccess && nSigsCount > 0) {

                    const Z &sig = Stack.stacktop (-isig).GetElement ();
                    const Z &pub = Stack.stacktop (-ikey).GetElement ();
                    
                    // Note how this makes the exact order of
                    // pubkey/signature evaluation distinguishable by
                    // CHECKMULTISIG NOT if the STRICTENC flag is set.
                    // See the script_(in)valid tests for details.
                    // Check signature
                    
                    result r = (doc == nullptr) ? result {true} : result {verify_signature (sig, pub, *doc, Flags)};
                    
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
                    if (!fSuccess && (Flags & SCRIPT_VERIFY_NULLFAIL) &&
                        !ikey2 && Stack.stacktop (-1).size ()) {
                        return SCRIPT_ERR_SIG_NULLFAIL;
                    }
                    
                    if (ikey2 > 0) ikey2--;
                    
                    Stack.pop_back ();
                }
                
                // A bug causes CHECKMULTISIG to consume one extra
                // argument whose contents were not checked in any way.
                //
                // Unfortunately this is a potential source of
                // mutability, so optionally verify it is exactly equal
                // to zero prior to removing it from the stack.
                if (Stack.size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                if ((Flags & SCRIPT_VERIFY_NULLDUMMY) &&
                    Stack.stacktop (-1).size ()) return SCRIPT_ERR_SIG_NULLDUMMY;
                
                Stack.pop_back ();
                
                Stack.push_back (Z::boolean (fSuccess));
                
                if (Op == OP_CHECKMULTISIGVERIFY) {
                    if (fSuccess) {
                        Stack.pop_back ();
                        return true;
                    } else return SCRIPT_ERR_CHECKMULTISIGVERIFY;
                }
                
            } break;

            //
            // Byte string operations
            //
            case OP_CAT: {
                // (x1 x2 -- out)
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                vector &vch1 = Stack.stacktop (-2);
                // We make copy of last element on stack (vch2) so we can pop the last
                // element before appending it to the previous element.
                // If appending would be first, we could exceed stack size in the process
                // even though OP_CAT actually reduces total stack size.
                vector vch2 = Stack.stacktop (-1);

                if (!utxo_after_genesis &&
                    (vch1.size () + vch2.size () > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS))
                    return SCRIPT_ERR_PUSH_SIZE;

                Stack.pop_back ();
                vch1.append (vch2);
            } break;

            case OP_SPLIT: {
                // (in position -- x1 x2)
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                const vector &data = Stack.stacktop (-2);

                // Make sure the split point is apropriate.
                const auto& top {Stack.stacktop (-1).GetElement ()};
                const CScriptNum n {
                    top, fRequireMinimal,
                    maxScriptNumLength,
                    utxo_after_genesis};

                if (n < 0 || n > data.size ())
                    return SCRIPT_ERR_INVALID_SPLIT_RANGE;

                const auto position {n.to_size_t_limited ()};

                // Prepare the results in their own buffer as `data`
                // will be invalidated.
                Z n1;
                Z n2;

                n1.resize (position);
                n2.resize (data.size () - position);

                std::copy (data.begin (), data.begin () + position, n1.begin ());
                std::copy (data.begin () + position, data.end (), n2.begin ());

                Stack.pop_back ();
                Stack.pop_back ();

                // Replace existing stack values by the new values.
                Stack.push_back (n1);
                Stack.push_back (n2);
            } break;

            //
            // Conversion operations
            //
            case OP_NUM2BIN: {
                // (in size -- out)
                if (Stack.size () < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                const auto& arg_1 = Stack.stacktop (-1).GetElement ();
                const CScriptNum n {
                    arg_1, fRequireMinimal,
                    maxScriptNumLength,
                    utxo_after_genesis};

                if (n < 0 || n > std::numeric_limits<int32_t>::max ())
                    return SCRIPT_ERR_PUSH_SIZE;

                const auto size {n.to_size_t_limited ()};
                if (!utxo_after_genesis && (size > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS))
                    return SCRIPT_ERR_PUSH_SIZE;

                Stack.pop_back ();
                vector &rawnum = Stack.stacktop (-1);

                // Try to see if we can fit that number in the number of
                // byte requested.
                rawnum.MinimallyEncode ();
                if (rawnum.size () > size)
                    // We definitively cannot.
                    return SCRIPT_ERR_IMPOSSIBLE_ENCODING;

                // We already have an element of the right size, we
                // don't need to do anything.
                if (rawnum.size () == size) break;

                uint8_t signbit = 0x00;
                if (rawnum.size () > 0) {
                    signbit = rawnum.GetElement ().back () & 0x80;
                    rawnum[rawnum.size () - 1] &= 0x7f;
                }

                rawnum.padRight (size, signbit);
            } break;

            case OP_BIN2NUM: {
                // (in -- out)
                if (Stack.size () < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                vector &n = Stack.stacktop (-1);
                n.MinimallyEncode ();

                // The resulting number must be a valid number.
                if (!n.IsMinimallyEncoded (maxScriptNumLength)) return SCRIPT_ERR_INVALID_NUMBER_RANGE;
            } break;
            
            default: {
                ScriptError err;
                
                long count;
                maybe<bool> result = Satoshi::EvalScript (
                    Config, Consensus, 
                    Stack, CScript (Counter.Next.begin (), Counter.Next.end ()), Flags,
                    AltStack, count,
                    Exec, Else, &err);
                
                if (err) return err;
                
            }
        }

        // Size limits
        if (!utxo_after_genesis && (Stack.size () + AltStack.size () > MAX_STACK_ELEMENTS_BEFORE_GENESIS))
            return SCRIPT_ERR_STACK_SIZE;
        
        Counter = Counter.next ();
        
        return SCRIPT_ERR_OK;
        
    }
    
}
