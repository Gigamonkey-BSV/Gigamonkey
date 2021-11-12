// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/machine.hpp>
#include <gigamonkey/script/bitcoin_core.hpp>
#include <sv/config.h>
#include <sv/script/interpreter.h>
#include <sv/script/script.h>
#include <sv/script/script_num.h>
#include <sv/policy/policy.h>
#include <boost/scoped_ptr.hpp>

// not in use but required by config.h dependency
bool fRequireStandard = true;

namespace Gigamonkey::Bitcoin::interpreter { 
    
    result inline verify_signature(bytes_view sig, bytes_view pub, const sighash::document &doc, uint32 flags) {
        
        if (flags & SCRIPT_VERIFY_COMPRESSED_PUBKEYTYPE && !secp256k1::pubkey::compressed(pub)) return SCRIPT_ERR_NONCOMPRESSED_PUBKEY;
        else if (flags & SCRIPT_VERIFY_STRICTENC && !secp256k1::pubkey::valid(pub)) return SCRIPT_ERR_PUBKEYTYPE;
        
        auto d = signature::directive(sig);
        auto raw = signature::raw(sig);
        
        if (!sighash::valid(d)) return SCRIPT_ERR_SIG_HASHTYPE;
        if (sighash::has_fork_id(d) && !(flags & SCRIPT_ENABLE_SIGHASH_FORKID)) return SCRIPT_ERR_ILLEGAL_FORKID;
        if (!sighash::has_fork_id(d) && (flags & SCRIPT_ENABLE_SIGHASH_FORKID)) return SCRIPT_ERR_MUST_USE_FORKID;
        
        if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) && !signature::DER(sig)) 
            return SCRIPT_ERR_SIG_DER;
        
        if ((flags & SCRIPT_VERIFY_LOW_S) && !secp256k1::signature::normalized(raw)) return SCRIPT_ERR_SIG_HIGH_S;
        
        if (signature::verify(sig, pub, doc)) return true;
        
        if (flags & SCRIPT_VERIFY_NULLFAIL && sig.size() != 0) return SCRIPT_ERR_SIG_NULLFAIL;
        
        return false;
    }
    
    list<bool> make_list(const std::vector<bool> &v) {
        list<bool> l;
        for (const bool &b : v) l << b;
        return l;
    }
    
    std::ostream& operator<<(std::ostream& o, const machine& i) {
        return o << "machine{\n\tProgram: " << i.State.unread()
            << ",\n\tHalt: " << (i.Halt ? "true" : "false") 
            << ", Result: " << i.Result << ", Flags: " << i.State.Flags << ",\n\tStack: " << i.State.Stack << ",\n\tAltStack: " 
            << i.State.AltStack << ", Exec: " << make_list(i.State.Exec) << ", Else: " << make_list(i.State.Else) << "}";
    }
    
    void step_through(machine &m) {
        std::cout << "begin program" << std::endl;
        while(true) {
            std::cout << m << std::endl;
            if (m.Halt) break;
            wait_for_enter();
            m.step();
        }
        
        std::cout << "Result " << m.Result << std::endl;
    }
    
    result state_step(machine::state &x) {
        return x.step();
    }
    
    result state_run(machine::state &x) {
        while (true) {
            auto err = x.step(); 
            if (err.Error || err.Success) return err;
        }
    }
    
    result catch_all_errors(result (*fn)(machine::state&), machine::state &x) {
        try {
            return fn(x);
        } catch(scriptnum_overflow_error& err) {
            return SCRIPT_ERR_SCRIPTNUM_OVERFLOW;
        } catch(scriptnum_minencode_error& err) {
            return SCRIPT_ERR_SCRIPTNUM_MINENCODE;
        } catch(stack_overflow_error& err) {
            return SCRIPT_ERR_STACK_SIZE;
        } catch(const bsv::big_int_error&) {
            return SCRIPT_ERR_BIG_INT;
        } catch(std::out_of_range& err) {
            return SCRIPT_ERR_INVALID_STACK_OPERATION;
        } catch(...) {
            return SCRIPT_ERR_UNKNOWN_ERROR;
        }
    }
    
    void machine::step() {
        if (Halt) return;
        auto err = catch_all_errors(state_step, State); 
        if (err.Error || err.Success) {
            Halt = true;
            Result = err;
        }
    }
    
    result machine::run() {
        Result = catch_all_errors(state_run, State);
        Halt = true;
        return Result;
    }
    
    machine::state::state(std::optional<redemption_document> doc, program_counter pc, uint32 flags) : 
        Flags{flags}, Document{doc}, Counter{pc}, 
        Stack{GlobalConfig::GetConfig().GetMaxStackMemoryUsage(Flags & SCRIPT_UTXO_AFTER_GENESIS, false)}, 
        AltStack{Stack.makeChildStack()}, Exec{}, Else{}, OpCount{0} {}
    
    machine::machine(const script &unlock, const script &lock, const redemption_document &doc, uint32 flags) : 
        machine{{doc}, decompile(unlock), decompile(lock), flags} {}
    
    machine::machine(const script &unlock, const script &lock, uint32 flags) : 
        machine{{}, decompile(unlock), decompile(lock), flags} {}
    
    inline bool IsValidMaxOpsPerScript(uint64_t nOpCount,
                                    const CScriptConfig &config,
                                    bool isGenesisEnabled, bool consensus)
    {
        return (nOpCount <= config.GetMaxOpsPerScript(isGenesisEnabled, consensus));
    }

    static bool IsOpcodeDisabled(opcodetype opcode) {
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
    
    bytes inline cleanup_script_code(bytes_view script_code, bytes_view sig) {
        return sighash::has_fork_id(signature::directive(sig)) ? 
            bytes(script_code) : 
            find_and_delete(script_code, compile(instruction::push(sig)));
    }
    
    sighash::document *add_script_code(redemption_document &doc, bytes_view script_code) {
        return new sighash::document(doc.RedeemedValue, script_code, doc.Transaction, doc.InputIndex);
    }
    
    result machine::state::step() {
        
        const GlobalConfig& config = GlobalConfig::GetConfig();
        bool consensus = false;
    
        const bool utxo_after_genesis{(Flags & SCRIPT_UTXO_AFTER_GENESIS) != 0};
        const bool fRequireMinimal = (Flags & SCRIPT_VERIFY_MINIMALDATA) != 0;
        
        // this will always be valid because we've already checked for invalid op codes. 
        bytes_view next = Counter.next_instruction();
        if (next == bytes_view{}) return true;
        
        op Op = op(next[0]);
        
        // Check opcode limits.
        //
        // Push values are not taken into consideration.
        // Note how OP_RESERVED does not count towards the opcode limit.
        if ((Op > OP_16) && !IsValidMaxOpsPerScript(++OpCount, config, utxo_after_genesis, consensus)) return SCRIPT_ERR_OP_COUNT;

        if (!utxo_after_genesis && (next.size() - 1 > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS))
            return SCRIPT_ERR_PUSH_SIZE;
        
        // whether this op code will be executed. 
        bool executed = !count(Exec.begin(), Exec.end(), false);
        if (!executed) return SCRIPT_ERR_OK;

        // Some opcodes are disabled.
        if (IsOpcodeDisabled(Op) && (!utxo_after_genesis || executed )) return SCRIPT_ERR_DISABLED_OPCODE;
        
        if (executed && 0 <= Op && Op <= OP_PUSHDATA4) {
            Stack.push_back(next.substr(1));
            return SCRIPT_ERR_OK;
        }
        
        switch (Op) {
            
            case OP_RETURN: {
                if (utxo_after_genesis) {
                    if (Exec.empty()) return true;
                    // Pre-Genesis OP_RETURN marks script as invalid
                } else return SCRIPT_ERR_OP_RETURN;
            } break;
            
            // we take care of this elsewhere. 
            case OP_CODESEPARATOR: break;
            
            case OP_CHECKSIG: 
            case OP_CHECKSIGVERIFY: {
                if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                const element &sig = Stack.stacktop(-2).GetElement();
                const element &pub = Stack.stacktop(-1).GetElement();
                
                result r = bool(Document) ?
                    result{verify_signature(sig, pub, Document->add_script_code(cleanup_script_code(Counter.script_code(), sig)), Flags)} : 
                    result{true};
                
                if (r.Error) return r.Error;
                
                Stack.pop_back();
                Stack.pop_back();
                Stack.push_back(script_bool(r.Success));
                
                if (Op == OP_CHECKSIGVERIFY) {
                    if (r.Success) {
                        Stack.pop_back();
                        return true;
                    } else return SCRIPT_ERR_CHECKSIGVERIFY;
                }
                
            } break;
            
            case OP_CHECKMULTISIG:
            case OP_CHECKMULTISIGVERIFY: {
                
                // ([sig ...] num_of_signatures [pubkey ...]
                // num_of_pubkeys -- bool)
                    
                uint64_t i = 1;
                if (Stack.size() < i) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                // initialize to max size of CScriptNum::MAXIMUM_ELEMENT_SIZE (4 bytes) 
                // because only 4 byte integers are supported by  OP_CHECKMULTISIG / OP_CHECKMULTISIGVERIFY
                int64_t nKeysCountSigned =
                    CScriptNum(Stack.stacktop(-i).GetElement(), fRequireMinimal, CScriptNum::MAXIMUM_ELEMENT_SIZE).getint();
                if (nKeysCountSigned < 0) return SCRIPT_ERR_PUBKEY_COUNT;
                
                uint64_t nKeysCount = static_cast<uint64_t>(nKeysCountSigned);
                if (nKeysCount > config.GetMaxPubKeysPerMultiSig(utxo_after_genesis, consensus)) 
                    return SCRIPT_ERR_PUBKEY_COUNT;
                
                OpCount += nKeysCount;
                if (!IsValidMaxOpsPerScript(OpCount, config, utxo_after_genesis, consensus)) 
                    return SCRIPT_ERR_OP_COUNT;
                
                uint64_t ikey = ++i;
                // ikey2 is the position of last non-signature item in
                // the stack. Top stack item = 1. With
                // SCRIPT_VERIFY_NULLFAIL, this is used for cleanup if
                // operation fails.
                uint64_t ikey2 = nKeysCount + 2;
                i += nKeysCount;
                if (Stack.size() < i) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                int64_t nSigsCountSigned =
                    CScriptNum(Stack.stacktop(-i).GetElement(), fRequireMinimal, CScriptNum::MAXIMUM_ELEMENT_SIZE).getint();
                    
                if (nSigsCountSigned < 0) return SCRIPT_ERR_SIG_COUNT;
                
                uint64_t nSigsCount = static_cast<uint64_t>(nSigsCountSigned);
                if (nSigsCount > nKeysCount) return SCRIPT_ERR_SIG_COUNT;
                
                uint64_t isig = ++i;
                i += nSigsCount;
                if (Stack.size() < i) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                sighash::document *doc = nullptr;
                if (bool(Document)) {
                    bytes script_code = Counter.script_code();
                    
                    // Remove signature for pre-fork scripts
                    for (auto it = Stack.begin() + 1; it != Stack.begin() + 1 + nSigsCount; it++) 
                        script_code = cleanup_script_code(script_code, it->GetElement());
                    
                    doc = add_script_code(*Document, script_code);
                }
                
                bool fSuccess = true;
                while (fSuccess && nSigsCount > 0) {

                    const element &sig = Stack.stacktop(-isig).GetElement();
                    const element &pub = Stack.stacktop(-ikey).GetElement();
                    
                    // Note how this makes the exact order of
                    // pubkey/signature evaluation distinguishable by
                    // CHECKMULTISIG NOT if the STRICTENC flag is set.
                    // See the script_(in)valid tests for details.
                    // Check signature
                    
                    result r = (doc == nullptr) ? result{true} : result{verify_signature(sig, pub, *doc, Flags)};
                    
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
                        !ikey2 && Stack.stacktop(-1).size()) {
                        return SCRIPT_ERR_SIG_NULLFAIL;
                    }
                    
                    if (ikey2 > 0) ikey2--;
                    
                    Stack.pop_back();
                }
                
                // A bug causes CHECKMULTISIG to consume one extra
                // argument whose contents were not checked in any way.
                //
                // Unfortunately this is a potential source of
                // mutability, so optionally verify it is exactly equal
                // to zero prior to removing it from the stack.
                if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                if ((Flags & SCRIPT_VERIFY_NULLDUMMY) &&
                    Stack.stacktop(-1).size()) return SCRIPT_ERR_SIG_NULLDUMMY;
                
                Stack.pop_back();
                
                Stack.push_back(script_bool(fSuccess));
                
                if (Op == OP_CHECKMULTISIGVERIFY) {
                    if (fSuccess) {
                        Stack.pop_back();
                        return true;
                    } else return SCRIPT_ERR_CHECKMULTISIGVERIFY;
                }
                
            } break;
            
            case OP_CHECKLOCKTIMEVERIFY: {
                if (!(Flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY) || utxo_after_genesis) {
                    // not enabled; treat as a NOP2
                    if (Flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;
                    break;
                }

                if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

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
                const CScriptNum nLockTime(Stack.stacktop(-1).GetElement(), fRequireMinimal, 5);

                // In the rare event that the argument may be < 0 due to
                // some arithmetic being done first, you can always use
                // 0 MAX CHECKLOCKTIMEVERIFY.
                if (nLockTime < 0) return SCRIPT_ERR_NEGATIVE_LOCKTIME;

                // Actually compare the specified lock time with the
                // transaction.
                if (bool(Document) && !Document->check_locktime(nLockTime)) return SCRIPT_ERR_UNSATISFIED_LOCKTIME;

            } break;

            case OP_CHECKSEQUENCEVERIFY: {
                if (!(Flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY) || utxo_after_genesis) {
                    // not enabled; treat as a NOP3
                    if (Flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;
                    break;
                }

                if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                // nSequence, like nLockTime, is a 32-bit unsigned
                // integer field. See the comment in CHECKLOCKTIMEVERIFY
                // regarding 5-byte numeric operands.
                const CScriptNum nSequence(Stack.stacktop(-1).GetElement(), fRequireMinimal, 5);

                // In the rare event that the argument may be < 0 due to
                // some arithmetic being done first, you can always use
                // 0 MAX CHECKSEQUENCEVERIFY.
                if (nSequence < 0) return SCRIPT_ERR_NEGATIVE_LOCKTIME;

                // To provide for future soft-fork extensibility, if the
                // operand has the disabled lock-time flag set,
                // CHECKSEQUENCEVERIFY behaves as a NOP.
                if ((nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != script_zero()) return SCRIPT_ERR_OK;

                // Compare the specified sequence number with the input.
                if (bool(Document) && !Document->check_sequence(nSequence)) return SCRIPT_ERR_UNSATISFIED_LOCKTIME;

            } break;
            
            default: {
                ScriptError err;
                
                long count;
                std::optional<bool> result = EvalScript(
                    config, consensus, 
                    Stack, CScript(next.begin(), next.end()), Flags, 
                    AltStack, count,
                    Exec, Else, &err);
                
                if (err) return err;
                
            }
        }
        
        return SCRIPT_ERR_OK;
        
    }
    
}
