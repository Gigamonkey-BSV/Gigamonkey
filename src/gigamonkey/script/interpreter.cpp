// Copyright (c) 2019-2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#include <gigamonkey/script/interpreter.hpp>
#include <gigamonkey/script/bitcoin_core.hpp>
#include <gigamonkey/wif.hpp>
#include <sv/script/script.h>
#include <sv/script/script_num.h>
#include <sv/policy/policy.h>
#include <sv/hash.h>
#include <boost/scoped_ptr.hpp>

// not in use but required by config.h dependency
bool fRequireStandard = true;

namespace Gigamonkey::Bitcoin { 
    
    ScriptError inline verify_signature(bytes_view sig, bytes_view pub, const sighash::document &doc, uint32 flags) {
        
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
        
        if (signature::verify(sig, pub, doc)) return SCRIPT_ERR_OK;
        
        if (flags & SCRIPT_VERIFY_NULLFAIL && sig.size() != 0) return SCRIPT_ERR_SIG_NULLFAIL;
        
        return SCRIPT_ERR_CHECKSIGVERIFY;
    }
    
    list<bool> make_list(const std::vector<bool> &v) {
        list<bool> l;
        for (const bool &b : v) l << b;
        return l;
    }
    
    std::ostream &write_stack(std::ostream &o, const machine::LimitedStack& stack) {
        o << "{";
        if (stack.size() > 0) {
            auto i = stack.begin();
            auto e = stack.end();
            while(true) {
                o << i->GetElement();
                i++;
                if (i == e) break;
                o << ", ";
            }
        }
        return o << "}";
    }
    
    std::ostream& operator<<(std::ostream& o, const interpreter& i) {
        return write_stack(write_stack(o << "interpreter{\n\tProgram: " << i.unread()
            << ",\n\tHalt: " << (i.Halt ? "true" : "false") 
            << ", Result: " << i.Result << ", Flags: " << i.Machine.Flags << ",\n\tStack: ", i.Machine.Stack) 
                << ",\n\tAltStack: ", i.Machine.AltStack) << ", Exec: " << make_list(i.Machine.Exec) << ", Else: " 
                << make_list(i.Machine.Else) << "}";
    }
    
    void step_through(interpreter &m) {
        while(true) {
            if (m.Halt) break;
            wait_for_enter();
            m.step();
        }
    }
    
    interpreter::interpreter(const script &unlock, const script &lock, const redemption_document &doc, uint32 flags, script_config config) : 
        interpreter{{doc}, decompile(unlock), decompile(lock), flags, config} {}
    
    interpreter::interpreter(const script &unlock, const script &lock, uint32 flags, script_config config) : 
        interpreter{{}, decompile(unlock), decompile(lock), flags, config} {}
    
    interpreter::interpreter(std::optional<redemption_document> doc, const program unlock, const program lock, uint32 flags, script_config config) : 
        Halt{false}, Result{SCRIPT_ERR_OK}, Machine{machine::make(flags, config)}, Script{compile(full(unlock, lock))}, Document{doc}, Counter{program_counter{Script}} {
        if (auto err = check_scripts(unlock, lock, flags); err) {
            Halt = true;
            Result = err;
        }
    }
    
    ScriptError state_step(interpreter &x) {
        return interpreter::step(x);
    }
    
    ScriptError state_run(interpreter &x) {
        
        if (x.Script.size() > x.Machine.Config.MaxScriptSize) return SCRIPT_ERR_SCRIPT_SIZE;
        
        while (!x.Halt) {
            auto err = interpreter::step(x); 
            if (err != SCRIPT_ERR_OK) return err;
        }
        
        return SCRIPT_ERR_OK;
    }
    
    ScriptError catch_all_errors(ScriptError (*fn)(interpreter&), interpreter &x) {
        try {
            return fn(x);
        } catch(scriptnum_overflow_error& err) {
            return SCRIPT_ERR_SCRIPTNUM_OVERFLOW;
        } catch(scriptnum_minencode_error& err) {
            return SCRIPT_ERR_SCRIPTNUM_MINENCODE;
        } catch(const bsv::big_int_error&) {
            return SCRIPT_ERR_BIG_INT;
        } catch(std::out_of_range& err) {
            return SCRIPT_ERR_INVALID_STACK_OPERATION;
        } catch(...) {
            return SCRIPT_ERR_UNKNOWN_ERROR;
        }
    }
    
    void interpreter::step() {
        if (Halt) return;
        Result = catch_all_errors(state_step, *this); 
        if (Result != SCRIPT_ERR_OK) {
            Halt = true;
        }
    }
    
    ScriptError interpreter::run() {
        Result = catch_all_errors(state_run, *this);
        Halt = true;
        return Result;
    }
    
    bool inline IsValidMaxOpsPerScript(
        uint64_t nOpCount, const CScriptConfig &config) {
        return (nOpCount <= config.MaxOpsPerScript);
    }

    bool IsOpcodeDisabled(opcodetype opcode) {
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

    bool IsInvalidBranchingOpcode(opcodetype opcode) {
        return opcode == OP_VERNOTIF || opcode == OP_VERIF;
    }
    
    bytes inline cleanup_script_code(bytes_view script_code, bytes_view sig) {
        return sighash::has_fork_id(signature::directive(sig)) ? 
            bytes(script_code) : interpreter::find_and_delete(script_code, compile(instruction::push(sig)));
    }
    
    sighash::document *add_script_code(redemption_document &doc, bytes_view script_code) {
        return new sighash::document(doc.RedeemedValue, script_code, doc.Transaction, doc.InputIndex);
    }
    
    bytes_view get_push_data(bytes_view instruction) {
        if (instruction.size() < 1) return {};
        
        op Op = op(instruction[0]);
        
        if (!is_push_data(Op)) return {};
        
        if (Op <= OP_PUSHSIZE75) return instruction.substr(1);
        
        if (Op == OP_PUSHDATA1) return instruction.substr(2);
        
        if (Op == OP_PUSHDATA2) return instruction.substr(3);
        
        return instruction.substr(5);
    }
    
    using LimitedStack = machine::LimitedStack;
    using LimitedVector = machine::LimitedVector;
    
    ScriptError interpreter::step(interpreter &m) {
        
        auto &Counter = m.Counter;
        auto &Flags = m.Machine.Flags;
        auto &Stack = m.Machine.Stack;
        auto &AltStack = m.Machine.AltStack;
        auto &OpCount = m.Machine.OpCount;
        auto &Config = m.Machine.Config;
        auto &utxo_after_genesis = m.Machine.UTXOAfterGenesis;
        auto &Exec = m.Machine.Exec;
        auto &Else = m.Machine.Else;
        auto &fRequireMinimal = m.Machine.RequireMinimal;
        
        using element = machine::element;
        
        if (Counter.Next == bytes_view{}) {
            m.Halt = true;
            return m.Machine.halt();
        }
        
        op Op = op(Counter.Next[0]);
        
        // Check opcode limits.
        //
        // Push values are not taken into consideration.
        // Note how OP_RESERVED does not count towards the opcode limit.
        if ((Op > OP_16) && !IsValidMaxOpsPerScript(++OpCount, Config)) return SCRIPT_ERR_OP_COUNT;

        if (!utxo_after_genesis && (m.Counter.Next.size() - 1 > MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS))
            return SCRIPT_ERR_PUSH_SIZE;
        
        // whether this op code will be executed. 
        bool executed = !count(Exec.begin(), Exec.end(), false);
        if (!executed) return SCRIPT_ERR_OK;

        // Some opcodes are disabled.
        if (IsOpcodeDisabled(Op) && (!utxo_after_genesis || executed )) return SCRIPT_ERR_DISABLED_OPCODE;
        
        ScriptError err;
        
        if (executed && 0 <= Op && Op <= OP_PUSHDATA4) {
            m.Machine.push(get_push_data(Counter.Next));
        } else switch (Op) {
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
                m.Machine.push(CScriptNum((int)Op - (int)(OP_1 - 1)));
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
                err = m.Machine.check_locktime_verify(bool(m.Document) ? &m.Document.value(): nullptr);
            } break;

            case OP_CHECKSEQUENCEVERIFY: {
                err = m.Machine.check_sequence_verify(bool(m.Document) ? &m.Document.value(): nullptr);
            } break;
            
            case OP_NOP1:
            case OP_NOP4:
            case OP_NOP5:
            case OP_NOP6:
            case OP_NOP7:
            case OP_NOP8:
            case OP_NOP9:
            case OP_NOP10: {
                if (Flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS) return SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS;
            } break;
            
            case OP_IF:
            case OP_NOTIF: {
                // <expression> if [statements] [else [statements]]
                // endif
                bool fValue = false;
                if (executed) {
                    if (Stack.size() < 1) SCRIPT_ERR_UNBALANCED_CONDITIONAL;
                    
                    LimitedVector &vch = Stack.stacktop(-1);
                    if (Flags & SCRIPT_VERIFY_MINIMALIF) {
                        if (vch.size() > 1) return SCRIPT_ERR_MINIMALIF;
                        
                        if (vch.size() == 1 && vch[0] != 1) return SCRIPT_ERR_MINIMALIF;
                    }
                    
                    fValue = bool(vch.GetElement());
                    if (Op == OP_NOTIF) fValue = !fValue;
                    Stack.pop_back();
                }
                
                Exec.push_back(fValue);
                Else.push_back(false);
            } break;

            case OP_ELSE: {
                // Only one ELSE is allowed in IF after genesis.
                if (Exec.empty() || (Else.back() && utxo_after_genesis)) return SCRIPT_ERR_UNBALANCED_CONDITIONAL;
                
                Exec.back() = !Exec.back();
                Else.back() = true;
            } break;

            case OP_ENDIF: {
                if (Exec.empty()) return SCRIPT_ERR_UNBALANCED_CONDITIONAL;
                
                Exec.pop_back();
                Else.pop_back();
            } break;

            case OP_VERIFY: {
                err = m.Machine.verify();
            } break;
            
            case OP_RETURN: {
                if (utxo_after_genesis) {
                    if (Exec.empty()) return SCRIPT_ERR_OK;
                    // Pre-Genesis OP_RETURN marks script as invalid
                } else return SCRIPT_ERR_OP_RETURN;
            } break;
            
            //
            // Stack ops
            //
            case OP_TOALTSTACK: {
                if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                AltStack.moveTopToStack(Stack);
            } break;
            
            case OP_FROMALTSTACK: {
                if (AltStack.size() < 1) return SCRIPT_ERR_INVALID_ALTSTACK_OPERATION;
                Stack.moveTopToStack(AltStack);
            } break;

            case OP_2DROP: {
                // (x1 x2 -- )
                if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                    
                Stack.pop_back();
                Stack.pop_back();
                
            } break;

            case OP_2DUP: {
                // (x1 x2 -- x1 x2 x1 x2)
                if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                LimitedVector vch1 = Stack.stacktop(-2);
                LimitedVector vch2 = Stack.stacktop(-1);
                
                Stack.push_back(vch1);
                Stack.push_back(vch2);
                
            } break;

            case OP_3DUP: {
                // (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
                if (Stack.size() < 3) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                LimitedVector vch1 = Stack.stacktop(-3);
                LimitedVector vch2 = Stack.stacktop(-2);
                LimitedVector vch3 = Stack.stacktop(-1);
                
                Stack.push_back(vch1);
                Stack.push_back(vch2);
                Stack.push_back(vch3);
                
            } break;

            case OP_2OVER: {
                // (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                if (Stack.size() < 4) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                LimitedVector vch1 = Stack.stacktop(-4);
                LimitedVector vch2 = Stack.stacktop(-3);
                Stack.push_back(vch1);
                Stack.push_back(vch2);
            } break;

            case OP_2ROT: {
                // (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                if (Stack.size() < 6) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                LimitedVector vch1 = Stack.stacktop(-6);
                LimitedVector vch2 = Stack.stacktop(-5);
                
                Stack.erase(- 6, - 4);
                Stack.push_back(vch1);
                Stack.push_back(vch2);
                
            } break;

            case OP_2SWAP: {
                
                // (x1 x2 x3 x4 -- x3 x4 x1 x2)
                if (Stack.size() < 4) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                Stack.swapElements(Stack.size() - 4, Stack.size() - 2);
                Stack.swapElements(Stack.size() - 3, Stack.size() - 1);
                
            } break;
            
            case OP_IFDUP: {
                // (x - 0 | x x)
                if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                LimitedVector vch = Stack.stacktop(-1);
                if (bool(vch.GetElement())) {
                    Stack.push_back(vch);
                }
                
            } break;

            case OP_DEPTH: {
                // -- stacksize
                Stack.push_back(CScriptNum(bsv::bint{Stack.size()}));
                
            } break;

            case OP_DROP: {
                err = m.Machine.drop();
            } break;

            case OP_DUP: {
                // (x -- x x)
                if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                LimitedVector vch = Stack.stacktop(-1);
                Stack.push_back(vch);
                
            } break;

            case OP_NIP: {
                // (x1 x2 -- x2)
                if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                Stack.erase(-2);
                
            } break;

            case OP_OVER: {
                // (x1 x2 -- x1 x2 x1)
                if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                LimitedVector vch = Stack.stacktop(-2);
                Stack.push_back(vch);
                
            } break;

            case OP_PICK:
            case OP_ROLL: {
                // (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                // (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                const auto& top{Stack.stacktop(-1).GetElement()};
                const CScriptNum sn{
                    top, fRequireMinimal,
                    Config.MaxScriptNumLength,
                    utxo_after_genesis};
                Stack.pop_back();
                if(sn < 0 || sn >= Stack.size()) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                const auto n{sn.to_size_t_limited()};
                LimitedVector vch = Stack.stacktop(-n - 1);

                if (Op == OP_ROLL) {
                    Stack.erase(- n - 1);
                }
                Stack.push_back(vch);
                
            } break;
            
            case OP_ROT: {
                // (x1 x2 x3 -- x2 x3 x1)
                //  x2 x1 x3  after first swap
                //  x2 x3 x1  after second swap
                if (Stack.size() < 3) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                Stack.swapElements(Stack.size() - 3, Stack.size() - 2);
                Stack.swapElements(Stack.size() - 2, Stack.size() - 1);
                
            } break;
            
            case OP_SWAP: {
                // (x1 x2 -- x2 x1)
                if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                Stack.swapElements(Stack.size() - 2, Stack.size() - 1);
                
            } break;
            
            case OP_TUCK: {
                // (x1 x2 -- x2 x1 x2)
                if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                LimitedVector vch = Stack.stacktop(-1);
                Stack.insert(-2, vch);
                
            } break;
            
            case OP_SIZE: {
                // (in -- in size)
                if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                CScriptNum bn(bsv::bint{Stack.stacktop(-1).size()});
                Stack.push_back(bn);
                
            } break;
            
            //
            // Bitwise logic
            //
            case OP_AND:
            case OP_OR:
            case OP_XOR: {
                // (x1 x2 - out)
                if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                LimitedVector &vch1 = Stack.stacktop(-2);
                LimitedVector &vch2 = Stack.stacktop(-1);

                // Inputs must be the same size
                if (vch1.size() != vch2.size()) return SCRIPT_ERR_INVALID_OPERAND_SIZE;

                // To avoid allocating, we modify vch1 in place.
                switch (Op) {
                    case OP_AND: for (size_t i = 0; i < vch1.size(); ++i) vch1[i] &= vch2[i];
                        break;
                        
                    case OP_OR: for (size_t i = 0; i < vch1.size(); ++i) vch1[i] |= vch2[i];
                        break;
                        
                    case OP_XOR: for (size_t i = 0; i < vch1.size(); ++i) vch1[i] ^= vch2[i];
                        break;
                        
                    default:
                        break;
                }

                // And pop vch2.
                Stack.pop_back();
            } break;

            case OP_INVERT: {
                // (x -- out)
                if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                LimitedVector &vch1 = Stack.stacktop(-1);
                // To avoid allocating, we modify vch1 in place
                for(size_t i=0; i<vch1.size(); i++) vch1[i] = ~vch1[i];
                
            } break;
            
            case OP_LSHIFT: {
                err = m.Machine.left_shift();
            } break;
            
            case OP_RSHIFT: {
                err = m.Machine.right_shift();
            } break;

            case OP_EQUAL:
                err = m.Machine.equal();
            case OP_EQUALVERIFY: {
                err = m.Machine.equal_verify();
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
                if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                const auto &top{Stack.stacktop(-1).GetElement()};
                CScriptNum bn{top, fRequireMinimal, Config.MaxScriptNumLength, utxo_after_genesis};
                
                switch (Op) {
                    case OP_1ADD:
                        bn += utxo_after_genesis ? CScriptNum{bsv::bint{1}} : machine::script_one();
                        break;
                    case OP_1SUB:
                        bn -= utxo_after_genesis ? CScriptNum{bsv::bint{1}} : machine::script_one();
                        // bn -= bnOne;
                        break;
                    case OP_NEGATE:
                        bn = -bn;
                        break;
                    case OP_ABS:
                        if (bn < machine::script_zero()) bn = -bn;
                        break;
                    case OP_NOT:
                        bn = (bn == machine::script_zero());
                        break;
                    case OP_0NOTEQUAL:
                        bn = (bn != machine::script_zero());
                        break;
                    default:
                        assert(!"invalid opcode");
                        break;
                }
                
                Stack.pop_back();
                Stack.push_back(bn);
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
                if (Stack.size() < 2) SCRIPT_ERR_INVALID_STACK_OPERATION;

                const auto& arg_2 = Stack.stacktop(-2);                        
                const auto& arg_1 = Stack.stacktop(-1);

                CScriptNum bn1(arg_2.GetElement(), fRequireMinimal,
                                Config.MaxScriptNumLength,
                                utxo_after_genesis);
                
                CScriptNum bn2(arg_1.GetElement(), fRequireMinimal,
                                Config.MaxScriptNumLength,
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
                        if (bn2 == machine::script_zero()) return SCRIPT_ERR_DIV_BY_ZERO;
                        bn = bn1 / bn2;
                        break;

                    case OP_MOD:
                        // divisor must not be 0
                        if (bn2 == machine::script_zero()) return SCRIPT_ERR_MOD_BY_ZERO;
                        bn = bn1 % bn2;
                        break;

                    case OP_BOOLAND:
                        bn = (bn1 != machine::script_zero() && bn2 != machine::script_zero());
                        break;
                    case OP_BOOLOR:
                        bn = (bn1 != machine::script_zero() || bn2 != machine::script_zero());
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
                        assert(!"invalid opcode");
                        break;
                }
                
                Stack.pop_back();
                Stack.pop_back();
                Stack.push_back(bn);

                if (Op == OP_NUMEQUALVERIFY) {
                    if (bool(Stack.stacktop(-1).GetElement())) Stack.pop_back();
                    else return SCRIPT_ERR_NUMEQUALVERIFY;
                }
            } break;

            case OP_WITHIN: {
                // (x min max -- out)
                if (Stack.size() < 3) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                const auto& top_3{Stack.stacktop(-3).GetElement()};
                const CScriptNum bn1{
                    top_3, fRequireMinimal,
                    Config.MaxScriptNumLength,
                    utxo_after_genesis};
                    
                const auto& top_2{Stack.stacktop(-2).GetElement()};
                const CScriptNum bn2{
                    top_2, fRequireMinimal,
                    Config.MaxScriptNumLength,
                    utxo_after_genesis};
                    
                const auto& top_1{Stack.stacktop(-1).GetElement()};
                const CScriptNum bn3{
                    top_1, fRequireMinimal,
                    Config.MaxScriptNumLength,
                    utxo_after_genesis};
                    
                const bool fValue = (bn2 <= bn1 && bn1 < bn3);
                Stack.pop_back();
                Stack.pop_back();
                Stack.pop_back();

                Stack.push_back(fValue ? machine::script_true() : machine::script_false());
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
                if (Stack.size() < 1) return SCRIPT_ERR_INVALID_STACK_OPERATION;

                LimitedVector &vch = Stack.stacktop(-1);
                element vchHash((Op == OP_RIPEMD160 ||
                                    Op == OP_SHA1 ||
                                    Op == OP_HASH160) ? 20 : 32);
                if (Op == OP_RIPEMD160) {
                    CRIPEMD160()
                        .Write(vch.GetElement().data(), vch.size())
                        .Finalize(vchHash.data());
                } else if (Op == OP_SHA1) {
                    CSHA1()
                        .Write(vch.GetElement().data(), vch.size())
                        .Finalize(vchHash.data());
                } else if (Op == OP_SHA256) {
                    CSHA256()
                        .Write(vch.GetElement().data(), vch.size())
                        .Finalize(vchHash.data());
                } else if (Op == OP_HASH160) {
                    CHash160()
                        .Write(vch.GetElement().data(), vch.size())
                        .Finalize(vchHash.data());
                } else if (Op == OP_HASH256) {
                    CHash256()
                        .Write(vch.GetElement().data(), vch.size())
                        .Finalize(vchHash.data());
                }
                Stack.pop_back();
                Stack.push_back(vchHash);
            } break;
            
            // we take care of this elsewhere. 
            case OP_CODESEPARATOR: break;
            
            case OP_CHECKSIG: 
            case OP_CHECKSIGVERIFY: {
                if (Stack.size() < 2) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                
                const element &sig = Stack.stacktop(-2).GetElement();
                const element &pub = Stack.stacktop(-1).GetElement();
                
                ScriptError r = bool(m.Document) ?
                    verify_signature(sig, pub, m.Document->add_script_code(cleanup_script_code(Counter.script_code(), sig)), Flags) : 
                    SCRIPT_ERR_OK;
                
                if (r) return r;
                
                Stack.pop_back();
                Stack.pop_back();
                Stack.push_back(machine::script_bool(r == SCRIPT_ERR_OK));
                
                if (Op == OP_CHECKSIGVERIFY) {
                    if (r == SCRIPT_ERR_OK) {
                        Stack.pop_back();
                        return SCRIPT_ERR_OK;
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
                if (nKeysCount > Config.MaxPubKeysPerMultiSig) 
                    return SCRIPT_ERR_PUBKEY_COUNT;
                
                OpCount += nKeysCount;
                if (!IsValidMaxOpsPerScript(OpCount, Config)) 
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
                if (bool(m.Document)) {
                    bytes script_code = Counter.script_code();
                    
                    // Remove signature for pre-fork scripts
                    for (auto it = Stack.begin() + 1; it != Stack.begin() + 1 + nSigsCount; it++) 
                        script_code = cleanup_script_code(script_code, it->GetElement());
                    
                    doc = add_script_code(*m.Document, script_code);
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
                    
                    ScriptError r = (doc == nullptr) ? SCRIPT_ERR_OK : verify_signature(sig, pub, *doc, Flags);
                    
                    if (r && r != SCRIPT_ERR_CHECKSIGVERIFY) return r;
                    
                    if (!r) {
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
                
                Stack.push_back(machine::script_bool(fSuccess));
                
                if (Op == OP_CHECKMULTISIGVERIFY) {
                    if (fSuccess) {
                        Stack.pop_back();
                        return SCRIPT_ERR_OK;
                    } else return SCRIPT_ERR_CHECKMULTISIGVERIFY;
                }
                
            } break;

            //
            // Byte string operations
            //
            case OP_CAT: {
                err = m.Machine.cat();
            } break; 
            
            case OP_SPLIT: {
                err = m.Machine.split();
            } break; 

            //
            // Conversion operations
            //
            case OP_NUM2BIN: {
                err = m.Machine.num_2_bin();
            } break; 
            
            case OP_BIN2NUM: {
                err = m.Machine.bin_2_num();
            } break; 
            
            default: {
                
                if (IsInvalidBranchingOpcode(Op) && utxo_after_genesis && !executed) break;
                
                err = SCRIPT_ERR_BAD_OPCODE;
                
            }
        }
                
        if (err) return err;

        // Size limits
        if (!utxo_after_genesis && (Stack.size() + AltStack.size() > MAX_STACK_ELEMENTS_BEFORE_GENESIS))
            return SCRIPT_ERR_STACK_SIZE;
        
        Counter = Counter.next();
        
        return SCRIPT_ERR_OK;
        
    }
    
}
