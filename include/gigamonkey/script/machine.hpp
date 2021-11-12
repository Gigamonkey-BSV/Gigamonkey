// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_MACHINE
#define GIGAMONKEY_SCRIPT_MACHINE

#include <gigamonkey/script/script.hpp>
#include <gigamonkey/script/stack.hpp>
#include <gigamonkey/script/counter.hpp>
#include <gigamonkey/script/config.hpp>
#include <data/io/wait_for_enter.hpp>

namespace Gigamonkey::Bitcoin::interpreter { 
    
    // a Bitcoin script interpreter that can be advanced step-by-step.
    struct machine {
        bool Halt;
        result Result;
        
        struct state {
            uint32 Flags;
            bool Consensus;
            
            script_config Config;
            
            std::optional<redemption_document> Document;
            
            program_counter Counter;
            
            LimitedStack<element> Stack;
            LimitedStack<element> AltStack;
            
            std::vector<bool> Exec;
            std::vector<bool> Else;
            
            long OpCount;
            
            state(uint32 flags, bool consensus, std::optional<redemption_document> doc, program_counter pc);
            
            program unread() const {
                return decompile(bytes_view{Counter.Script}.substr(Counter.Counter));
            }
            
            result step();
        };
        
        state State;
    
        machine(const script& unlock, const script& lock, uint32 flags = StandardScriptVerifyFlags(true, true));
    
        machine(const script& unlock, const script& lock, const redemption_document &doc, uint32 flags = StandardScriptVerifyFlags(true, true));
    
        machine(program p, uint32 flags = StandardScriptVerifyFlags(true, true));
        
        void step();
        
        result run();
        
    private:
        
        program inline full(const program unlock, const program lock) {
            return unlock << OP_CODESEPARATOR << lock;
        }
        
        ScriptError check_scripts(const program unlock, const program lock, uint32 flags) {
            if (flags & SCRIPT_VERIFY_SIGPUSHONLY && !is_push(unlock)) return SCRIPT_ERR_SIG_PUSHONLY;
            return verify(unlock << OP_CODESEPARATOR << lock, flags);
        }
        
        machine(std::optional<redemption_document> doc, const program unlock, const program lock, uint32 flags) : 
            Halt{false}, Result{false}, State{flags, false, doc, program_counter{compile(full(unlock, lock))}} {
            if (auto err = check_scripts(unlock, lock, flags); err) {
                Halt = true;
                Result = err;
            }
        }
        
        static const element &script_false() {
            static element False(0);
            return False;
        }
    
        static const element &script_true() {
            static element True(1, 1);
            return True;
        }
    
        static const element &script_bool(bool b) {
            return b ? script_true() : script_false();
        }
        
        static const CScriptNum &script_zero() {
            static CScriptNum Zero(0);
            return Zero;
        }
        
        static const CScriptNum &script_one() {
            static CScriptNum One(1);
            return One;
        }
    };
    
    std::ostream& operator<<(std::ostream&, const machine&);
    
    void step_through(machine& m);
    
}

namespace Gigamonkey::Bitcoin { 
    
    result inline evaluate(const script& unlock, const script& lock, uint32 flags) {
        return interpreter::machine(unlock, lock, flags).run();
    }
    
    // Evaluate script with real signature operations. 
    result inline evaluate(const script& unlock, const script& lock, const redemption_document &doc, uint32 flags) {
        return interpreter::machine(unlock, lock, doc, flags).run();
    }
    
}

#endif
