// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_INTERPRETER
#define GIGAMONKEY_SCRIPT_INTERPRETER

#include <gigamonkey/script/machine.hpp>
#include <gigamonkey/script/counter.hpp>
#include <data/io/wait_for_enter.hpp>

namespace Gigamonkey::Bitcoin { 
    
    // a Bitcoin script interpreter that can be advanced step-by-step.
    struct interpreter {
        bool Halt;
        ScriptError Result;
        
        machine Machine;
        
        bytes Script;
        program_counter Counter;
        
        program unread() const {
            return decompile(bytes_view{Counter.Script}.substr(Counter.Counter));
        }
        
        std::optional<redemption_document> Document;
        
        interpreter(const script& unlock, const script& lock, 
            uint32 flags = StandardScriptVerifyFlags(true, true), 
            script_config = get_standard_script_config(true, true));
        
        interpreter(const script& unlock, const script& lock, const redemption_document &doc, 
            uint32 flags = StandardScriptVerifyFlags(true, true), 
            script_config = get_standard_script_config(true, true));
        
        interpreter(program p, uint32 flags = StandardScriptVerifyFlags(true, true));
        
        void step();
        
        ScriptError run();
        
        static ScriptError step(interpreter &);
        
        static bytes find_and_delete(bytes_view script_code, bytes_view sig);
        
    private:
        
        static bool isP2SH(const program p) {
            bytes script = compile(p);
            return script.size() == 23 && script[0] == OP_HASH160 &&
                script[1] == 0x14 && script[22] == OP_EQUAL;
        }
        
        program inline full(const program unlock, const program lock) {
            if (!isP2SH(lock) || data::empty(unlock)) return (unlock << OP_CODESEPARATOR) + lock;
            return (unlock << OP_CODESEPARATOR) + (lock << OP_CODESEPARATOR) + decompile(data::reverse(unlock).first().data());
        }
        
        ScriptError check_scripts(const program unlock, const program lock, uint32 flags) {
            if (flags & SCRIPT_VERIFY_SIGPUSHONLY && !is_push(unlock)) return SCRIPT_ERR_SIG_PUSHONLY;
            if (isP2SH(lock)) {
                if (unlock.empty()) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                if (!is_push(unlock)) return SCRIPT_ERR_SIG_PUSHONLY;
            }
            return verify(full(unlock, lock), flags);
        }
        
        interpreter(std::optional<redemption_document> doc, const program unlock, const program lock, uint32 flags, script_config);
        
    };
    
    std::ostream& operator<<(std::ostream&, const interpreter&);
    
    void step_through(interpreter& m);
    
    ScriptError inline evaluate(const script& unlock, const script& lock, uint32 flags) {
        return interpreter(unlock, lock, flags).run();
    }
    
    // Evaluate script with real signature operations. 
    ScriptError inline evaluate(const script& unlock, const script& lock, const redemption_document &doc, uint32 flags) {
        return interpreter(unlock, lock, doc, flags).run();
    }
    
}

#endif
