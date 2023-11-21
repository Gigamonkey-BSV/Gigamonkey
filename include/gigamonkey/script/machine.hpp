// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_MACHINE
#define GIGAMONKEY_SCRIPT_MACHINE

#include <gigamonkey/script/script.hpp>
#include <gigamonkey/script/stack.hpp>
#include <gigamonkey/script/counter.hpp>
#include <gigamonkey/script/config.hpp>

namespace Gigamonkey::Bitcoin::interpreter { 

    using stack = LimitedStack<Z>;
    using vector = LimitedVector<Z>;
    
    // a Bitcoin script interpreter that can be advanced step-by-step.
    struct machine {
        bool Halt;
        result Result;
        
        struct state {
            uint32 Flags;
            bool Consensus;
            
            script_config Config;
            
            maybe<redemption_document> Document;
            
            bytes Script;
            program_counter Counter;
            
            stack Stack;
            stack AltStack;
            
            cross<bool> Exec;
            cross<bool> Else;
            
            long OpCount;
            
            state (uint32 flags, bool consensus, maybe<redemption_document> doc, const bytes &script);
            
            program unread () const {
                return decompile (bytes_view {Counter.Script}.substr (Counter.Counter));
            }
            
            result step ();
        };
        
        state State;
    
        machine (const script &unlock, const script &lock, uint32 flags = StandardScriptVerifyFlags (true, true));
    
        machine (const script &unlock, const script &lock,
            const redemption_document &doc, uint32 flags = StandardScriptVerifyFlags (true, true));
    
        machine (program p, uint32 flags = StandardScriptVerifyFlags (true, true));
        
        void step ();
        
        result run ();
        
    private:

        static bool isP2SH (const program p) {
            bytes script = compile (p);
            return script.size () == 23 && script[0] == OP_HASH160 &&
                script[1] == 0x14 && script[22] == OP_EQUAL;
        }
        
        program inline full (const program unlock, const program lock) {
            if (!isP2SH (lock) || data::empty (unlock)) return (unlock << OP_CODESEPARATOR) + lock;
            return (unlock << OP_CODESEPARATOR) + (lock << OP_CODESEPARATOR) + decompile (data::reverse (unlock).first ().data ());
        }
        
        ScriptError check_scripts (const program unlock, const program lock, uint32 flags) {
            if (flags & SCRIPT_VERIFY_SIGPUSHONLY && !is_push (unlock)) return SCRIPT_ERR_SIG_PUSHONLY;

            if (isP2SH (lock)) {
                if (unlock.empty ()) return SCRIPT_ERR_INVALID_STACK_OPERATION;
                if (!is_push (unlock)) return SCRIPT_ERR_SIG_PUSHONLY;
            }

            return verify (full (unlock, lock), flags);
        }
        
        machine (maybe<redemption_document> doc, const program unlock, const program lock, uint32 flags);
        
        static const CScriptNum &script_zero () {
            static CScriptNum Zero (0);
            return Zero;
        }
        
        static const CScriptNum &script_one () {
            static CScriptNum One (1);
            return One;
        }
    };
    
    std::ostream &operator << (std::ostream &, const machine &);
    
    void step_through (machine &m);
    
}

namespace Gigamonkey::Bitcoin { 
    
    result inline evaluate (const script &unlock, const script& lock, uint32 flags) {
        return interpreter::machine (unlock, lock, flags).run ();
    }
    
    // Evaluate script with real signature operations. 
    result inline evaluate (const script &unlock, const script& lock, const redemption_document &doc, uint32 flags) {
        return interpreter::machine (unlock, lock, doc, flags).run ();
    }
    
}

namespace Gigamonkey::Bitcoin::interpreter {

}

#endif
