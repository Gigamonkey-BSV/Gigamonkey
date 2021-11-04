// Copyright (c) 2021 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_MACHINE
#define GIGAMONKEY_SCRIPT_MACHINE

#include <gigamonkey/script/script.hpp>
#include <data/io/wait_for_enter.hpp>

namespace Gigamonkey::Bitcoin::interpreter { 
    
    // a Bitcoin script interpreter that can be advanced step-by-step.
    struct machine {
        
        struct state {
            bool Halt;
            bool Success;
            ScriptError Error;
            
            uint32 Flags;
        
            list<bytes> Stack;
            list<bytes> AltStack;
            
            list<bool> Exec;
            list<bool> Else;
            
            long Counter;
            
            state(uint32 flags) : Halt{false}, Success{false}, Error{SCRIPT_ERR_OK}, 
                Flags{flags}, Stack{}, AltStack{}, Exec{}, Else{}, Counter{0} {}
            
            state step(const BaseSignatureChecker&, instruction) const;
        
            state run(const BaseSignatureChecker& x, program p) const {
                state m = *this;
                while (m.Error == SCRIPT_ERR_OK && p.size() > 0) {
                    m = m.step(x, p.first());
                    p = p.rest();
                }
                
                return m;
            }
        };
        
        program Program;
        
        state State;
        transaction Transaction;
        uint32 Index;
    
        machine(program p, uint32 flags = StandardScriptVerifyFlags(true, true), uint32 index = 0, satoshi value = 0, transaction tx = {});
        
        void step() {
            if (State.Halt) return;
            State = State.step(*SignatureChecker, Program.first());
            Program = Program.rest();
            if (data::empty(Program)) State.Halt = true;
        };
        
        ~machine() {
            delete SignatureChecker;
            delete Tx;
        }
        
    private:
        BaseSignatureChecker* SignatureChecker;
        CTransaction* Tx;
    };
    
    std::ostream& operator<<(std::ostream&, const machine&);
    
    void step_through(machine& m);
    
}

#endif
