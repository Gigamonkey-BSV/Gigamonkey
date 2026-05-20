// Copyright (c) 2021-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_MACHINE
#define GIGAMONKEY_SCRIPT_MACHINE

#include <gigamonkey/script.hpp>
#include <gigamonkey/script/stack.hpp>
#include <gigamonkey/script/counter.hpp>
#include <gigamonkey/script/config.hpp>

namespace Gigamonkey::Bitcoin {

    struct conditional {
        // add an if branch to the stack.
        void push (bool);

        // remove an if branch to the stack.
        Error pop ();

        // else encountered.
        Error flip ();

        bool executed () const;

        // whether we are in a branch
        operator bool () const;

        // before genesis, multiple OP_ELSEs are allowed.
        conditional (bool utxo_after_genesis);

        friend std::ostream &operator << (std::ostream &, const conditional &);

    private:
        struct branch {
            bool Exec;
            bool Else;
        };

        bool UtxoAfterGenesis;
        cross<branch> Branch {};
    };

    // a Bitcoin script interpreter that can be advanced step-by-step.
    struct machine {

        script_config Config;
            
        maybe<redemption_document> Document;
            
        ptr<two_stack> Stacks;

        conditional Conditional;

        long OpCount;

        int LastCodeSeparator {-1};

        bool increment_operation ();
        uint64 max_pubkeys_per_multisig () const;

        Error step (const program_counter &Counter);

        machine (maybe<redemption_document> doc = {}, const script_config &conf = {}):
            machine (enable_genesis_stack (conf.Flags) ?
                std::static_pointer_cast<two_stack> (std::make_shared<limited_two_stack<true>> (conf.MaxStackMemoryUsage)) :
                std::static_pointer_cast<two_stack> (std::make_shared<limited_two_stack<false>> ()), doc, conf) {}

        machine (ptr<two_stack>, maybe<redemption_document> doc = {}, const script_config & = {});

        Error top () const {
            if (Stacks->size_down () == 0) return Error::INVALID_STACK_OPERATION;
            return nonzero (Stacks->top ()) ? Error::OK : Error::FAIL;
        }
    };

    std::ostream inline &operator << (std::ostream &o, const machine &m) {
        return o << "{Flags: " << m.Config.Flags << ", Stacks: " << *m.Stacks << ", Conditional: " << m.Conditional << "}";
    }

    inline conditional::conditional (bool utxo_after_genesis): UtxoAfterGenesis {utxo_after_genesis} {
        Branch.reserve (10);
    }

    void inline conditional::push (bool branch) {
        Branch.push_back ({branch, false});
    }

    Error inline conditional::pop () {
        if (Branch.size () == 0)
            return Error::UNBALANCED_CONDITIONAL;

        Branch.pop_back ();
        return Error::OK;
    }

    Error inline conditional::flip () {

        // Only one ELSE is allowed in IF after genesis.
        if (Branch.size () == 0 || (Branch.back ().Else && UtxoAfterGenesis))
            return Error::UNBALANCED_CONDITIONAL;

        Branch.back ().Exec = !Branch.back ().Exec;
        Branch.back ().Else = true;
        return Error::OK;
    }

    bool inline conditional::executed () const {
        for (const branch &b : Branch) if (!b.Exec) return false;
        return true;
    }

    inline conditional::operator bool () const {
        return Branch.size () > 0;
    }

    std::ostream inline &operator << (std::ostream &o, const conditional &x) {
        o << "{" << std::boolalpha;
        for (const auto &z : x.Branch) o << "{" << z.Exec << ", " << z.Else << "}";
        return o << "}";
    }

}


#endif
