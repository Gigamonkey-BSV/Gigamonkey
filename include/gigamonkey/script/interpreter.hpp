// Copyright (c) 2021-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_INTERPRETER
#define GIGAMONKEY_SCRIPT_INTERPRETER

#include <gigamonkey/script/machine.hpp>

namespace Gigamonkey::Bitcoin {

    // a Bitcoin script interpreter that can be advanced step-by-step.
    struct interpreter {
        machine Machine;
        bytes Script;
        program_counter Counter;

        // If the redemption document is not provided, all signature operations will succeed.
        interpreter (const script &unlock, const script &lock, const redemption_document &doc, const script_config & = {});

        interpreter (const script &unlock, const script &lock, const script_config & = {});

        void step ();
        result run ();

        program unread () const;

        // before looking at the scripts as a complete program, there are some rules that apply to the
        // script signature (the part in the input) vs the script pubkey (the part in the output).
        static ScriptError pre_check_scripts (const program unlock, const program lock, const script_config & = {});

    private:

        static bool isP2SH (const program p);

        static program full (const program unlock, const program lock, bool support_p2sh);

        interpreter (maybe<redemption_document> doc, const program unlock, const program lock, const script_config &);
    };

    std::ostream &operator << (std::ostream &, const interpreter &);

    result step_through (interpreter &m);

    result inline evaluate (const script &unlock, const script &lock, const redemption_document &doc, const script_config &conf) {
        return interpreter (unlock, lock, doc, conf).run ();
    }

    // if the redemption document is not provided, all signature operations will succeed.
    result inline evaluate (const script &unlock, const script &lock, const script_config &conf) {
        return interpreter (unlock, lock, conf).run ();
    }

    bool inline interpreter::isP2SH (const program p) {
        bytes script = compile (p);
        return script.size () == 23 && script[0] == OP_HASH160 &&
            script[1] == 0x14 && script[22] == OP_EQUAL;
    }

    // note: pay to script hash only applies to scripts that were created before genesis.
    program inline interpreter::full (const program unlock, const program lock, bool support_p2sh) {
        if (!support_p2sh || !isP2SH (lock) || data::empty (unlock)) return (unlock << OP_CODESEPARATOR) + lock;
        // For P2SH scripts. This is a depricated special case that is supported for backwards compatability.
        return (unlock << OP_CODESEPARATOR) + (lock << OP_CODESEPARATOR) + decompile (data::reverse (unlock).first ().data ());
    }

    ScriptError inline interpreter::pre_check_scripts (const program unlock, const program lock, const script_config &conf) {
        if (conf.verify_sig_push_only () && !is_push (unlock)) return SCRIPT_ERR_SIG_PUSHONLY;

        if (conf.support_P2SH () && isP2SH (lock)) {
            if (data::empty (unlock)) return SCRIPT_ERR_INVALID_STACK_OPERATION;
            if (!is_push (unlock)) return SCRIPT_ERR_SIG_PUSHONLY;
        }

        return pre_verify (full (unlock, lock, conf.support_P2SH ()), conf.Flags);
    }

    inline interpreter::interpreter (const script &unlock, const script &lock, const redemption_document &doc, const script_config &conf) :
        interpreter {{doc}, decompile (unlock), decompile (lock), conf} {}

    inline interpreter::interpreter (const script &unlock, const script &lock, const script_config &conf) :
        interpreter {{}, decompile (unlock), decompile (lock), conf} {}

    program inline interpreter::unread () const {
        return decompile (bytes_view {Counter.Script}.substr (Counter.Counter));
    }

}

#endif

