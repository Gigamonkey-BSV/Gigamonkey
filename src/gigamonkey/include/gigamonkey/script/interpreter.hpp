// Copyright (c) 2021-2024 Daniel Krawisz
// Distributed under the Open BSV software license, see the accompanying file LICENSE.

#ifndef GIGAMONKEY_SCRIPT_INTERPRETER
#define GIGAMONKEY_SCRIPT_INTERPRETER

#include <gigamonkey/script/machine.hpp>
#include <gigamonkey/script/program.hpp>

namespace Gigamonkey::Bitcoin {

    // a Bitcoin script interpreter that can be advanced step-by-step.
    struct interpreter {

        machine Machine;
        execution_image Program;
        cross<size_t> Stages;
        program_counter Counter;

        // If the redemption document is not provided, all signature operations will succeed.
        interpreter (const list<script> scripts, const redemption_document &doc, const script_config & = {});

        interpreter (const list<script> scripts, const script_config & = {});

        void step ();
        result run ();

        segment unread () const;

    };

    std::ostream &operator << (std::ostream &, const interpreter &);

    // evaluate with real signatures.
    result inline evaluate (const script &unlock, const script &lock, const redemption_document &doc, const script_config &conf) {
        return interpreter (list<script> {unlock, lock}, doc, conf).run ();
    }

    // if the redemption document is not provided, all signature operations will succeed automatically.
    result inline evaluate (const script &unlock, const script &lock, const script_config &conf) {
        return interpreter (list<script> {unlock, lock}, conf).run ();
    }

    // evaluate with real signatures.
    result inline evaluate (const list<script> scripts, const redemption_document &doc, const script_config &conf) {
        return interpreter (scripts, doc, conf).run ();
    }

    // if the redemption document is not provided, all signature operations will succeed automatically.
    result inline evaluate (const list<script> scripts, const script_config &conf) {
        return interpreter (scripts, conf).run ();
    }

    segment inline interpreter::unread () const {
        return decompile (byte_slice {Program.Script}.drop (Counter.Index));
    }

}

#endif

